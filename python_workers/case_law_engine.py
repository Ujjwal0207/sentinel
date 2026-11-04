import logging
import psycopg2
import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sklearn.neighbors import NearestNeighbors
from datetime import datetime
import json
import math
import collections

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = FastAPI(title="SENTINEL Case Law Engine", version="1.0")

# Add CORS Middleware to allow React dashboard to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this to the dashboard URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database & API Configuration (from config.py with safe fallback)
try:
    from config import DB_HOST, DB_NAME, DB_USER, DB_PASS, DB_PORT, API_HOST, API_PORT
except ImportError:
    import os
    DB_HOST = os.getenv("SENTINEL_DB_HOST", "localhost")
    DB_NAME = os.getenv("SENTINEL_DB_NAME", "sentinel_audit")
    DB_USER = os.getenv("SENTINEL_DB_USER", "sentinel")
    DB_PASS = os.getenv("SENTINEL_DB_PASS", "password123")
    DB_PORT = int(os.getenv("SENTINEL_DB_PORT", "5432"))
    API_HOST = os.getenv("SENTINEL_API_HOST", "0.0.0.0")
    API_PORT = int(os.getenv("SENTINEL_API_PORT", "8000"))

def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )

def ensure_audit_table():
    """
    Auto-initialize the audit_logs table schema if it does not exist.
    Prevents UndefinedTable crashes when case_law_engine.py starts
    before audit_worker.py has created the table (Issue #37).
    """
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP NOT NULL,
                agent_id VARCHAR(255) NOT NULL,
                action VARCHAR(255) NOT NULL,
                payload JSONB NOT NULL,
                decision VARCHAR(50) NOT NULL,
                previous_hash VARCHAR(64) NOT NULL,
                current_hash VARCHAR(64) NOT NULL
            )
        """)
        conn.commit()
        cursor.close()
        logging.info("✅ audit_logs table verified/created.")
    except Exception as e:
        logging.warning(f"Could not auto-initialize audit_logs table: {e}")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

# --- Feature Engineering ---
# High-Dimensional Vectorization Engine (Sentinel Hardened Guardrails)
# Vectorizes financial magnitude, temporal patterns, action categories, 
# parameter entropy (obfuscation/injection detection), payload complexity, and action risk weight.
ACTION_MAP = {
    "TRANSFER": 0,
    "REFUND": 1,
    "ISSUE_REFUND": 1,
    "CREDIT_INCREASE": 2,
    "LOCK_CARD": 3,
    "LOGIN": 4,
    "WITHDRAW": 5,
}

ACTION_RISK_WEIGHTS = {
    "TRANSFER": 0.9,
    "CREDIT_INCREASE": 0.8,
    "ISSUE_REFUND": 0.5,
    "REFUND": 0.5,
    "LOCK_CARD": 0.3,
    "LOGIN": 0.2,
    "WITHDRAW": 0.8,
}

def calculate_payload_entropy(payload: dict) -> float:
    """
    Computes Shannon entropy across all text values in the payload.
    High entropy flags encrypted blobs, obfuscated shellcode, or SQL injections.
    """
    text = ""
    for k, v in payload.items():
        if isinstance(v, str):
            text += v
        elif isinstance(v, (dict, list)):
            text += str(v)
    if not text:
        return 0.0
    freq = collections.Counter(text)
    total = len(text)
    entropy = -sum((cnt / total) * math.log2(cnt / total) for cnt in freq.values())
    # Normalize: max entropy for printable ASCII is ~6.55 bits
    return min(1.0, entropy / 6.5)

def vectorize_transaction(action: str, payload: dict) -> np.ndarray:
    """
    Converts an action and its payload into a robust 6-dimensional normalized vector for k-NN:
    [Amount_Norm, Hour_Norm, Action_Norm, Entropy, Complexity, Risk_Weight]
    """
    action_str = str(action).upper() if action else ""
    action_val = ACTION_MAP.get(action_str, -1)
    
    # Safe payload sanitization: handle None, strings, lists, or non-dict payloads
    if not isinstance(payload, dict):
        payload = {}
        
    # Safe amount extraction: handles None, numeric, and string currency ($50.00)
    raw_amount = payload.get("amount")
    try:
        if isinstance(raw_amount, str):
            raw_amount = raw_amount.replace("$", "").replace(",", "").strip()
        amount = float(raw_amount) if raw_amount is not None else 0.0
        amount = max(0.0, amount)
    except (ValueError, TypeError):
        amount = 0.0
    
    # Extract hour of day if present, default to 12.0 (noon)
    hour = 12.0
    if payload and "time" in payload:
        try:
            parsed_hour = float(str(payload["time"]).split(":")[0])
            if 0.0 <= parsed_hour <= 24.0:
                hour = parsed_hour
        except (ValueError, TypeError, IndexError):
            hour = 12.0
            
    # Feature 0: Log-scaled normalized amount (handles $0 to $100,000 without distortion)
    amount_norm = min(1.0, math.log10(1.0 + amount) / 5.0)
    # Feature 1: Normalized hour of day (0.0 - 1.0)
    hour_norm = hour / 24.0
    # Feature 2: Normalized Action ID (0.0 - 1.0)
    action_norm = float(action_val) / 6.0 if action_val >= 0 else 0.0
    # Feature 3: Shannon Entropy (obfuscation & injection detection)
    entropy = calculate_payload_entropy(payload)
    # Feature 4: Payload structural complexity (number of fields / 10.0)
    complexity = min(1.0, len(payload) / 10.0)
    # Feature 5: Action risk weight
    risk_weight = ACTION_RISK_WEIGHTS.get(action_str, 0.4)
    
    vec = np.array([amount_norm, hour_norm, action_norm, entropy, complexity, risk_weight], dtype=np.float64)
    # Cosine distance safeguard: L2 normalize to prevent zero-norm division
    norm = np.linalg.norm(vec)
    if norm == 0.0:
        vec[1] = 0.0001
        norm = np.linalg.norm(vec)
        
    return vec / norm

# --- Advanced Trust Economy Math & Distributed State ---
try:
    from config import AGENT_PROFILES, REDIS_HOST, REDIS_PORT
    INITIAL_AGENTS = list(AGENT_PROFILES.keys())
except ImportError:
    INITIAL_AGENTS = ["ag_Dispute_AI", "ag_Travel_Bot", "ag_Fraud_Bot", "ag_Rogue_Sim"]
    AGENT_PROFILES = {
        "ag_Dispute_AI": {"model": "gpt-4", "prompt": "dispute_v3", "tools": "refund_api"},
        "ag_Travel_Bot": {"model": "gpt-4", "prompt": "dispute_v3", "tools": "refund_api"},
        "ag_Fraud_Bot": {"model": "claude-3", "prompt": "fraud_v1", "tools": "lock_api"},
        "ag_Rogue_Sim": {"model": "gpt-4", "prompt": "dispute_v3", "tools": "refund_api"},
    }
    REDIS_HOST = "localhost"
    REDIS_PORT = 6379

# In-Memory Fallback Structures
AGENT_BUDGETS = collections.defaultdict(lambda: 100.0)
for agent in INITIAL_AGENTS:
    AGENT_BUDGETS[agent] = 100.0

AGENT_HISTORY = collections.defaultdict(list)
FLEET_FROZEN = False

# Distributed Redis Connection for Fault-Tolerant Persistence
redis_client = None
try:
    import redis
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True, socket_timeout=1.0)
    r.ping()
    redis_client = r
    logging.info(f"✅ Connected to Redis ({REDIS_HOST}:{REDIS_PORT}) for persistent Trust Economy.")
except Exception as e:
    logging.info(f"ℹ️ Redis offline or unavailable ({e}). Operating in resilient in-memory Trust Economy mode.")
    redis_client = None

def get_agent_budget(agent_id: str) -> float:
    """Reads agent trust budget with Redis persistence and memory fallback."""
    if redis_client:
        try:
            val = redis_client.hget("sentinel:budgets", agent_id)
            if val is not None:
                return float(val)
        except Exception as e:
            logging.warning(f"Redis get budget failed: {e}")
    return float(AGENT_BUDGETS[agent_id])

def set_agent_budget(agent_id: str, budget: float):
    """Sets agent trust budget atomically with Redis sync."""
    capped_budget = max(0.0, min(100.0, float(budget)))
    AGENT_BUDGETS[agent_id] = capped_budget
    if redis_client:
        try:
            redis_client.hset("sentinel:budgets", agent_id, str(capped_budget))
        except Exception as e:
            logging.warning(f"Redis set budget failed: {e}")

def get_fleet_frozen() -> bool:
    """Reads fleet kill-switch state with Redis persistence."""
    global FLEET_FROZEN
    if redis_client:
        try:
            val = redis_client.get("sentinel:fleet_frozen")
            if val is not None:
                return val.lower() == "true"
        except Exception as e:
            logging.warning(f"Redis get fleet_frozen failed: {e}")
    return FLEET_FROZEN

def set_fleet_frozen(frozen: bool):
    """Sets fleet kill-switch state with Redis sync."""
    global FLEET_FROZEN
    FLEET_FROZEN = frozen
    if redis_client:
        try:
            redis_client.set("sentinel:fleet_frozen", "true" if frozen else "false")
        except Exception as e:
            logging.warning(f"Redis set fleet_frozen failed: {e}")

def _profile_similarity(agent_a: str, agent_b: str) -> float:
    """
    Profile-based similarity fallback for agents with no behavioral history.
    Compares model, prompt template, and tool configuration from AGENT_PROFILES.
    Returns a similarity score between 0.0 and 1.0.
    """
    prof_a = AGENT_PROFILES.get(agent_a, {})
    prof_b = AGENT_PROFILES.get(agent_b, {})
    if not prof_a or not prof_b:
        return 0.0
    
    score = 0.0
    if prof_a.get("model") == prof_b.get("model"):
        score += 0.4
    if prof_a.get("prompt") == prof_b.get("prompt"):
        score += 0.35
    if prof_a.get("tools") == prof_b.get("tools"):
        score += 0.25
    return score

def apply_contagion(rogue_agent: str, rogue_vector: np.ndarray):
    """
    Exponential Decay Contagion Algorithm:
    If one agent goes rogue, mathematically restrict the budgets of similar agents.
    Persists updates to Redis when available.
    """
    global AGENT_HISTORY
    
    # Base penalty for the rogue agent is severe (-25.0%)
    current_rogue_budget = get_agent_budget(rogue_agent)
    set_agent_budget(rogue_agent, current_rogue_budget - 25.0)
    
    # Calculate vector similarity for everyone in the fleet
    all_agents = set(list(AGENT_BUDGETS.keys()) + INITIAL_AGENTS)
    
    for agent in all_agents:
        if agent == rogue_agent:
            continue
        
        history = AGENT_HISTORY.get(agent, [])
        
        if len(history) > 0:
            # Behavioral similarity: cosine similarity on last 5 action vectors
            avg_vector = np.mean(history[-5:], axis=0)
            norm_a = np.linalg.norm(avg_vector)
            norm_b = np.linalg.norm(rogue_vector)
            if norm_a > 0.0 and norm_b > 0.0:
                dot_product = float(np.dot(avg_vector, rogue_vector))
                similarity = max(0.0, min(1.0, dot_product / (norm_a * norm_b)))
            else:
                similarity = 0.0
        else:
            # Profile-based fallback: compare model, prompt, tools
            similarity = _profile_similarity(agent, rogue_agent)
        
        # Apply shared penalty proportional to mathematical similarity
        if similarity > 0.65:
            penalty = 15.0 * similarity
            current_peer_budget = get_agent_budget(agent)
            set_agent_budget(agent, current_peer_budget - penalty)
            logging.info(f"🧬 Contagion applied to {agent}: similarity={similarity:.2f}, penalty=-{penalty:.2f}%")

# --- The Precedent Database ---
# We keep a cached version of precedents in memory for sub-millisecond lookups
PRECEDENT_VECTORS = []
PRECEDENT_METADATA = []
knn_model = None

def load_precedents():
    """Loads all historical transactions from PostgreSQL to build the Case Law database."""
    global PRECEDENT_VECTORS, PRECEDENT_METADATA, knn_model
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Exclude system initialization genesis events (action != 'INIT')
        cursor.execute("SELECT id, action, payload, decision FROM audit_logs WHERE action != 'INIT'")
        rows = cursor.fetchall()
        
        vectors = []
        metadata = []
        
        for row in rows:
            log_id, action, payload, decision = row
            # Robust payload parsing (Issue #49): handles None, JSON string, dict, or malformed payloads
            if not payload:
                payload = {}
            elif isinstance(payload, str):
                try:
                    payload = json.loads(payload) if payload.strip() else {}
                except Exception:
                    payload = {}
            if not isinstance(payload, dict):
                payload = {}
                
            vec = vectorize_transaction(action, payload)
            vectors.append(vec)
            metadata.append({"log_id": log_id, "action": action, "decision": decision})
            
        if len(vectors) > 0:
            PRECEDENT_VECTORS = np.array(vectors)
            PRECEDENT_METADATA = metadata
            
            # Train the KNN Model (Using Cosine Similarity)
            # n_neighbors cannot be larger than the number of samples
            n_neighbors = min(3, len(PRECEDENT_VECTORS))
            knn_model = NearestNeighbors(n_neighbors=n_neighbors, metric='cosine')
            knn_model.fit(PRECEDENT_VECTORS)
            logging.info(f"Loaded {len(PRECEDENT_VECTORS)} precedents into the Case Law Engine.")
        else:
            logging.warning("No precedents found in the database. KNN model is empty.")
            
        cursor.close()
    except Exception as e:
        logging.error(f"Failed to load precedents: {e}")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

# Load precedents on startup, ensuring table exists first
@app.on_event("startup")
def startup_event():
    ensure_audit_table()
    load_precedents()

# --- API Models ---
class EvaluateRequest(BaseModel):
    agent_id: str
    action: str
    payload: dict

@app.post("/evaluate")
def evaluate_case(request: EvaluateRequest):
    """
    Evaluates a new transaction against historical case law using KNN.
    Returns the nearest precedents and an inferred decision.
    
    Hard-denies all transactions when FLEET_FROZEN is active (Issue #35).
    Strictly enforces Trust Economy quarantine BEFORE precedent fallback (Issue #47).
    """
    # 1. Circuit Breaker: Kill Switch enforcement (Highest Priority)
    if get_fleet_frozen():
        return {
            "status": "FROZEN",
            "decision": "DENY",
            "reason": "🛑 FLEET KILL SWITCH ACTIVE: All agent actions are hard-denied by the operator circuit breaker.",
            "citations": []
        }
    
    # 2. Vectorize the incoming request for history & evaluation
    target_vector = vectorize_transaction(request.action, request.payload).reshape(1, -1)
    
    # 3. Trust Economy Quarantine Check (Prioritized over Model Fallback - Issue #47)
    # Prevents cold-start / uninitialized model fallback from bypassing quarantine on rogue agents.
    current_budget = get_agent_budget(request.agent_id)
    if current_budget <= 20.0:
        AGENT_HISTORY[request.agent_id].append(target_vector[0])
        if len(AGENT_HISTORY[request.agent_id]) > 20:
            AGENT_HISTORY[request.agent_id] = AGENT_HISTORY[request.agent_id][-20:]
        logging.warning(f"🛑 {request.agent_id} BLOCKED by Trust Economy quarantine (Budget: {current_budget:.1f}%)")
        return {
            "status": "QUARANTINED",
            "decision": "DENY",
            "reason": f"Agent {request.agent_id} trust budget depleted ({current_budget:.1f}% <= 20.0%). Quarantined under Trust Economy.",
            "citations": []
        }

    # 4. Precedent Model Availability & Lazy Bootstrap
    # If the model is not fitted yet, attempt a reload before falling back
    if knn_model is None or len(PRECEDENT_VECTORS) == 0:
        load_precedents()
        
    if knn_model is None or len(PRECEDENT_VECTORS) == 0:
        # Safe fallback only for healthy, non-quarantined agents
        AGENT_HISTORY[request.agent_id].append(target_vector[0])
        if len(AGENT_HISTORY[request.agent_id]) > 20:
            AGENT_HISTORY[request.agent_id] = AGENT_HISTORY[request.agent_id][-20:]
        return {
            "status": "FALLBACK",
            "decision": "ALLOW",
            "reason": "No precedents exist in database. Defaulting to ALLOW for non-quarantined agent.",
            "citations": []
        }
        
    # 5. Find K-Nearest Neighbors in Case Law
    n_neighbors = min(3, len(PRECEDENT_VECTORS))
    distances, indices = knn_model.kneighbors(target_vector, n_neighbors=n_neighbors)
    
    # 6. Compile citations and vote tally
    citations = []
    allow_count = 0
    deny_count = 0
    
    for i in range(len(indices[0])):
        idx = indices[0][i]
        dist = distances[0][i]
        meta = PRECEDENT_METADATA[idx]
        
        if meta["decision"].upper() == "ALLOW":
            allow_count += 1
        else:
            deny_count += 1
            
        dist_val = float(dist) if not math.isnan(float(dist)) else 1.0
        similarity_val = max(0.0, min(1.0, 1.0 - dist_val))
        citations.append({
            "audit_log_id": meta["log_id"],
            "historical_action": meta["action"],
            "historical_decision": meta["decision"],
            "similarity_score": round(similarity_val, 4)
        })
        
    # 7. Fail-closed tie-breaker (Issue #45): split votes default to DENY
    final_decision = "ALLOW" if allow_count > deny_count else "DENY"
    reason = f"Decision based on {len(citations)} closest precedents ({allow_count} ALLOW, {deny_count} DENY)."
    
    # 8. Sliding Window History & Contagion / Replenishment
    AGENT_HISTORY[request.agent_id].append(target_vector[0])
    if len(AGENT_HISTORY[request.agent_id]) > 20:
        AGENT_HISTORY[request.agent_id] = AGENT_HISTORY[request.agent_id][-20:]
    
    if final_decision == "DENY":
        logging.warning(f"🚨 {request.agent_id} DENIED by Case Law. Triggering Contagion Engine...")
        apply_contagion(request.agent_id, target_vector[0])
    elif final_decision == "ALLOW":
        # Positive Trust Replenishment (Issue #34): +1.5% per approved action, capped at 100.0%
        old_budget = get_agent_budget(request.agent_id)
        new_budget = min(100.0, old_budget + 1.5)
        set_agent_budget(request.agent_id, new_budget)
        if old_budget < 100.0:
            logging.info(f"💚 Trust replenished for {request.agent_id}: {old_budget:.1f}% → {new_budget:.1f}%")
    
    return {
        "status": "SUCCESS",
        "decision": final_decision,
        "reason": reason,
        "citations": citations
    }

@app.get("/api/trust-economy")
def get_trust_economy():
    """Returns the live, mathematically derived contagion state."""
    is_frozen = get_fleet_frozen()
    all_keys = set(list(AGENT_BUDGETS.keys()) + INITIAL_AGENTS)
    current_budgets = {agent: round(get_agent_budget(agent), 2) for agent in all_keys}
    
    # When fleet is frozen, report zero budget and zero active agents (Issue #41)
    if is_frozen:
        return {
            "fleet_budget": 0.0,
            "active_agents": 0,
            "fleet_frozen": True,
            "budgets": current_budgets
        }
    
    total_registered = len(current_budgets)
    if total_registered == 0:
        return {"fleet_budget": 100.0, "active_agents": 0, "fleet_frozen": False, "budgets": {}}
        
    # Active agents count (Issue #50): only agents with budget > 20.0% are active (not quarantined)
    active_agents_count = sum(1 for b in current_budgets.values() if b > 20.0)
    fleet_budget = sum(current_budgets.values()) / total_registered
    return {
        "fleet_budget": round(float(fleet_budget), 2),
        "active_agents": active_agents_count,
        "fleet_frozen": False,
        "budgets": current_budgets
    }

# --- Kill Switch Endpoints (Issue #35) ---
@app.post("/api/kill-switch")
def activate_kill_switch():
    """
    Backend circuit breaker: freezes the entire fleet.
    All subsequent /evaluate calls will be hard-denied until resumed.
    """
    set_fleet_frozen(True)
    logging.critical("🛑 FLEET KILL SWITCH ACTIVATED by operator. All agent actions HARD-DENIED.")
    return {
        "status": "FROZEN",
        "message": "Fleet kill switch activated. All agent transactions are now DENIED."
    }

@app.post("/api/resume-fleet")
def resume_fleet():
    """
    Resumes fleet operations after a kill switch activation.
    """
    set_fleet_frozen(False)
    logging.info("✅ Fleet operations RESUMED by operator.")
    return {
        "status": "ACTIVE",
        "message": "Fleet resumed. Agent transactions will be evaluated normally."
    }

@app.post("/refresh")
def refresh_precedents():
    """Manually trigger a reload of the database to update the KNN model."""
    load_precedents()
    return {"status": "SUCCESS", "message": f"Reloaded {len(PRECEDENT_VECTORS)} precedents."}

@app.get("/api/logs")
def get_logs():
    """Fetches the latest 15 cryptographic logs for the React dashboard."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Fetch latest logs ordered by ID descending
        cursor.execute("SELECT id, timestamp, agent_id, action, payload, decision, current_hash FROM audit_logs ORDER BY id DESC LIMIT 15")
        rows = cursor.fetchall()
        
        logs = []
        for row in rows:
            log_id, timestamp_val, agent_id, action, payload, decision, current_hash = row
            
            # Robust payload parsing (Issue #49): handles None, JSON string, dict, or malformed payloads
            if not payload:
                payload = {}
            elif isinstance(payload, str):
                try:
                    payload = json.loads(payload) if payload.strip() else {}
                except Exception:
                    payload = {}
            elif not isinstance(payload, dict):
                payload = {}
                
            raw_amount = payload.get("amount")
            if raw_amount is None or raw_amount == "N/A" or raw_amount == "":
                amount = "N/A"
            else:
                try:
                    if isinstance(raw_amount, str):
                        cleaned = raw_amount.replace("$", "").replace(",", "").strip()
                        amount = f"${float(cleaned):,.2f}"
                    else:
                        amount = f"${float(raw_amount):,.2f}"
                except (ValueError, TypeError):
                    amount = str(raw_amount)
                
            # Format time nicely for the dashboard
            if hasattr(timestamp_val, "strftime"):
                time_str = timestamp_val.strftime("%I:%M:%S %p")
            else:
                time_str = str(timestamp_val) if timestamp_val else "--:--:--"
            
            logs.append({
                "id": log_id,
                "time": time_str,
                "agent": agent_id,
                "action": action,
                "amount": amount,
                "decision": decision,
                "hash": (current_hash[:12] + "...") if current_hash else "PENDING..." # Truncate hash for UI
            })
            
        cursor.close()
        return logs
    except Exception as e:
        logging.error(f"Failed to fetch logs: {e}")
        raise HTTPException(status_code=500, detail="Database connection failed")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

@app.get("/api/verify-audit-chain")
def verify_audit_chain():
    """
    Forensic Verification API: Cryptographically validates the entire SHA-256
    hash chain across all stored audit records to prove non-tampering.
    """
    try:
        from audit_worker import verify_chain_integrity
        return verify_chain_integrity()
    except Exception as e:
        logging.error(f"Audit chain verification error: {e}")
        return {"status": "ERROR", "error": str(e), "tampered": None}

if __name__ == "__main__":
    import uvicorn
    # Run the API using centralized configuration
    uvicorn.run(app, host=API_HOST, port=API_PORT)
