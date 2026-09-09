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
        conn.close()
        logging.info("✅ audit_logs table verified/created.")
    except Exception as e:
        logging.warning(f"Could not auto-initialize audit_logs table: {e}")

# --- Feature Engineering ---
# In a real production system, this would be a robust embedding model.
# For the hackathon, we vectorize the payload into a standard format.
# e.g., Vector = [Amount, Hour_of_day, Action_ID (0 for TRANSFER, 1 for REFUND, etc)]
ACTION_MAP = {
    "TRANSFER": 0,
    "REFUND": 1,
    "ISSUE_REFUND": 1,
    "CREDIT_INCREASE": 2,
    "LOCK_CARD": 3,
    "LOGIN": 4,
    "WITHDRAW": 5,
}

def vectorize_transaction(action: str, payload: dict) -> np.ndarray:
    """Converts an action and its payload into a numeric vector for KNN."""
    action_str = str(action).upper() if action else ""
    action_val = ACTION_MAP.get(action_str, -1)
    
    # Safe amount extraction: handles None, numeric, and string currency ($50.00)
    raw_amount = payload.get("amount") if payload else 0
    try:
        if isinstance(raw_amount, str):
            raw_amount = raw_amount.replace("$", "").replace(",", "").strip()
        amount = float(raw_amount) if raw_amount is not None else 0.0
    except (ValueError, TypeError):
        amount = 0.0
    
    # Extract hour of day if present, default to 12.0 (noon)
    hour = 12.0
    if payload and "time" in payload:
        try:
            hour = float(str(payload["time"]).split(":")[0])
        except (ValueError, TypeError, IndexError):
            hour = 12.0
            
    vec = np.array([amount, hour, float(action_val)], dtype=np.float64)
    # Cosine distance safeguard: prevent zero-norm division by zero
    if np.linalg.norm(vec) == 0.0:
        vec[1] = 0.0001
        
    return vec

# --- Advanced Trust Economy Math ---
try:
    from config import AGENT_PROFILES
    INITIAL_AGENTS = list(AGENT_PROFILES.keys())
except ImportError:
    INITIAL_AGENTS = ["ag_Dispute_AI", "ag_Travel_Bot", "ag_Fraud_Bot", "ag_Rogue_Sim"]
    AGENT_PROFILES = {
        "ag_Dispute_AI": {"model": "gpt-4", "prompt": "dispute_v3", "tools": "refund_api"},
        "ag_Travel_Bot": {"model": "gpt-4", "prompt": "dispute_v3", "tools": "refund_api"},
        "ag_Fraud_Bot": {"model": "claude-3", "prompt": "fraud_v1", "tools": "lock_api"},
        "ag_Rogue_Sim": {"model": "gpt-4", "prompt": "dispute_v3", "tools": "refund_api"},
    }

AGENT_BUDGETS = collections.defaultdict(lambda: 100.0)
for agent in INITIAL_AGENTS:
    AGENT_BUDGETS[agent] = 100.0

AGENT_HISTORY = collections.defaultdict(list)

# --- Fleet Kill Switch State (Issue #35) ---
FLEET_FROZEN = False

def _profile_similarity(agent_a: str, agent_b: str) -> float:
    """
    Profile-based similarity fallback for agents with no behavioral history.
    Compares model, prompt template, and tool configuration from AGENT_PROFILES.
    Returns a similarity score between 0.0 and 1.0.
    
    This ensures contagion can propagate to similar-profile agents even before
    they have transacted, fulfilling Pillar III of the architecture (Issue #33).
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
    
    Enhanced (Issue #33): Iterates ALL fleet agents (not just those with history).
    Falls back to profile-based similarity when behavioral history is empty.
    """
    global AGENT_BUDGETS, AGENT_HISTORY
    
    # Base penalty for the rogue agent is severe
    AGENT_BUDGETS[rogue_agent] = max(0.0, AGENT_BUDGETS[rogue_agent] - 25.0)
    
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
            AGENT_BUDGETS[agent] = max(0.0, AGENT_BUDGETS[agent] - penalty)
            logging.info(f"🧬 Contagion applied to {agent}: similarity={similarity:.2f}, penalty=-{penalty:.2f}%")

# --- The Precedent Database ---
# We keep a cached version of precedents in memory for sub-millisecond lookups
PRECEDENT_VECTORS = []
PRECEDENT_METADATA = []
knn_model = None

def load_precedents():
    """Loads all historical transactions from PostgreSQL to build the Case Law database."""
    global PRECEDENT_VECTORS, PRECEDENT_METADATA, knn_model
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
            # payload is JSONB, psycopg2 automatically converts it to dict
            if isinstance(payload, str):
                payload = json.loads(payload)
                
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
        conn.close()
    except Exception as e:
        logging.error(f"Failed to load precedents: {e}")

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
    """
    global FLEET_FROZEN
    
    # --- Circuit Breaker: Kill Switch enforcement ---
    if FLEET_FROZEN:
        return {
            "status": "FROZEN",
            "decision": "DENY",
            "reason": "🛑 FLEET KILL SWITCH ACTIVE: All agent actions are hard-denied by the operator circuit breaker.",
            "citations": []
        }
    
    if knn_model is None or len(PRECEDENT_VECTORS) == 0:
        # Fallback if no history exists yet
        return {
            "status": "FALLBACK",
            "decision": "ALLOW",
            "reason": "No precedents exist. Defaulting to ALLOW.",
            "citations": []
        }
        
    # 1. Vectorize the incoming request
    target_vector = vectorize_transaction(request.action, request.payload).reshape(1, -1)
    
    # 2. Find K-Nearest Neighbors
    n_neighbors = min(3, len(PRECEDENT_VECTORS))
    distances, indices = knn_model.kneighbors(target_vector, n_neighbors=n_neighbors)
    
    # 3. Compile the citations
    citations = []
    allow_count = 0
    deny_count = 0
    
    for i in range(len(indices[0])):
        idx = indices[0][i]
        dist = distances[0][i]
        meta = PRECEDENT_METADATA[idx]
        
        # Tally the votes
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
            "similarity_score": round(similarity_val, 4) # Convert cosine distance to similarity
        })
        
    # 4. Make a decision based on Case Law precedent & Trust Economy Budget
    current_budget = AGENT_BUDGETS.get(request.agent_id, 100.0)
    if current_budget <= 20.0:
        # Agent has breached risk threshold / quarantined
        final_decision = "DENY"
        reason = f"Agent {request.agent_id} trust budget depleted ({current_budget:.1f}% <= 20.0%). Quarantined under Trust Economy."
        logging.warning(f"🛑 {request.agent_id} BLOCKED by Trust Economy quarantine (Budget: {current_budget:.1f}%)")
    else:
        final_decision = "ALLOW" if allow_count >= deny_count else "DENY"
        reason = f"Decision based on {len(citations)} closest precedents ({allow_count} ALLOW, {deny_count} DENY)."
    
    # --- Execute Trust Economy Contagion & Sliding Window History ---
    AGENT_HISTORY[request.agent_id].append(target_vector[0])
    if len(AGENT_HISTORY[request.agent_id]) > 20:
        AGENT_HISTORY[request.agent_id] = AGENT_HISTORY[request.agent_id][-20:]
    
    if final_decision == "DENY":
        logging.warning(f"🚨 {request.agent_id} DENIED. Triggering Contagion Engine...")
        apply_contagion(request.agent_id, target_vector[0])
    elif final_decision == "ALLOW":
        # --- Positive Trust Replenishment (Issue #34) ---
        # Reward clean behavior: +1.5% per approved action, capped at 100.0%
        old_budget = AGENT_BUDGETS[request.agent_id]
        AGENT_BUDGETS[request.agent_id] = min(100.0, old_budget + 1.5)
        if old_budget < 100.0:
            logging.info(f"💚 Trust replenished for {request.agent_id}: {old_budget:.1f}% → {AGENT_BUDGETS[request.agent_id]:.1f}%")
    
    return {
        "status": "SUCCESS",
        "decision": final_decision,
        "reason": reason,
        "citations": citations
    }

@app.get("/api/trust-economy")
def get_trust_economy():
    """Returns the live, mathematically derived contagion state."""
    active_count = len(AGENT_BUDGETS)
    if active_count == 0:
        return {"fleet_budget": 100.0, "active_agents": 0, "fleet_frozen": FLEET_FROZEN}
        
    fleet_budget = sum(AGENT_BUDGETS.values()) / active_count
    return {
        "fleet_budget": round(fleet_budget, 2),
        "active_agents": active_count,
        "fleet_frozen": FLEET_FROZEN,
        "budgets": {k: round(v, 2) for k, v in AGENT_BUDGETS.items()}
    }

# --- Kill Switch Endpoints (Issue #35) ---
@app.post("/api/kill-switch")
def activate_kill_switch():
    """
    Backend circuit breaker: freezes the entire fleet.
    All subsequent /evaluate calls will be hard-denied until resumed.
    """
    global FLEET_FROZEN
    FLEET_FROZEN = True
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
    global FLEET_FROZEN
    FLEET_FROZEN = False
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
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Fetch latest logs ordered by ID descending
        cursor.execute("SELECT id, timestamp, agent_id, action, payload, decision, current_hash FROM audit_logs ORDER BY id DESC LIMIT 15")
        rows = cursor.fetchall()
        
        logs = []
        for row in rows:
            log_id, timestamp_val, agent_id, action, payload, decision, current_hash = row
            
            # Ensure payload is dict
            if isinstance(payload, str):
                payload = json.loads(payload)
                
            amount = payload.get("amount", "N/A")
            if amount != "N/A":
                try:
                    amount = f"${float(amount):,.2f}"
                except (ValueError, TypeError):
                    amount = str(amount)
                
            # Format time nicely for the dashboard
            if hasattr(timestamp_val, "strftime"):
                time_str = timestamp_val.strftime("%I:%M:%S %p")
            else:
                time_str = str(timestamp_val)
            
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
        conn.close()
        return logs
    except Exception as e:
        logging.error(f"Failed to fetch logs: {e}")
        raise HTTPException(status_code=500, detail="Database connection failed")

if __name__ == "__main__":
    import uvicorn
    # Run the API using centralized configuration
    uvicorn.run(app, host=API_HOST, port=API_PORT)
