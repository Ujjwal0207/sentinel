import logging
import os
import sys
import hashlib
import threading
import psycopg2
import psycopg2.pool
import numpy as np
import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Any, Dict, Optional
from sklearn.neighbors import NearestNeighbors
from datetime import datetime, timezone
import json
import math
import collections
import re

# Ensure sibling modules resolve cleanly regardless of working directory
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(_THIS_DIR), ".env"))
except ImportError:
    pass

from paypal_sandbox import PayPalSandboxClient
from gemini_agent import DEFAULT_GEMINI_MODEL, run_guarded_paypal_agent
from elastic_audit import ElasticAuditClient, search_in_memory_fallback

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = FastAPI(title="SENTINEL Case Law Engine", version="1.0")

# Add CORS Middleware to allow React dashboard to connect cleanly (local + Render)
_raw_cors = os.getenv("CORS_ALLOW_ORIGINS", "*").strip()
_cors_origins = [o.strip() for o in _raw_cors.split(",") if o.strip()] if _raw_cors and _raw_cors != "*" else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=(_cors_origins != ["*"]),
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

_db_pool = None

def get_db_pool():
    global _db_pool
    if _db_pool is None or _db_pool.closed:
        try:
            _db_pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=2,
                maxconn=25,
                host=DB_HOST,
                port=DB_PORT,
                database=DB_NAME,
                user=DB_USER,
                password=DB_PASS,
                connect_timeout=1,
            )
        except Exception as e:
            logging.warning(f"Could not initialize connection pool: {e}")
            _db_pool = None
    return _db_pool

def get_db_connection():
    pool = get_db_pool()
    if pool:
        try:
            return pool.getconn()
        except Exception:
            pass
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        connect_timeout=1,
    )

def release_db_connection(conn):
    if conn:
        try:
            if _db_pool and not _db_pool.closed:
                _db_pool.putconn(conn)
                return
            conn.close()
        except Exception:
            pass

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
            release_db_connection(conn)

# --- Feature Engineering ---
# High-Dimensional Vectorization Engine (Sentinel Hardened Guardrails)
# Vectorizes financial magnitude, temporal patterns, action categories, 
# parameter entropy (obfuscation/injection detection), payload complexity, and action risk weight.
ACTION_MAP = {
    "TRANSFER": 0,
    "PAYPAL_PAYOUT": 0,
    "PAYPAL_CREATE_ORDER": 0,
    "REFUND": 1,
    "ISSUE_REFUND": 1,
    "PAYPAL_REFUND": 1,
    "CREDIT_INCREASE": 2,
    "LOCK_CARD": 3,
    "LOGIN": 4,
    "WITHDRAW": 5,
}

ACTION_RISK_WEIGHTS = {
    "TRANSFER": 0.9,
    "PAYPAL_PAYOUT": 0.85,
    "PAYPAL_CREATE_ORDER": 0.5,
    "CREDIT_INCREASE": 0.8,
    "ISSUE_REFUND": 0.5,
    "REFUND": 0.5,
    "PAYPAL_REFUND": 0.55,
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
            release_db_connection(conn)

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
        record_live_audit_log({
            "agent": request.agent_id,
            "action": request.action,
            "payload": request.payload,
            "decision": "DENY",
        })
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
        record_live_audit_log({
            "agent": request.agent_id,
            "action": request.action,
            "payload": request.payload,
            "decision": "DENY",
        })
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
        record_live_audit_log({
            "agent": request.agent_id,
            "action": request.action,
            "payload": request.payload,
            "decision": "ALLOW",
        })
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

    record_live_audit_log({
        "agent": request.agent_id,
        "action": request.action,
        "payload": request.payload,
        "decision": final_decision,
    })

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

# In-memory live audit log ring buffer (ensures real-time dashboard visibility even when PostgreSQL is offline)
_GENESIS_HASH = hashlib.sha256(b"SENTINEL_GENESIS_BLOCK").hexdigest()
_LIVE_LOG_LOCK = threading.Lock()
LIVE_AUDIT_LOGS = collections.deque(
    [
        {
            "id": 1000001,
            "time": datetime.now().strftime("%I:%M:%S %p"),
            "agent": "SYSTEM",
            "action": "INIT_GENESIS_BLOCK",
            "amount": "N/A",
            "decision": "ALLOW",
            "hash": _GENESIS_HASH[:12] + "...",
        }
    ],
    maxlen=50,
)
_LIVE_LOG_SEQ = 1000001
_LAST_LIVE_HASH = _GENESIS_HASH


def _format_log_amount(payload: dict) -> str:
    raw_amount = payload.get("amount") if isinstance(payload, dict) else None
    if raw_amount is None or raw_amount == "N/A" or raw_amount == "":
        return "N/A"
    try:
        if isinstance(raw_amount, str):
            cleaned = raw_amount.replace("$", "").replace(",", "").strip()
            return f"${float(cleaned):,.2f}"
        return f"${float(raw_amount):,.2f}"
    except (ValueError, TypeError):
        return str(raw_amount)


def _extract_amount_usd(payload: dict) -> float:
    raw_amount = payload.get("amount") if isinstance(payload, dict) else None
    if raw_amount is None or raw_amount == "" or raw_amount == "N/A":
        return 0.0
    try:
        if isinstance(raw_amount, str):
            return max(0.0, float(raw_amount.replace("$", "").replace(",", "").strip()))
        return max(0.0, float(raw_amount))
    except (ValueError, TypeError):
        return 0.0


def _sanitize_public_log(item: dict) -> dict:
    return {k: v for k, v in item.items() if not str(k).startswith("_")}


def record_live_audit_log(entry: dict):
    global _LIVE_LOG_SEQ, _LAST_LIVE_HASH
    payload = entry.get("payload") or {}
    wal_hash = entry.get("wal_hash")
    action = entry.get("action", "UNKNOWN")
    agent = entry.get("agent", "ag_Unknown")
    decision = entry.get("decision", "DENY")
    feature_vec = [float(x) for x in vectorize_transaction(action, payload).tolist()]

    with _LIVE_LOG_LOCK:
        _LIVE_LOG_SEQ += 1
        seq_id = _LIVE_LOG_SEQ
        if not wal_hash:
            digest_input = f"{_LAST_LIVE_HASH}|{agent}|{action}|{json.dumps(payload, sort_keys=True, default=str)}|{decision}"
            wal_hash = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()
        _LAST_LIVE_HASH = wal_hash
        display_time = datetime.now().strftime("%I:%M:%S %p")
        item = {
            "id": seq_id,
            "time": display_time,
            "agent": agent,
            "action": action,
            "amount": _format_log_amount(payload),
            "decision": decision,
            "hash": wal_hash[:12] + "...",
            "_vector": feature_vec,
        }
        if entry.get("paypal_id"):
            item["paypal_id"] = entry["paypal_id"]
        if entry.get("message"):
            item["message"] = entry["message"]
        LIVE_AUDIT_LOGS.appendleft(item)

    # Forward telemetry + 6D behavioral vector to Elasticsearch SIEM when configured
    es_client = ElasticAuditClient()
    if es_client.is_configured():
        es_doc = {
            "event_id": f"evt-{seq_id}-{wal_hash[:10]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "display_time": display_time,
            "agent_id": agent,
            "action": action,
            "decision": decision,
            "amount": _format_log_amount(payload),
            "amount_usd": _extract_amount_usd(payload),
            "wal_hash": wal_hash,
            "paypal_id": entry.get("paypal_id"),
            "prompt": entry.get("prompt") or (payload.get("prompt") if isinstance(payload, dict) else None),
            "message": entry.get("message") or "",
            "payload": payload if isinstance(payload, dict) else {},
            "feature_vector": feature_vec,
        }
        es_client.index_audit_event(es_doc)


def _sync_gateway_fleet_freeze(frozen: bool):
    gateway_enforce_url = os.getenv("SENTINEL_GATEWAY_URL", "http://localhost:8080/enforce").strip()
    base = gateway_enforce_url.rsplit("/enforce", 1)[0]
    endpoint = f"{base}/v1/fleet/freeze" if frozen else f"{base}/v1/fleet/resume"
    try:
        requests.post(endpoint, timeout=1.5)
    except Exception as e:
        logging.debug(f"Go gateway freeze sync skipped ({endpoint}): {e}")


# --- Kill Switch Endpoints (Issue #35) ---
@app.post("/api/kill-switch")
def activate_kill_switch():
    """
    Backend circuit breaker: freezes the entire fleet.
    All subsequent /evaluate calls will be hard-denied until resumed.
    """
    set_fleet_frozen(True)
    _sync_gateway_fleet_freeze(True)
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
    _sync_gateway_fleet_freeze(False)
    logging.info("✅ Fleet operations RESUMED by operator.")
    return {
        "status": "ACTIVE",
        "message": "Fleet resumed. Agent transactions will be evaluated normally."
    }

@app.post("/api/trust-economy/reset")
def reset_trust_economy():
    """Restores registered agent trust budgets to 100.0% and clears sliding history."""
    AGENT_HISTORY.clear()
    all_keys = set(list(AGENT_BUDGETS.keys()) + INITIAL_AGENTS)
    for agent in all_keys:
        set_agent_budget(agent, 100.0)
    return {
        "status": "RESET",
        "fleet_budget": 100.0,
        "budgets": {agent: 100.0 for agent in all_keys},
    }

@app.post("/refresh")
def refresh_precedents():
    """Manually trigger a reload of the database to update the KNN model."""
    load_precedents()
    return {"status": "SUCCESS", "message": f"Reloaded {len(PRECEDENT_VECTORS)} precedents."}

@app.get("/api/logs")
def get_logs():
    """Fetches the latest 15 cryptographic logs (PostgreSQL when online, live in-memory buffer fallback)."""
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
                
            amount = _format_log_amount(payload)
                
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
        with _LIVE_LOG_LOCK:
            live_events = [_sanitize_public_log(item) for item in LIVE_AUDIT_LOGS if item.get("action") != "INIT_GENESIS_BLOCK"]
        if logs:
            combined = live_events + logs
            return combined[:25]
        with _LIVE_LOG_LOCK:
            return [_sanitize_public_log(item) for item in list(LIVE_AUDIT_LOGS)[:25]]
    except Exception as e:
        logging.info(f"PostgreSQL offline for /api/logs ({e}); serving live in-memory audit buffer.")
        with _LIVE_LOG_LOCK:
            return [_sanitize_public_log(item) for item in list(LIVE_AUDIT_LOGS)[:25]]
    finally:
        if conn:
            release_db_connection(conn)


@app.get("/")
def root_info():
    return {
        "service": "SENTINEL Case Law & PayPal Sandbox Orchestrator",
        "status": "ok",
        "endpoints": ["/health", "/api/integrations/status", "/api/agent/execute", "/api/logs", "/api/audit/search"],
    }


@app.get("/health")
def health_check():
    """Fast Render/Kubernetes liveness & readiness probe."""
    return {
        "status": "ok",
        "service": "sentinel-api",
        "fleet_frozen": get_fleet_frozen(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _build_search_vector(q: str, ref_action: str, ref_amount: Optional[float]) -> list:
    resolved_action = (ref_action or "").strip().upper()
    if not resolved_action:
        q_upper = (q or "").upper()
        for candidate in ("PAYPAL_PAYOUT", "PAYPAL_CREATE_ORDER", "PAYPAL_REFUND", "TRANSFER", "ISSUE_REFUND", "CREDIT_INCREASE"):
            if candidate in q_upper:
                resolved_action = candidate
                break
        if not resolved_action:
            if "ORDER" in q_upper:
                resolved_action = "PAYPAL_CREATE_ORDER"
            elif "REFUND" in q_upper:
                resolved_action = "PAYPAL_REFUND"
            else:
                resolved_action = "PAYPAL_PAYOUT"

    resolved_amount = ref_amount
    if resolved_amount is None:
        m = re.search(r"\$?\s*([0-9][0-9,]*(?:\.[0-9]+)?)", q or "")
        if m:
            try:
                resolved_amount = float(m.group(1).replace(",", ""))
            except ValueError:
                resolved_amount = 50000.0
        else:
            resolved_amount = 50000.0

    vec = vectorize_transaction(resolved_action, {"amount": resolved_amount, "prompt": q or ""})
    return [float(x) for x in vec.tolist()]


@app.get("/api/audit/search")
def search_audit_logs(
    q: str = "",
    decision: str = "",
    agent_id: str = "",
    mode: str = "text",
    ref_action: str = "",
    ref_amount: Optional[float] = None,
    limit: int = 25,
):
    """
    Searches SENTINEL audit events via Elasticsearch (`sentinel-audit-events` SIEM full-text
    or 6D `dense_vector` kNN similarity) with automatic live in-memory fallback.
    """
    search_mode = (mode or "text").strip().lower()
    query_vec = _build_search_vector(q, ref_action, ref_amount) if search_mode == "knn" else None

    es_client = ElasticAuditClient()
    if es_client.is_configured():
        try:
            res = es_client.search_audit_events(
                query=q,
                decision=decision,
                agent_id=agent_id,
                query_vector=query_vec,
                size=limit,
            )
            if query_vec is not None:
                res["query_vector"] = [round(v, 4) for v in query_vec]
            return res
        except Exception as exc:
            logging.warning(f"Elasticsearch search failed ({exc}); falling back to in-memory buffer.")
            with _LIVE_LOG_LOCK:
                snapshot = [dict(item) for item in LIVE_AUDIT_LOGS]
            fallback = search_in_memory_fallback(
                records=snapshot,
                query=q,
                decision=decision,
                agent_id=agent_id,
                query_vector=query_vec,
                vectorize_fn=vectorize_transaction,
                size=limit,
            )
            fallback["warning"] = f"Elasticsearch query error: {exc}"
            if query_vec is not None:
                fallback["query_vector"] = [round(v, 4) for v in query_vec]
            return fallback

    with _LIVE_LOG_LOCK:
        snapshot = [dict(item) for item in LIVE_AUDIT_LOGS]
    fallback = search_in_memory_fallback(
        records=snapshot,
        query=q,
        decision=decision,
        agent_id=agent_id,
        query_vector=query_vec,
        vectorize_fn=vectorize_transaction,
        size=limit,
    )
    if query_vec is not None:
        fallback["query_vector"] = [round(v, 4) for v in query_vec]
    return fallback


class AgentExecuteRequest(BaseModel):
    prompt: str
    agent_id: str = "ag_Travel_Bot"
    mandate_max_amount: Optional[float] = None
    mandate_currency: str = "USD"
    mandate_recipient: Optional[str] = None
    mandate_authorized_action: Optional[str] = None
    data_origin: Optional[str] = None
    force_tool: Optional[str] = None
    force_args: Optional[Dict[str, Any]] = None
    dry_run_paypal: bool = False
    gemini_api_key: Optional[str] = None
    gemini_model: Optional[str] = None
    paypal_client_id: Optional[str] = None
    paypal_client_secret: Optional[str] = None


@app.get("/api/integrations/status")
def get_integrations_status(verify: bool = False):
    """Reports live readiness for Google Gemini, Go Edge Gateway, PayPal Sandbox, and Elasticsearch."""
    gemini_key = (os.getenv("GEMINI_API_KEY", "") or os.getenv("GOOGLE_API_KEY", "")).strip()
    gemini_model = os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL).strip() or DEFAULT_GEMINI_MODEL

    pp_client = PayPalSandboxClient()
    if verify and pp_client.is_configured():
        paypal_status = pp_client.verify_connection()
    else:
        paypal_status = {
            "configured": pp_client.is_configured(),
            "connected": None,
            "environment": pp_client.mode,
            "base_url": pp_client.base_url,
            "message": "Ready (call ?verify=true to test live OAuth2 token)" if pp_client.is_configured() else "Missing PAYPAL_CLIENT_ID / PAYPAL_CLIENT_SECRET",
        }

    gateway_enforce = os.getenv("SENTINEL_GATEWAY_URL", "http://localhost:8080/enforce").strip()
    gateway_health = gateway_enforce.rsplit("/enforce", 1)[0] + "/health"
    gateway_status = {"reachable": False, "url": gateway_health}
    try:
        r = requests.get(gateway_health, timeout=1.5)
        if r.status_code == 200:
            gateway_status["reachable"] = True
            gateway_status["details"] = r.json()
    except Exception as e:
        gateway_status["error"] = str(e)

    es_status = ElasticAuditClient().check_health()

    return {
        "fleet_frozen": get_fleet_frozen(),
        "gemini": {
            "configured": bool(gemini_key),
            "model": gemini_model,
        },
        "paypal": paypal_status,
        "gateway": gateway_status,
        "elastic": es_status,
    }


@app.post("/api/agent/execute")
def execute_gemini_paypal_workflow(req: AgentExecuteRequest):
    """
    Executes an AI-driven commerce request end-to-end:
      1. Google Gemini translates natural language -> PayPal Sandbox tool call
      2. SENTINEL Go Edge Gateway verifies KYA, AP2 Mandate, guardrails & RBAC
      3. PayPal Sandbox executes ONLY when SENTINEL returns ALLOW
    """
    # Respect Python Fleet Kill Switch & Trust Quarantine upfront as well
    if get_fleet_frozen():
        record_live_audit_log({
            "agent": req.agent_id,
            "action": "PAYPAL_AGENT_CALL",
            "payload": {"prompt": req.prompt},
            "decision": "DENY",
        })
        return {
            "status": "FROZEN",
            "decision": "DENY",
            "gemini": {"model": req.gemini_model or os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)},
            "sentinel": {
                "decision": "DENY",
                "status_code": 503,
                "error": "FLEET_FROZEN",
                "message": "Fleet kill switch active: all AI agent transactions are frozen.",
            },
            "paypal": {
                "executed": False,
                "environment": "sandbox",
                "status": "BLOCKED_BY_KILL_SWITCH",
            },
        }

    current_budget = get_agent_budget(req.agent_id)
    if current_budget <= 20.0:
        record_live_audit_log({
            "agent": req.agent_id,
            "action": "PAYPAL_AGENT_CALL",
            "payload": {"prompt": req.prompt},
            "decision": "DENY",
        })
        return {
            "status": "QUARANTINED",
            "decision": "DENY",
            "gemini": {"model": req.gemini_model or os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)},
            "sentinel": {
                "decision": "DENY",
                "status_code": 403,
                "error": "TRUST_ECONOMY_QUARANTINED",
                "message": f"Agent {req.agent_id} is quarantined (trust budget {current_budget:.1f}% <= 20.0%).",
            },
            "paypal": {
                "executed": False,
                "environment": "sandbox",
                "status": "BLOCKED_BY_QUARANTINE",
            },
        }

    override = None
    if req.force_tool and req.force_args is not None:
        override = (req.force_tool, req.force_args)

    try:
        result = run_guarded_paypal_agent(
            prompt=req.prompt,
            agent_id=req.agent_id,
            mandate_max_amount=req.mandate_max_amount,
            mandate_currency=req.mandate_currency,
            mandate_recipient=req.mandate_recipient,
            mandate_authorized_action=req.mandate_authorized_action,
            data_origin=req.data_origin,
            gemini_api_key=req.gemini_api_key,
            gemini_model=req.gemini_model,
            paypal_client_id=req.paypal_client_id,
            paypal_client_secret=req.paypal_client_secret,
            direct_tool_override=override,
            dry_run_paypal=req.dry_run_paypal,
            log_recorder=record_live_audit_log,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Sync Trust Economy contagion/replenishment with outcome
    try:
        gem_info = result.get("gemini") or {}
        action_name = gem_info.get("sentinel_action") or "PAYPAL_PAYOUT"
        args_payload = gem_info.get("arguments") or {}
        vec = vectorize_transaction(action_name, args_payload)
        AGENT_HISTORY[req.agent_id].append(vec)
        if len(AGENT_HISTORY[req.agent_id]) > 20:
            AGENT_HISTORY[req.agent_id] = AGENT_HISTORY[req.agent_id][-20:]

        if result.get("decision") == "DENY":
            apply_contagion(req.agent_id, vec)
        elif result.get("decision") == "ALLOW":
            old_budget = get_agent_budget(req.agent_id)
            set_agent_budget(req.agent_id, min(100.0, old_budget + 1.5))
    except Exception as e:
        logging.warning(f"Trust economy sync warning: {e}")

    return result

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
