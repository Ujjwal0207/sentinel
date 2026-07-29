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

# Database Configuration (Matches docker-compose.yml)
DB_HOST = "localhost"
DB_NAME = "sentinel_audit"
DB_USER = "sentinel"
DB_PASS = "password123"

def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )

# --- Feature Engineering ---
# In a real production system, this would be a robust embedding model.
# For the hackathon, we vectorize the payload into a standard format.
# e.g., Vector = [Amount, Hour_of_day, Action_ID (0 for TRANSFER, 1 for REFUND, etc)]
ACTION_MAP = {"TRANSFER": 0, "REFUND": 1, "LOGIN": 2, "WITHDRAW": 3}

def vectorize_transaction(action: str, payload: dict) -> np.ndarray:
    """Converts an action and its payload into a numeric vector for KNN."""
    action_val = ACTION_MAP.get(action.upper(), -1)
    
    # Extract amount if present, default to 0
    amount = float(payload.get("amount", 0))
    
    # Extract hour of day if present, default to 12 (noon)
    # If the payload has a 'time', try to parse it, else use 12
    hour = 12.0
    if "time" in payload:
        try:
            # simple mock extraction
            hour = float(payload["time"].split(":")[0])
        except:
            pass
            
    return np.array([amount, hour, action_val])

# --- Advanced Trust Economy Math ---
AGENT_BUDGETS = collections.defaultdict(lambda: 100.0)
AGENT_HISTORY = collections.defaultdict(list)

def apply_contagion(rogue_agent: str, rogue_vector: np.ndarray):
    """
    Exponential Decay Contagion Algorithm:
    If one agent goes rogue, mathematically restrict the budgets of similar agents.
    """
    global AGENT_BUDGETS, AGENT_HISTORY
    
    # Base penalty for the rogue agent is severe
    AGENT_BUDGETS[rogue_agent] = max(0.0, AGENT_BUDGETS[rogue_agent] - 25.0)
    
    # Calculate vector similarity for everyone else
    for agent, history in AGENT_HISTORY.items():
        if agent == rogue_agent or len(history) == 0:
            continue
            
        # Get the average behavioral vector for this agent
        avg_vector = np.mean(history[-5:], axis=0) # last 5 actions
        
        # Calculate Euclidean Distance
        dist = np.linalg.norm(avg_vector - rogue_vector)
        
        # Convert distance to similarity (0 to 1). Exponential decay.
        # If dist is 0 (identical), similarity is 1. If dist is large, similarity approaches 0.
        similarity = math.exp(-0.5 * dist)
        
        # Apply shared penalty proportional to mathematical similarity
        penalty = 15.0 * similarity
        if penalty > 0.5:
            logging.info(f"🧬 Contagion applied to {agent}: similarity={similarity:.2f}, penalty=-{penalty:.2f}%")
            AGENT_BUDGETS[agent] = max(0.0, AGENT_BUDGETS[agent] - penalty)

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
        
        # We only want to learn from human-overridden decisions, or historically 'final' decisions
        cursor.execute("SELECT id, action, payload, decision FROM audit_logs")
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

# Load precedents on startup
@app.on_event("startup")
def startup_event():
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
    """
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
            
        citations.append({
            "audit_log_id": meta["log_id"],
            "historical_action": meta["action"],
            "historical_decision": meta["decision"],
            "similarity_score": round(1.0 - float(dist), 4) # Convert cosine distance to similarity
        })
        
    # 4. Make a decision based on Case Law precedent
    final_decision = "ALLOW" if allow_count >= deny_count else "DENY"
    
    # --- Execute Trust Economy Contagion ---
    AGENT_HISTORY[request.agent_id].append(target_vector[0])
    
    if final_decision == "DENY":
        logging.warning(f"🚨 {request.agent_id} DENIED by Case Law. Triggering Contagion Engine...")
        apply_contagion(request.agent_id, target_vector[0])
    
    return {
        "status": "SUCCESS",
        "decision": final_decision,
        "reason": f"Decision based on {len(citations)} closest precedents ({allow_count} ALLOW, {deny_count} DENY).",
        "citations": citations
    }

@app.get("/api/trust-economy")
def get_trust_economy():
    """Returns the live, mathematically derived contagion state."""
    active_count = len(AGENT_BUDGETS)
    if active_count == 0:
        return {"fleet_budget": 100.0, "active_agents": 0}
        
    fleet_budget = sum(AGENT_BUDGETS.values()) / active_count
    return {
        "fleet_budget": round(fleet_budget, 2),
        "active_agents": active_count,
        "budgets": {k: round(v, 2) for k, v in AGENT_BUDGETS.items()}
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
        cursor.execute("SELECT id, created_at, agent_id, action, payload, decision, hash FROM audit_logs ORDER BY id DESC LIMIT 15")
        rows = cursor.fetchall()
        
        logs = []
        for row in rows:
            log_id, created_at, agent_id, action, payload, decision, hash_val = row
            
            # Ensure payload is dict
            if isinstance(payload, str):
                payload = json.loads(payload)
                
            amount = payload.get("amount", "N/A")
            if amount != "N/A":
                amount = f"${float(amount):,.2f}"
                
            # Format time nicely for the dashboard
            time_str = created_at.strftime("%I:%M:%S %p")
            
            logs.append({
                "id": log_id,
                "time": time_str,
                "agent": agent_id,
                "action": action,
                "amount": amount,
                "decision": decision,
                "hash": hash_val[:12] + "..." if hash_val else "PENDING..." # Truncate hash for UI
            })
            
        cursor.close()
        conn.close()
        return logs
    except Exception as e:
        logging.error(f"Failed to fetch logs: {e}")
        raise HTTPException(status_code=500, detail="Database connection failed")

if __name__ == "__main__":
    import uvicorn
    # Run the API on port 8000
    uvicorn.run(app, host="0.0.0.0", port=8000)
