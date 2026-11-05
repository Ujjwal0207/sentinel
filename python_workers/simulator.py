import requests
import time
import random
import json
import logging
import hmac
import hashlib
import uuid
from datetime import datetime, timezone
import os

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%H:%M:%S')

GATEWAY_URL = "http://localhost:8080/enforce"  # Default fallback
SENTINEL_AGENT_SECRET = "sentinel-agent-auth-secret-2026"
try:
    from config import GATEWAY_URL, SENTINEL_AGENT_SECRET
except ImportError:
    GATEWAY_URL = os.getenv("SENTINEL_GATEWAY_URL", "http://localhost:8080/enforce")
    SENTINEL_AGENT_SECRET = os.getenv("SENTINEL_AGENT_SECRET", "sentinel-agent-auth-secret-2026")

ENABLE_KYA_SIGNING = os.getenv("SENTINEL_SIM_SIGN", "true").lower() == "true"

AGENTS = ["ag_Travel_Bot", "ag_Dispute_AI", "ag_Fraud_Bot", "ag_Rogue_Sim"]

ACTIONS = [
    {"action": "Issue_Refund", "amount_range": (10, 500)},
    {"action": "Credit_Increase", "amount_range": (1000, 10000)},
    {"action": "Lock_Card", "amount_range": (0, 0)},
    {"action": "TRANSFER", "amount_range": (50, 2000)},
]

def run_simulator():
    print("🚀 Starting SENTINEL Traffic Simulator...")
    print(f"📡 Sending traffic to {GATEWAY_URL}")
    print(f"🔐 Cryptographic KYA Signatures: {'ENABLED' if ENABLE_KYA_SIGNING else 'DISABLED (Legacy Mode)'}\n")

    try:
        while True:
            agent_id = random.choice(AGENTS)
            action_data = random.choice(ACTIONS)
            
            # Targeted simulation behavior for ag_Rogue_Sim
            if agent_id == "ag_Rogue_Sim":
                action = "Issue_Refund"
                # 60% probability of anomalous high-dollar / odd-hour refund to trigger Case Law denial & Contagion
                if random.random() < 0.6:
                    amount = round(random.uniform(4500, 9500), 2)
                    sim_time = "03:15:00"
                else:
                    amount = round(random.uniform(25, 120), 2)
                    sim_time = datetime.now().strftime("%H:%M:%S")
                payload = {
                    "time": sim_time,
                    "amount": amount,
                    "currency": "USD"
                }
            else:
                action = action_data["action"]
                # Generate random amount
                amount = 0
                if action_data["amount_range"][1] > 0:
                    amount = round(random.uniform(action_data["amount_range"][0], action_data["amount_range"][1]), 2)
                payload = {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "amount": amount,
                    "currency": "USD"
                }
            
            request_data = {
                "agent_id": agent_id,
                "action": action,
                "payload": payload
            }
            
            headers = {"Content-Type": "application/json"}
            if ENABLE_KYA_SIGNING:
                raw_bytes = json.dumps(request_data, separators=(',', ':')).encode('utf-8')
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                nonce = str(uuid.uuid4())
                body_hash = hashlib.sha256(raw_bytes).hexdigest()
                canonical = f"{agent_id}|{ts}|{nonce}|{body_hash}"
                sig = hmac.new(SENTINEL_AGENT_SECRET.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
                headers.update({
                    "X-Sentinel-Agent-ID": agent_id,
                    "X-Sentinel-Timestamp": ts,
                    "X-Sentinel-Nonce": nonce,
                    "X-Sentinel-Signature": sig
                })
            
            try:
                response = requests.post(GATEWAY_URL, json=request_data, headers=headers, timeout=2)
                amt_str = f"${amount:,.2f}" if amount > 0 else "N/A"
                reset = "\033[0m"
                
                if response.status_code in (200, 403, 429):
                    try:
                        resp_json = response.json()
                        decision = resp_json.get("status", "DENY")
                    except Exception:
                        decision = "DENY" if response.status_code in (403, 429) else "UNKNOWN"
                        
                    color = "\033[92m" if decision == "ALLOW" else "\033[91m"
                    if response.status_code == 403:
                        tag = f"{decision} (Policy/RBAC Block)"
                    elif response.status_code == 429:
                        tag = f"{decision} (Quarantined)"
                    else:
                        tag = decision
                    logging.info(f"[{agent_id}] requested {action} ({amt_str}) -> {color}{tag}{reset}")
                elif response.status_code == 401:
                    logging.error(f"[{agent_id}] ⛔ KYA AUTH REJECTED: {response.text}")
                else:
                    logging.warning(f"Gateway returned unexpected HTTP {response.status_code}: {response.text}")
            except requests.exceptions.RequestException as req_err:
                logging.error(f"Network error connecting to {GATEWAY_URL}: {req_err}")
                
            # Wait a few seconds before the next event
            time.sleep(random.uniform(2.0, 5.0))
            
    except KeyboardInterrupt:
        print("\n🛑 Simulator stopped.")


if __name__ == "__main__":
    run_simulator()
