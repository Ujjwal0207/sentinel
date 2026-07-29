import requests
import time
import random
import json
import logging
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%H:%M:%S')

GATEWAY_URL = "http://localhost:8080/enforce"

AGENTS = ["ag_Travel_Bot", "ag_Dispute_AI", "ag_Fraud_Bot"]

ACTIONS = [
    {"action": "Issue_Refund", "amount_range": (10, 500)},
    {"action": "Credit_Increase", "amount_range": (1000, 10000)},
    {"action": "Lock_Card", "amount_range": (0, 0)},
    {"action": "TRANSFER", "amount_range": (50, 2000)},
]

print("🚀 Starting SENTINEL Traffic Simulator...")
print(f"📡 Sending traffic to {GATEWAY_URL}\n")

try:
    while True:
        agent_id = random.choice(AGENTS)
        action_data = random.choice(ACTIONS)
        
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
        
        try:
            response = requests.post(GATEWAY_URL, json=request_data, timeout=2)
            if response.status_code == 200:
                decision = response.json().get("status", "UNKNOWN")
                color = "\033[92m" if decision == "ALLOW" else "\033[91m"
                reset = "\033[0m"
                amt_str = f"${amount:,.2f}" if amount > 0 else "N/A"
                logging.info(f"[{agent_id}] requested {action} ({amt_str}) -> {color}{decision}{reset}")
            else:
                logging.warning(f"Gateway returned {response.status_code}: {response.text}")
        except requests.exceptions.ConnectionError:
            logging.error(f"Failed to connect to {GATEWAY_URL}. Is the Go Gateway running?")
            
        # Wait a few seconds before the next event
        time.sleep(random.uniform(2.0, 5.0))
        
except KeyboardInterrupt:
    print("\n🛑 Simulator stopped.")
