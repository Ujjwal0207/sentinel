import psycopg2
from datetime import datetime
import json
import hashlib

# Database Configuration (from config.py with safe fallback)
try:
    from config import DB_HOST, DB_NAME, DB_USER, DB_PASS, DB_PORT
except ImportError:
    import os
    DB_HOST = os.getenv("SENTINEL_DB_HOST", "localhost")
    DB_NAME = os.getenv("SENTINEL_DB_NAME", "sentinel_audit")
    DB_USER = os.getenv("SENTINEL_DB_USER", "sentinel")
    DB_PASS = os.getenv("SENTINEL_DB_PASS", "password123")
    DB_PORT = int(os.getenv("SENTINEL_DB_PORT", "5432"))

def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS
    )

def seed_database():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if table exists (assuming audit_worker already created it, but just in case)
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
    
    # Check if we already seeded
    cursor.execute("SELECT COUNT(*) FROM audit_logs")
    count = cursor.fetchone()[0]
    
    if count >= 7:
        print(f"Database already has {count} records. Skipping seed.")
        return

    # If ledger is completely empty, initialize Genesis Block first
    if count == 0:
        genesis_hash = hashlib.sha256(b"SENTINEL_GENESIS_BLOCK").hexdigest()
        cursor.execute("""
            INSERT INTO audit_logs (timestamp, agent_id, action, payload, decision, previous_hash, current_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (datetime.now(), "SYSTEM", "INIT", json.dumps({}), "ALLOW", "0"*64, genesis_hash))
        conn.commit()
        print("🌱 Initialized Genesis Block in empty audit ledger.")
        
    print("Seeding database with historical precedents...")
    
    # Historical precedents aligned with canonical agent profiles and actions
    precedents = [
        # Normal transfers (Allowed)
        ("ag_Travel_Bot", "TRANSFER", {"amount": 50, "time": "14:00"}, "ALLOW"),
        ("ag_Dispute_AI", "TRANSFER", {"amount": 100, "time": "10:30"}, "ALLOW"),
        ("ag_Travel_Bot", "TRANSFER", {"amount": 500, "time": "11:15"}, "ALLOW"),
        
        # Suspicious transfers (Denied by humans)
        ("ag_Fraud_Bot", "TRANSFER", {"amount": 9500, "time": "03:00"}, "DENY"), # High amount, weird hour
        ("ag_Travel_Bot", "TRANSFER", {"amount": 12000, "time": "02:45"}, "DENY"),
        
        # Refunds
        ("ag_Dispute_AI", "REFUND", {"amount": 25, "time": "15:00"}, "ALLOW"),
        ("ag_Fraud_Bot", "REFUND", {"amount": 450, "time": "23:00"}, "DENY"),
    ]
    
    # Fetch the latest block hash so seeded precedents link cleanly to Genesis
    cursor.execute("SELECT current_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
    last_block = cursor.fetchone()
    prev_hash = last_block[0] if last_block else ("0" * 64)
    
    for agent_id, action, payload, decision in precedents:
        data_to_lock = f"{prev_hash}{agent_id}{action}{decision}{json.dumps(payload, sort_keys=True)}"
        curr_hash = hashlib.sha256(data_to_lock.encode('utf-8')).hexdigest()
        
        cursor.execute("""
            INSERT INTO audit_logs (timestamp, agent_id, action, payload, decision, previous_hash, current_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (datetime.now(), agent_id, action, json.dumps(payload), decision, prev_hash, curr_hash))
        
        prev_hash = curr_hash
        
    conn.commit()
    cursor.close()
    conn.close()
    print("✅ Seeded 7 historical precedents into the database.")

if __name__ == "__main__":
    seed_database()
