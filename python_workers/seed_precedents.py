import psycopg2
from datetime import datetime
import json
import hashlib

# Database Configuration
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
    
    if count > 10:
        print(f"Database already has {count} records. Skipping seed.")
        return
        
    print("Seeding database with historical precedents...")
    
    # Some mock data to represent past human decisions
    precedents = [
        # Normal transfers (Allowed)
        ("Agent_A", "TRANSFER", {"amount": 50, "time": "14:00"}, "ALLOW"),
        ("Agent_B", "TRANSFER", {"amount": 100, "time": "10:30"}, "ALLOW"),
        ("Agent_A", "TRANSFER", {"amount": 500, "time": "11:15"}, "ALLOW"),
        
        # Suspicious transfers (Denied by humans)
        ("Agent_C", "TRANSFER", {"amount": 9500, "time": "03:00"}, "DENY"), # High amount, weird hour
        ("Agent_A", "TRANSFER", {"amount": 12000, "time": "02:45"}, "DENY"),
        
        # Refunds
        ("Agent_B", "REFUND", {"amount": 25, "time": "15:00"}, "ALLOW"),
        ("Agent_C", "REFUND", {"amount": 450, "time": "23:00"}, "DENY"),
    ]
    
    prev_hash = "0" * 64
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
