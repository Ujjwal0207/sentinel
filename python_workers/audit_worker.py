import json
import logging
import hashlib
import psycopg2
from confluent_kafka import Consumer, KafkaError
from datetime import datetime

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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

def setup_database():
    """Ensure the audit_logs table exists."""
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
    # Insert a genesis block if table is completely empty
    cursor.execute("SELECT COUNT(*) FROM audit_logs")
    if cursor.fetchone()[0] == 0:
        genesis_hash = hashlib.sha256(b"SENTINEL_GENESIS_BLOCK").hexdigest()
        cursor.execute("""
            INSERT INTO audit_logs (timestamp, agent_id, action, payload, decision, previous_hash, current_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (datetime.now(), "SYSTEM", "INIT", json.dumps({}), "ALLOW", "0"*64, genesis_hash))
    conn.commit()
    cursor.close()
    conn.close()
    logging.info("Database setup complete.")

def get_latest_hash():
    """Fetch the hash of the most recent audit log to link the chain."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT current_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return result[0] if result else ("0" * 64)

def insert_audit_log(agent_id, action, payload, decision, prev_hash, curr_hash):
    """Save the cryptographically secured log to PostgreSQL."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO audit_logs (timestamp, agent_id, action, payload, decision, previous_hash, current_hash)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (datetime.now(), agent_id, action, json.dumps(payload), decision, prev_hash, curr_hash))
    conn.commit()
    cursor.close()
    conn.close()

def consume_audit_logs():
    """
    Connects to Redpanda, processes incoming events, applies Hash-Chaining,
    and persists them to PostgreSQL.
    """
    conf = {
        'bootstrap.servers': 'localhost:9092',
        'group.id': 'python_audit_worker',
        'auto.offset.reset': 'earliest'
    }

    consumer = Consumer(conf)
    topic = 'sentinel-audit-events'
    
    # Initialize the database table
    try:
        setup_database()
    except Exception as e:
        logging.error(f"Failed to setup database: {e}. (Is Docker running?)")
        return

    try:
        consumer.subscribe([topic])
        logging.info(f"Subscribed to topic: {topic}. Waiting for events from Gateway...")

        while True:
            msg = consumer.poll(timeout=1.0)
            
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                else:
                    logging.error(f"Consumer error: {msg.error()}")
                    break

            try:
                # 1. Read event
                event_data = json.loads(msg.value().decode('utf-8'))
                
                # We expect the Go API to send these fields at a minimum
                agent_id = event_data.get("agent_id", "UNKNOWN")
                action = event_data.get("action", "UNKNOWN")
                decision = event_data.get("decision", "UNKNOWN")
                payload = event_data.get("payload", {})
                
                # 2. Get previous hash to maintain the chain
                prev_hash = get_latest_hash()
                
                # 3. Create the new cryptographic hash (The "Blockchain without Blockchain" logic)
                data_to_lock = f"{prev_hash}{agent_id}{action}{decision}{json.dumps(payload, sort_keys=True)}"
                curr_hash = hashlib.sha256(data_to_lock.encode('utf-8')).hexdigest()
                
                # 4. Save to Immutable Database
                insert_audit_log(agent_id, action, payload, decision, prev_hash, curr_hash)
                
                logging.info(f"🔒 Secured Event: {agent_id} | Action: {action} | Decision: {decision} | Hash: {curr_hash[:8]}...")
                
            except Exception as e:
                logging.error(f"Failed to process message: {e}")

    except KeyboardInterrupt:
        logging.info("Shutting down consumer...")
    finally:
        consumer.close()

if __name__ == "__main__":
    consume_audit_logs()
