import json
import logging
import hashlib
import time
import psycopg2
from confluent_kafka import Consumer, KafkaError
from datetime import datetime

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database & Broker Configuration (from config.py with safe fallback)
try:
    from config import DB_HOST, DB_NAME, DB_USER, DB_PASS, DB_PORT, KAFKA_BOOTSTRAP, KAFKA_TOPIC
except ImportError:
    import os
    DB_HOST = os.getenv("SENTINEL_DB_HOST", "localhost")
    DB_NAME = os.getenv("SENTINEL_DB_NAME", "sentinel_audit")
    DB_USER = os.getenv("SENTINEL_DB_USER", "sentinel")
    DB_PASS = os.getenv("SENTINEL_DB_PASS", "password123")
    DB_PORT = int(os.getenv("SENTINEL_DB_PORT", "5432"))
    KAFKA_BOOTSTRAP = os.getenv("SENTINEL_KAFKA_BOOTSTRAP", "localhost:9092")
    KAFKA_TOPIC = os.getenv("SENTINEL_KAFKA_TOPIC", "sentinel-audit-events")

def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
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

def parse_origin_timestamp(event_data: dict) -> datetime:
    """
    Parse the RFC3339 origin timestamp from the Go Gateway event payload.
    Falls back to current time if the field is missing or malformed.
    This ensures the cryptographic ledger records the TRUE time of the event,
    not the delayed consumption time.
    """
    raw_ts = event_data.get("timestamp") or event_data.get("Timestamp")
    if raw_ts and isinstance(raw_ts, str):
        # Try ISO 8601 / RFC3339 formats
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S.%f%z"):
            try:
                return datetime.strptime(raw_ts, fmt)
            except ValueError:
                continue
        # Python 3.7+ fromisoformat fallback
        try:
            return datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            pass
    # Fallback: use current time (preserves backward compat)
    return datetime.now()

def insert_audit_log(timestamp_val, agent_id, action, payload, decision, prev_hash, curr_hash):
    """Save the cryptographically secured log to PostgreSQL."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO audit_logs (timestamp, agent_id, action, payload, decision, previous_hash, current_hash)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (timestamp_val, agent_id, action, json.dumps(payload), decision, prev_hash, curr_hash))
    conn.commit()
    cursor.close()
    conn.close()

def consume_audit_logs():
    """
    Connects to Redpanda, processes incoming events, applies Hash-Chaining,
    and persists them to PostgreSQL.

    Resilience: transient Kafka errors trigger exponential backoff retry
    instead of fatal consumer termination.
    """
    conf = {
        'bootstrap.servers': KAFKA_BOOTSTRAP,
        'group.id': 'python_audit_worker',
        'auto.offset.reset': 'earliest'
    }

    consumer = Consumer(conf)
    topic = KAFKA_TOPIC
    
    # Initialize the database table
    try:
        setup_database()
    except Exception as e:
        logging.error(f"Failed to setup database: {e}. (Is Docker running?)")
        return

    # Exponential backoff state for transient Kafka errors
    consecutive_errors = 0
    MAX_BACKOFF_SECONDS = 30

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
                    # --- RESILIENT RETRY: transient errors no longer kill the consumer ---
                    consecutive_errors += 1
                    backoff = min(MAX_BACKOFF_SECONDS, 2 ** consecutive_errors)
                    logging.warning(
                        f"⚠️ Transient Kafka error (attempt {consecutive_errors}): {msg.error()}. "
                        f"Retrying in {backoff}s..."
                    )
                    time.sleep(backoff)
                    continue

            # Reset backoff on successful message
            consecutive_errors = 0

            try:
                # 1. Read event
                event_data = json.loads(msg.value().decode('utf-8'))
                
                # We expect the Go API to send these fields at a minimum
                agent_id = event_data.get("agent_id", "UNKNOWN")
                action = event_data.get("action", "UNKNOWN")
                decision = event_data.get("decision", "UNKNOWN")
                payload = event_data.get("payload", {})
                
                # 2. Parse the TRUE origin timestamp from the Gateway event
                origin_ts = parse_origin_timestamp(event_data)
                
                # 3. Get previous hash to maintain the chain
                prev_hash = get_latest_hash()
                
                # 4. Create the new cryptographic hash (The "Blockchain without Blockchain" logic)
                data_to_lock = f"{prev_hash}{agent_id}{action}{decision}{json.dumps(payload, sort_keys=True)}"
                curr_hash = hashlib.sha256(data_to_lock.encode('utf-8')).hexdigest()
                
                # 5. Save to Immutable Database with origin timestamp
                insert_audit_log(origin_ts, agent_id, action, payload, decision, prev_hash, curr_hash)
                
                logging.info(f"🔒 Secured Event: {agent_id} | Action: {action} | Decision: {decision} | Hash: {curr_hash[:8]}...")
                
            except Exception as e:
                logging.error(f"Failed to process message: {e}")

    except KeyboardInterrupt:
        logging.info("Shutting down consumer...")
    finally:
        consumer.close()

if __name__ == "__main__":
    consume_audit_logs()
