import os

DB_HOST = os.getenv("SENTINEL_DB_HOST", "localhost")
DB_NAME = os.getenv("SENTINEL_DB_NAME", "sentinel_audit")
DB_USER = os.getenv("SENTINEL_DB_USER", "sentinel")
DB_PASS = os.getenv("SENTINEL_DB_PASS", "password123")

REDIS_HOST = os.getenv("SENTINEL_REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("SENTINEL_REDIS_PORT", "6379"))

KAFKA_BOOTSTRAP = os.getenv("SENTINEL_KAFKA_BOOTSTRAP", "localhost:9092")
KAFKA_TOPIC = os.getenv("SENTINEL_KAFKA_TOPIC", "sentinel-audit-events")

API_HOST = os.getenv("SENTINEL_API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("SENTINEL_API_PORT", "8000"))

# Trust Economy defaults
FLEET_BUDGET_TOTAL = float(os.getenv("SENTINEL_FLEET_BUDGET", "100000"))
DEFAULT_AGENT_CEILING = float(os.getenv("SENTINEL_AGENT_CEILING", "10000"))

# Canonical numerical index mapping for ML vectorization
ACTION_INDEX = {
    "TRANSFER": 0,
    "REFUND": 1,
    "ISSUE_REFUND": 1,
    "CREDIT_INCREASE": 2,
    "LOCK_CARD": 3,
    "LOGIN": 4,
    "WITHDRAW": 5,
    "INIT": 6,
}

AGENT_PROFILES = {
    "ag_Dispute_AI": {"model": "gpt-4", "prompt": "dispute_v3", "tools": "refund_api"},
    "ag_Travel_Bot": {"model": "gpt-4", "prompt": "dispute_v3", "tools": "refund_api"},
    "ag_Fraud_Bot": {"model": "claude-3", "prompt": "fraud_v1", "tools": "lock_api"},
    "ag_Rogue_Sim": {"model": "gpt-4", "prompt": "dispute_v3", "tools": "refund_api"},
}
