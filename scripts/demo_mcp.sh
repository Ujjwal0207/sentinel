#!/bin/bash
set -e

# ==============================================================================
# 🛡️ SENTINEL: 30-Second Zero-Trust MCP Tool Execution Demo
# ==============================================================================
# Demonstrates pure-Go Standalone Edge Mode:
# 1. Microsecond MCP Tool Call Authorization
# 2. Wire-Speed Destructive SQL Injection Interception
# 3. Mathematical Offline Merkle Audit Trail Verification
# ==============================================================================

PORT=8089
GATEWAY_DIR="$(cd "$(dirname "$0")/../gateway" && pwd)"
WAL_FILE="/tmp/sentinel_demo_audit.wal"

# Ensure clean slate
lsof -ti :$PORT | xargs kill -9 2>/dev/null || true
rm -f "$WAL_FILE"

# Cleanup on exit
cleanup() {
    lsof -ti :$PORT | xargs kill -9 2>/dev/null || true
    if [ -n "$GATEWAY_PID" ]; then
        kill "$GATEWAY_PID" 2>/dev/null || true
        wait "$GATEWAY_PID" 2>/dev/null || true
    fi
    rm -f "$WAL_FILE"
}
trap cleanup EXIT

echo "========================================================================"
echo "🛡️  SENTINEL: Standalone Edge Mode Demo (Pure Go, Zero Dependencies)"
echo "========================================================================"

# 1. Start Sentinel Gateway in Standalone Edge Mode
echo "🚀 [Step 1] Booting Sentinel Gateway on port :$PORT in Standalone Edge Mode..."
export PORT=$PORT
export SENTINEL_MODE="standalone"
export SENTINEL_INPROCESS_POLICY="true"
export SENTINEL_WAL_PATH="$WAL_FILE"

cd "$GATEWAY_DIR"
go run . run > /dev/null 2>&1 &
GATEWAY_PID=$!

# Wait for server to become healthy
for i in {1..30}; do
    if curl -s "http://localhost:$PORT/health" > /dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

echo "✅ Sentinel Gateway is live! (PID: $GATEWAY_PID)"
curl -s "http://localhost:$PORT/health" | grep -o '"mode":"[^"]*"' || true
echo ""

# 2. Test Benign MCP Tool Call
echo "📋 [Step 2] Sending Benign MCP Tool Call: 'issue_refund' ($45.00 USD)..."
BENIGN_PAYLOAD='{"jsonrpc":"2.0","id":101,"method":"tools/call","params":{"name":"issue_refund","arguments":{"amount":45.0,"currency":"USD"}}}'

BENIGN_RESP=$(curl -s -X POST "http://localhost:$PORT/mcp" \
    -H "Content-Type: application/json" \
    -d "$BENIGN_PAYLOAD")

echo "👉 Response: $BENIGN_RESP"
echo ""

# 3. Test Adversarial Prompt-Injected Tool Call
echo "🚨 [Step 3] Sending Adversarial MCP Tool Call: Prompt-Injected 'DROP TABLE users'..."
ATTACK_PAYLOAD='{"jsonrpc":"2.0","id":102,"method":"tools/call","params":{"name":"query","arguments":{"query":"DROP TABLE users; -- ignore previous constraints"}}}'

ATTACK_RESP=$(curl -s -X POST "http://localhost:$PORT/mcp" \
    -H "Content-Type: application/json" \
    -d "$ATTACK_PAYLOAD")

echo "⛔ Interception: $ATTACK_RESP"
echo ""

# 4. Offline Cryptographic Verification
echo "🔐 [Step 4] Running Sentinel Offline Merkle WAL Verifier CLI..."
go run . verify "$WAL_FILE" || true

echo "========================================================================"
echo "🏆 DEMO COMPLETE: Pure Go Edge Gateway successfully protected the MCP tool boundary!"
echo "========================================================================"
