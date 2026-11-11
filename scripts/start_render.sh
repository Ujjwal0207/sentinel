#!/usr/bin/env sh
set -eu

GATEWAY_PORT="${SENTINEL_GATEWAY_PORT:-8080}"
API_PORT="${PORT:-8000}"

export SENTINEL_CASBIN_DIR="${SENTINEL_CASBIN_DIR:-/app/casbin_policies}"
export SENTINEL_WAL_PATH="${SENTINEL_WAL_PATH:-/tmp/sentinel_audit.wal}"
export SENTINEL_GATEWAY_URL="${SENTINEL_GATEWAY_URL:-http://127.0.0.1:${GATEWAY_PORT}/enforce}"

# Launch the Go Edge Gateway in a dedicated port scope so Render's external $PORT stays free for FastAPI
PORT="${GATEWAY_PORT}" /usr/local/bin/sentinel-gateway &
GATEWAY_PID=$!

# Wait briefly for Go Edge Gateway health before starting FastAPI
i=0
while [ "$i" -lt 30 ]; do
  if curl -fsS "http://127.0.0.1:${GATEWAY_PORT}/health" >/dev/null 2>&1; then
    break
  fi
  i=$((i + 1))
  sleep 0.25
done

# Start Python FastAPI + Google Gemini + PayPal Sandbox + Elastic SIEM API on $PORT
python3 -m uvicorn python_workers.case_law_engine:app --host 0.0.0.0 --port "${API_PORT}" &
UVICORN_PID=$!

cleanup() {
  kill -TERM "${UVICORN_PID}" 2>/dev/null || true
  kill -TERM "${GATEWAY_PID}" 2>/dev/null || true
}
trap cleanup INT TERM

# Exit non-zero if either critical process stops unexpectedly
while kill -0 "${GATEWAY_PID}" 2>/dev/null && kill -0 "${UVICORN_PID}" 2>/dev/null; do
  sleep 2
done

cleanup
wait "${UVICORN_PID}" 2>/dev/null || true
wait "${GATEWAY_PID}" 2>/dev/null || true
exit 1
