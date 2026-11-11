# Stage 1: Build pure-Go / Casbin SENTINEL Edge Gateway
FROM golang:1.24-bookworm AS gateway-builder

WORKDIR /src/gateway
COPY gateway/go.mod gateway/go.sum ./
RUN go mod download

COPY gateway/ ./
RUN go build -o /out/sentinel-gateway .

# Stage 2: Combined Render Web Service Runtime (Go Gateway + Python FastAPI + Gemini + PayPal + Elastic)
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SENTINEL_MODE=standalone \
    SENTINEL_INPROCESS_POLICY=true \
    SENTINEL_CASBIN_DIR=/app/casbin_policies \
    SENTINEL_WAL_PATH=/tmp/sentinel_audit.wal

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=gateway-builder /out/sentinel-gateway /usr/local/bin/sentinel-gateway
COPY casbin_policies/ ./casbin_policies/

COPY python_workers/requirements.txt ./python_workers/requirements.txt
RUN pip install --no-cache-dir -r ./python_workers/requirements.txt

COPY python_workers/ ./python_workers/
COPY scripts/start_render.sh /usr/local/bin/start_render.sh
RUN chmod +x /usr/local/bin/start_render.sh

EXPOSE 8000

CMD ["/usr/local/bin/start_render.sh"]
