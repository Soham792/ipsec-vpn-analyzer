#!/bin/bash
# Generate Web (HTTP) traffic across IPsec tunnel
# Usage: ./gen_web.sh [target_ip] [duration_seconds]

TARGET_IP="${1:-172.28.0.20}"
DURATION="${2:-15}"
PORT="${3:-8000}"

echo "[Traffic Gen: Web] Starting HTTP traffic to ${TARGET_IP}:${PORT} for ${DURATION}s..."

END_TIME=$((SECONDS + DURATION))

while [ $SECONDS -lt $END_TIME ]; do
    # GET standard index
    curl -s -m 2 "http://${TARGET_IP}:${PORT}/" > /dev/null || true
    sleep 0.2
    
    # POST payload
    curl -s -m 2 -X POST -H "Content-Type: application/json" -d '{"event":"telemetry","status":"active","metrics":{"cpu":45.2,"mem":68.1}}' "http://${TARGET_IP}:${PORT}/api/metrics" > /dev/null || true
    sleep 0.3
    
    # GET large binary chunk
    curl -s -m 3 "http://${TARGET_IP}:${PORT}/large.bin" > /dev/null || true
    sleep 0.5
done

echo "[Traffic Gen: Web] Finished web traffic generation."
