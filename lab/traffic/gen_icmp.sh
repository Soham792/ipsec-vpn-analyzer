#!/bin/bash
# Generate ICMP Ping traffic across IPsec tunnel
# Usage: ./gen_icmp.sh [target_ip] [duration_seconds]

TARGET_IP="${1:-172.28.0.20}"
DURATION="${2:-15}"

echo "[Traffic Gen: ICMP] Sending ping bursts to ${TARGET_IP} for ${DURATION}s..."

END_TIME=$((SECONDS + DURATION))

while [ $SECONDS -lt $END_TIME ]; do
    # Standard 64-byte ping
    ping -c 2 -W 1 -s 56 "${TARGET_IP}" > /dev/null 2>&1 || true
    sleep 0.5

    # 128-byte ping
    ping -c 2 -W 1 -s 120 "${TARGET_IP}" > /dev/null 2>&1 || true
    sleep 0.5

    # 512-byte ping
    ping -c 1 -W 1 -s 504 "${TARGET_IP}" > /dev/null 2>&1 || true
    sleep 0.8
done

echo "[Traffic Gen: ICMP] Finished ICMP traffic generation."
