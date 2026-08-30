#!/bin/bash
# ==============================================================================
# verify_lab.sh — Environment & Lab Health Verification Script
# Part of Workstream A (AI-Powered IPsec Protocol Analyzer)
# ==============================================================================

echo "=================================================================="
echo "=== 1. Checking Linux IPsec Kernel Modules ==="
echo "=================================================================="
if command -v lsmod >/dev/null 2>&1; then
    lsmod | grep -E "esp4|esp6|ah4|ah6|xfrm" || echo "[!] Notice: XFRM kernel modules not explicitly listed in lsmod (Docker host kernel might provide built-in support)."
else
    echo "[!] lsmod not available on host."
fi

echo ""
echo "=================================================================="
echo "=== 2. Checking Docker & Container Status ==="
echo "=================================================================="
if ! command -v docker >/dev/null 2>&1; then
    echo "[-] Docker is not installed or not in PATH."
    exit 1
fi

docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -E "NAMES|node-a|node-b" || echo "[!] node-a and node-b containers are not currently running."

echo ""
echo "=================================================================="
echo "=== 3. Testing Container Network Connectivity ==="
echo "=================================================================="
if docker ps --format '{{.Names}}' | grep -q "^node-a$" && docker ps --format '{{.Names}}' | grep -q "^node-b$"; then
    echo "[+] Node-A -> Node-B IPv4 Ping:"
    docker exec node-a ping -c 2 172.28.0.20 || echo "[-] IPv4 Ping failed!"

    echo "[+] Node-A -> Node-B IPv6 Ping:"
    docker exec node-a ping6 -c 2 fd00:abcd:1234::20 || echo "[!] IPv6 Ping failed (check IPv6 bridge settings)."

    echo ""
    echo "=================================================================="
    echo "=== 4. Checking strongSwan Daemon Status ==="
    echo "=================================================================="
    echo "[+] Node-A strongSwan status:"
    docker exec node-a swanctl --version || docker exec node-a ipsec --version || true
    docker exec node-a swanctl --list-sas || true

    echo "[+] Node-B strongSwan status:"
    docker exec node-b swanctl --version || docker exec node-b ipsec --version || true
else
    echo "[!] Containers not running. Start them with:"
    echo "    docker compose -f lab/docker-compose.yml up -d"
fi

echo ""
echo "=== Lab Health Check Complete ==="
