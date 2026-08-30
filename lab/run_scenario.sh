#!/bin/bash
# ==============================================================================
# run_scenario.sh — Automated IPsec Scenario Loader & Initiator
# Part of Workstream A (AI-Powered IPsec Protocol Analyzer)
#
# Usage:
#   ./lab/run_scenario.sh <scenario_id_or_config_file>
# Example:
#   ./lab/run_scenario.sh S01
#   ./lab/run_scenario.sh S01_tunnel_aes256gcm_dh14_pfson_v4
#   ./lab/run_scenario.sh lab/configs/S01_tunnel_aes256gcm_dh14_pfson_v4.conf
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONFIGS_DIR="${SCRIPT_DIR}/configs"

TARGET="${1:-S01}"

# Resolve config file path
CONFIG_FILE=""
if [ -f "$TARGET" ]; then
    CONFIG_FILE="$TARGET"
elif [ -f "${CONFIGS_DIR}/${TARGET}" ]; then
    CONFIG_FILE="${CONFIGS_DIR}/${TARGET}"
elif [ -f "${CONFIGS_DIR}/${TARGET}.conf" ]; then
    CONFIG_FILE="${CONFIGS_DIR}/${TARGET}.conf"
else
    # Try prefix matching (e.g. "S01")
    MATCH=$(find "${CONFIGS_DIR}" -maxdepth 1 -name "${TARGET}*.conf" | head -n 1)
    if [ -n "$MATCH" ] && [ -f "$MATCH" ]; then
        CONFIG_FILE="$MATCH"
    else
        echo "[-] Error: Config for '$TARGET' not found in ${CONFIGS_DIR}."
        echo "Available scenarios:"
        ls -1 "${CONFIGS_DIR}"/*.conf 2>/dev/null || true
        exit 1
    fi
fi

SCENARIO_NAME="$(basename "${CONFIG_FILE}" .conf)"
echo "=================================================================="
echo "[+] Target Scenario: ${SCENARIO_NAME}"
echo "[+] Config Template: ${CONFIG_FILE}"
echo "=================================================================="

# Check if docker containers node-a and node-b are running
if ! docker ps --format '{{.Names}}' | grep -q "^node-a$"; then
    echo "[-] Error: Container 'node-a' is not running. Please start lab with 'docker compose -f lab/docker-compose.yml up -d'"
    exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -q "^node-b$"; then
    echo "[-] Error: Container 'node-b' is not running. Please start lab with 'docker compose -f lab/docker-compose.yml up -d'"
    exit 1
fi

# Clean up any existing swanctl scenario config
docker exec node-a sh -c 'rm -f /etc/swanctl/conf.d/active*.conf' 2>/dev/null || true
docker exec node-b sh -c 'rm -f /etc/swanctl/conf.d/active*.conf' 2>/dev/null || true

# Generate Node-A config
NODE_A_CONF=$(cat "$CONFIG_FILE" \
    | sed 's/%LOCAL_IP%/172.28.0.10/g' \
    | sed 's/%REMOTE_IP%/172.28.0.20/g' \
    | sed 's/%LOCAL_IPV6%/fd00:abcd:1234::10/g' \
    | sed 's/%REMOTE_IPV6%/fd00:abcd:1234::20/g' \
    | sed 's/%LOCAL_ID%/node-a/g' \
    | sed 's/%REMOTE_ID%/node-b/g' \
    | sed 's/%LOCAL_TS%/172.28.0.10\/32/g' \
    | sed 's/%REMOTE_TS%/172.28.0.20\/32/g' \
    | sed 's/%LOCAL_TS_V6%/fd00:abcd:1234::10\/128/g' \
    | sed 's/%REMOTE_TS_V6%/fd00:abcd:1234::20\/128/g')

# Generate Node-B config (symmetric mirror)
NODE_B_CONF=$(cat "$CONFIG_FILE" \
    | sed 's/%LOCAL_IP%/172.28.0.20/g' \
    | sed 's/%REMOTE_IP%/172.28.0.10/g' \
    | sed 's/%LOCAL_IPV6%/fd00:abcd:1234::20/g' \
    | sed 's/%REMOTE_IPV6%/fd00:abcd:1234::10/g' \
    | sed 's/%LOCAL_ID%/node-b/g' \
    | sed 's/%REMOTE_ID%/node-a/g' \
    | sed 's/%LOCAL_TS%/172.28.0.20\/32/g' \
    | sed 's/%REMOTE_TS%/172.28.0.10\/32/g' \
    | sed 's/%LOCAL_TS_V6%/fd00:abcd:1234::20\/128/g' \
    | sed 's/%REMOTE_TS_V6%/fd00:abcd:1234::10\/128/g')

# Push config to Node-A
echo "$NODE_A_CONF" | docker exec -i node-a tee /etc/swanctl/conf.d/active.conf > /dev/null

# Push config to Node-B
echo "$NODE_B_CONF" | docker exec -i node-b tee /etc/swanctl/conf.d/active.conf > /dev/null

echo "[+] Config deployed to node-a and node-b."

# Terminate existing SAs on both nodes
docker exec node-a swanctl --terminate --ike vpn-scenario 2>/dev/null || true
docker exec node-b swanctl --terminate --ike vpn-scenario 2>/dev/null || true
sleep 1

# Reload swanctl on both nodes
echo "[+] Reloading strongSwan configuration..."
docker exec node-b swanctl --load-all > /dev/null 2>&1 || true
docker exec node-a swanctl --load-all > /dev/null 2>&1 || true

# Initiate tunnel from Node-A
echo "[+] Initiating tunnel from node-a -> node-b..."
INIT_OUT=$(docker exec node-a swanctl --initiate --child vpn-child 2>&1 || true)
echo "$INIT_OUT"

# Verify tunnel state
echo "[+] Verifying SA establishment..."
ESTABLISHED=false
for i in $(seq 1 10); do
    SAS=$(docker exec node-a swanctl --list-sas 2>&1 || true)
    if echo "$SAS" | grep -q "ESTABLISHED" || echo "$SAS" | grep -q "INSTALLED"; then
        ESTABLISHED=true
        break
    fi
    sleep 1
done

if [ "$ESTABLISHED" = true ]; then
    echo "=================================================================="
    echo "[*] SUCCESS: Scenario ${SCENARIO_NAME} Negotiated & ESTABLISHED!"
    echo "=================================================================="
    docker exec node-a swanctl --list-sas
    exit 0
else
    echo "=================================================================="
    echo "[-] FAILED: Scenario ${SCENARIO_NAME} could not establish SA."
    echo "=================================================================="
    echo "Diagnostics from node-a:"
    docker exec node-a swanctl --list-sas || true
    exit 1
fi
