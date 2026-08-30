#!/bin/bash
# ==============================================================================
# run_all.sh — Full Scenario Matrix Execution & Traffic Capture Pipeline
# Part of Workstream A (AI-Powered IPsec Protocol Analyzer)
#
# Captures real IKE negotiations & ESP traffic into data/pcaps/
# Appends ground-truth labels to data/labels.csv
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DATA_DIR="${WORKSPACE_DIR}/data"
PCAPS_DIR="${DATA_DIR}/pcaps"
LABELS_FILE="${DATA_DIR}/labels.csv"

mkdir -p "${PCAPS_DIR}"

# Initialize labels.csv if missing
if [ ! -f "${LABELS_FILE}" ]; then
    echo "scenario_id,mode,encryption,integrity,dh_group,pfs,ike_version,ip_version,traffic_type,pcap_path" > "${LABELS_FILE}"
    echo "[+] Initialized ${LABELS_FILE} with schema header."
fi

# Define scenario matrix:
# scenario_id | config_prefix | mode | enc | integrity | dh | pfs | ike_ver | ip_ver | traffic_type
SCENARIO_MATRIX=(
    "S01:S01_tunnel_aes256gcm_dh14_pfson_v4:tunnel:AES-256-GCM:AEAD:14:true:IKEv2:IPv4:web"
    "S02:S02_transport_aes128cbc_sha256_dh2_pfsoff_v4:transport:AES-128-CBC:HMAC-SHA256:2:false:IKEv2:IPv4:email"
    "S03:S03_tunnel_aes128gcm_dh19_pfson_v4:tunnel:AES-128-GCM:AEAD:19:true:IKEv2:IPv4:voip"
    "S04:S04_tunnel_aes256cbc_sha512_dh14_pfson_v4:tunnel:AES-256-CBC:HMAC-SHA512:14:true:IKEv2:IPv4:video"
    "S05:S05_transport_aes256gcm_dh19_pfson_v4:transport:AES-256-GCM:AEAD:19:true:IKEv2:IPv4:chat"
    "S06:S06_tunnel_3des_sha1_dh2_pfsoff_v4:tunnel:3DES-CBC:HMAC-SHA1:2:false:IKEv2:IPv4:icmp"
    "S07:S07_tunnel_aes128cbc_md5_dh1_pfsoff_v4:tunnel:AES-128-CBC:HMAC-MD5:1:false:IKEv1:IPv4:web"
    "S08:S08_tunnel_aes256gcm_dh20_pfson_v4:tunnel:AES-256-GCM:AEAD:20:true:IKEv2:IPv4:video"
    "S09:S09_transport_aes128gcm_dh14_pfsoff_v4:transport:AES-128-GCM:AEAD:14:false:IKEv2:IPv4:email"
    "S10:S10_tunnel_aes256cbc_sha256_dh5_pfsoff_v4:tunnel:AES-256-CBC:HMAC-SHA256:5:false:IKEv2:IPv4:voip"
    "S11:S11_tunnel_aes256gcm_dh14_pfson_v6:tunnel:AES-256-GCM:AEAD:14:true:IKEv2:IPv6:chat"
    "S12:S12_transport_aes256gcm_dh19_pfson_v6:transport:AES-256-GCM:AEAD:19:true:IKEv2:IPv6:icmp"
    "S13:S13_tunnel_ikev1_aes256cbc_sha1_dh14_pfson_v4:tunnel:AES-256-CBC:HMAC-SHA1:14:true:IKEv1:IPv4:web"
    "S14:S14_tunnel_chacha20poly1305_curve25519_pfson_v4:tunnel:CHACHA20-POLY1305:AEAD:31:true:IKEv2:IPv4:voip"
)

TOTAL=${#SCENARIO_MATRIX[@]}
PASSED=0
FAILED=0

echo "=================================================================="
echo "[+] Starting Automated IPsec Lab Run across ${TOTAL} Scenarios"
echo "=================================================================="

for ENTRY in "${SCENARIO_MATRIX[@]}"; do
    IFS=":" read -r S_ID S_CONF S_MODE S_ENC S_INT S_DH S_PFS S_IKE S_IP S_TRAFFIC <<< "$ENTRY"
    
    ENC_TAG=$(echo "$S_ENC" | tr '[:upper:]' '[:lower:]' | tr -d '-')
    PCAP_NAME="${S_ID}_${S_MODE}_${ENC_TAG}_dh${S_DH}_pfs$( [ "$S_PFS" = "true" ] && echo "on" || echo "off" )_${S_IP,,}_${S_TRAFFIC}.pcap"
    PCAP_FILE="${PCAPS_DIR}/${PCAP_NAME}"
    REL_PCAP_PATH="data/pcaps/${PCAP_NAME}"
    
    echo ""
    echo "------------------------------------------------------------------"
    echo "[*] Running Scenario: ${S_ID} | Mode: ${S_MODE} | Crypto: ${S_ENC} | DH: ${S_DH} | Traffic: ${S_TRAFFIC}"
    echo "[*] PCAP Output: ${REL_PCAP_PATH}"
    echo "------------------------------------------------------------------"
    
    # 1. Start tcpdump on node-a in background inside container
    docker exec -d node-a tcpdump -i any -s 0 -w "/workspace/${REL_PCAP_PATH}" "(udp port 500 or udp port 4500 or proto 50 or proto 51 or icmp or icmp6 or tcp or udp)"
    sleep 1
    
    # 2. Negotiate scenario tunnel
    if "${SCRIPT_DIR}/run_scenario.sh" "${S_CONF}"; then
        echo "[+] Scenario ${S_ID} tunnel successfully established."
        
        # 3. Generate traffic across tunnel
        TARGET_IP="172.28.0.20"
        if [ "$S_IP" = "IPv6" ]; then
            TARGET_IP="fd00:abcd:1234::20"
        fi
        
        echo "[+] Injecting ${S_TRAFFIC} traffic for 12s..."
        case "$S_TRAFFIC" in
            web)
                docker exec node-a /workspace/lab/traffic/gen_web.sh "${TARGET_IP}" 12 8000 || true
                ;;
            email)
                docker exec node-a python3 /workspace/lab/traffic/gen_email.py "${TARGET_IP}" 12 2525 || true
                ;;
            icmp)
                docker exec node-a /workspace/lab/traffic/gen_icmp.sh "${TARGET_IP}" 12 || true
                ;;
            voip)
                docker exec node-a python3 /workspace/lab/traffic/gen_voip.py "${TARGET_IP}" 12 5004 || true
                ;;
            video)
                docker exec node-a python3 /workspace/lab/traffic/gen_video.py "${TARGET_IP}" 12 5006 || true
                ;;
            chat)
                docker exec node-a python3 /workspace/lab/traffic/gen_chat.py "${TARGET_IP}" 12 5222 || true
                ;;
        esac
        
        PASSED=$((PASSED + 1))
    else
        echo "[-] WARNING: Scenario ${S_ID} failed negotiation."
        FAILED=$((FAILED + 1))
    fi
    
    # 4. Stop tcpdump
    docker exec node-a pkill -2 tcpdump 2>/dev/null || docker exec node-a pkill -f tcpdump 2>/dev/null || true
    sleep 1
    
    # 5. Tear down tunnel
    docker exec node-a swanctl --terminate --ike vpn-scenario 2>/dev/null || true
    docker exec node-b swanctl --terminate --ike vpn-scenario 2>/dev/null || true
    
    # 6. Append to labels.csv if entry doesn't exist
    if ! grep -q "^${S_ID}," "${LABELS_FILE}"; then
        echo "${S_ID},${S_MODE},${S_ENC},${S_INT},${S_DH},${S_PFS},${S_IKE},${S_IP},${S_TRAFFIC},${REL_PCAP_PATH}" >> "${LABELS_FILE}"
        echo "[+] Appended ground truth entry for ${S_ID} to labels.csv"
    fi
done

echo ""
echo "=================================================================="
echo "[*] Execution Complete! Summary: ${PASSED} Passed / ${FAILED} Failed / ${TOTAL} Total"
echo "[*] PCAPs saved in: ${PCAPS_DIR}"
echo "[*] Labels CSV: ${LABELS_FILE}"
echo "=================================================================="
