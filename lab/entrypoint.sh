#!/bin/bash
set -e

echo "=== Initializing strongSwan IPsec Node ==="

# Enable kernel IP forwarding if permitted
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
sysctl -w net.ipv6.conf.all.forwarding=1 2>/dev/null || true

# Set up swanctl pre-shared keys
cat << 'EOF' > /etc/swanctl/conf.d/secrets.conf
secrets {
    ike-psk {
        secret = "VpnSecretKey2026!SihStrongPsk"
    }
}
EOF

# Set up classic ipsec.secrets as fallback
cat << 'EOF' > /etc/ipsec.secrets
: PSK "VpnSecretKey2026!SihStrongPsk"
EOF
chmod 600 /etc/ipsec.secrets /etc/swanctl/conf.d/secrets.conf 2>/dev/null || true

# Start charon daemon if not already running
if ! pgrep -x "charon" > /dev/null; then
    echo "Starting strongSwan charon daemon..."
    # Ensure run dir exists
    mkdir -p /var/run/charon
    /usr/lib/ipsec/charon &
    
    # Wait for VICI socket to be ready
    for i in $(seq 1 15); do
        if [ -S /var/run/charon.vici ]; then
            echo "Charon daemon ready (VICI socket available)."
            break
        fi
        sleep 0.5
    done
fi

# Load initial swanctl secrets
swanctl --load-creds 2>/dev/null || true

# If this is node-b, launch traffic receiver daemon in background
if [[ "$HOSTNAME" == *"node-b"* ]] || [[ "$NODE_ROLE" == "responder" ]] || [[ "$NODE_ROLE" == "node-b" ]]; then
    echo "Starting Traffic Receiver Server on node-b..."
    if [ -f "/workspace/lab/traffic/traffic_server.py" ]; then
        python3 /workspace/lab/traffic/traffic_server.py &
    fi
fi

echo "=== strongSwan Node Ready ==="

# Execute passed command
exec "$@"
