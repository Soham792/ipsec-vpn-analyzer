# StrongSwan IPsec VPN Lab Node Dockerfile
# Based on Ubuntu 22.04 LTS
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install strongSwan, swanctl, plugins, network utilities, python, and capture tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan \
    strongswan-swanctl \
    strongswan-pki \
    libcharon-extra-plugins \
    libstrongswan-extra-plugins \
    libstrongswan-standard-plugins \
    tcpdump \
    tshark \
    curl \
    iproute2 \
    iptables \
    iputils-ping \
    net-tools \
    socat \
    procps \
    python3 \
    python3-pip \
    python3-scapy \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies for traffic generation inside containers
RUN pip3 install --no-cache-dir \
    scapy \
    requests \
    aiosmtpd

# Create strongSwan directory structure
RUN mkdir -p /etc/swanctl/conf.d \
    /etc/swanctl/x509 \
    /etc/swanctl/x509ca \
    /etc/swanctl/rsa \
    /etc/swanctl/pkcs8 \
    /etc/swanctl/pubkey \
    /var/run/charon \
    /workspace/lab \
    /workspace/data/pcaps

# Set working directory
WORKDIR /workspace

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 500/udp 4500/udp 8000 2525 5004/udp 5006/udp 5222/udp

ENTRYPOINT ["/entrypoint.sh"]
CMD ["sleep", "infinity"]
