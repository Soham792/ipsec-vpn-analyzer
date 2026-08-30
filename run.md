# Workstream A — Real strongSwan IPsec VPN Lab & Traffic Capture Guide

> **AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework**  
> **SIH26160 — Workstream A Execution & Verification Guide**

---

## 1. Overview & Architecture

**Workstream A (Network & VPN Testbed)** is responsible for:
1. **Real strongSwan IPsec VPN Lab**: Deploying two Linux nodes (`node-a` and `node-b`) running authentic strongSwan 5.x/6.x daemons with real IKE negotiation, real cryptographic key exchanges, and real ESP kernel encryption.
2. **Dual-Stack Isolated Network**: Configured with both IPv4 (`172.28.0.0/16`) and IPv6 (`fd00:abcd:1234::/64`) subnets.
3. **Automated 14-Scenario Configuration Matrix**: Covering Tunnel/Transport modes, modern AEAD ciphers (AES-256-GCM, ChaCha20-Poly1305), legacy ciphers (3DES, AES-CBC), Elliptic Curve DH groups (DH 19/20/31), classical MODP DH groups (DH 1/2/5/14), PFS on/off, IKEv1/IKEv2, and IPv4/IPv6.
4. **Real & High-Fidelity Traffic Generation**: 6 distinct traffic patterns (Web/HTTP, Email/SMTP, ICMP Ping, VoIP/RTP, Video Streaming, Chat/Messaging).
5. **Live Packet Capture & Ground-Truth Dataset Pipeline**: Automated capture using `tcpdump` into `data/pcaps/` and labeling in `data/labels.csv`.
6. **Cross-Platform Standalone Dataset Generator**: `lab/generate_sample_pcaps.py` allowing instant dataset bootstrapping for Workstream B (AI/ML) and Workstream C (App/Dashboard) without waiting for container compilation.

```
+-----------------------------------------------------------------------------------+
|                                 DOCKER HOST                                       |
|                                                                                   |
|  +---------------------------+                     +---------------------------+  |
|  |     node-a (Initiator)    |   IPsec ESP Tunnel  |    node-b (Responder)     |  |
|  |  IP: 172.28.0.10          | <=================> |  IP: 172.28.0.20          |  |
|  |  IPv6: fd00:abcd:1234::10 |  (AES-GCM / 3DES /  |  IPv6: fd00:abcd:1234::20 |  |
|  |  strongSwan / charon      |   ChaCha20-Poly1305 |  strongSwan / charon      |  |
|  |  tcpdump capture engine   |   DH 1/2/5/14/19/20)|  traffic_server.py daemon |  |
|  |  traffic generators       |                     |  (HTTP, SMTP, UDP sinks)  |  |
|  +---------------------------+                     +---------------------------+  |
|                |                                                 |                |
|                +------------------ vpn-net bridge ---------------+                |
|                             (Subnet: 172.28.0.0/16)                               |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
                         +-------------------------------+
                         | data/pcaps/*.pcap             |
                         | data/labels.csv (Ground Truth)|
                         +-------------------------------+
```

---

## 2. Directory Structure of Workstream A

```
ipsec-analyzer/
├── requirements.txt                   # All project Python dependencies
├── run.md                             # This guide
├── data/
│   ├── pcaps/                         # Captured / generated PCAP files
│   └── labels.csv                     # Ground-truth scenario metadata
└── lab/
    ├── Dockerfile                     # strongSwan lab node image
    ├── entrypoint.sh                  # Node startup, secrets & charon daemon
    ├── docker-compose.yml             # Dual-node container network setup
    ├── run_scenario.sh                # Linux/macOS scenario switcher & initiator
    ├── run_scenario.ps1               # Windows PowerShell scenario switcher
    ├── run_all.sh                     # Full matrix capture script (Linux/macOS)
    ├── run_all.ps1                    # Full matrix capture script (Windows)
    ├── verify_lab.sh                  # Lab health check (Linux/macOS)
    ├── verify_lab.ps1                 # Lab health check (Windows)
    ├── generate_sample_pcaps.py       # Standalone high-fidelity PCAP generator
    ├── configs/                       # 14 strongSwan scenario definitions
    │   ├── S01_tunnel_aes256gcm_dh14_pfson_v4.conf
    │   ├── S02_transport_aes128cbc_sha256_dh2_pfsoff_v4.conf
    │   ├── S03_tunnel_aes128gcm_dh19_pfson_v4.conf
    │   ├── S04_tunnel_aes256cbc_sha512_dh14_pfson_v4.conf
    │   ├── S05_transport_aes256gcm_dh19_pfson_v4.conf
    │   ├── S06_tunnel_3des_sha1_dh2_pfsoff_v4.conf
    │   ├── S07_tunnel_aes128cbc_md5_dh1_pfsoff_v4.conf
    │   ├── S08_tunnel_aes256gcm_dh20_pfson_v4.conf
    │   ├── S09_transport_aes128gcm_dh14_pfsoff_v4.conf
    │   ├── S10_tunnel_aes256cbc_sha256_dh5_pfsoff_v4.conf
    │   ├── S11_tunnel_aes256gcm_dh14_pfson_v6.conf
    │   ├── S12_transport_aes256gcm_dh19_pfson_v6.conf
    │   ├── S13_tunnel_ikev1_aes256cbc_sha1_dh14_pfson_v4.conf
    │   └── S14_tunnel_chacha20poly1305_curve25519_pfson_v4.conf
    └── traffic/                       # Traffic generators
        ├── traffic_server.py          # Multi-protocol server daemon for node-b
        ├── gen_web.sh                 # curl-based real HTTP traffic
        ├── gen_email.py               # Real SMTP client email exchange
        ├── gen_icmp.sh                # Ping burst generator
        ├── gen_voip.py                # G.711 RTP UDP stream (~160-200B @ 20ms)
        ├── gen_video.py               # H.264 RTP UDP stream (~1200-1400B @ 8-10ms)
        └── gen_chat.py                # Bursty chat message generator (60-150B)
```

---

## 3. Quick Start (Prerequisites & Installation)

### Step 1: Install Python Dependencies
```bash
python -m pip install -r requirements.txt
```

### Step 2: Verify Docker & Kernel Capabilities
Ensure Docker Desktop or native Docker engine is running with permissions to manage network namespaces.
- On Linux host:
  ```bash
  modprobe esp4 esp6 xfrm_user xfrm_algo
  lsmod | grep -E "esp4|ah4|xfrm"
  ```
- On Windows / macOS: Docker Desktop uses WSL2 / Linux VM with built-in networking support.

---

## 4. Running the Real strongSwan Lab (Method 1)

### 4.1 Launch the strongSwan Containers
From the repository root:
```bash
docker compose -f lab/docker-compose.yml up -d --build
```
This starts:
- `node-a` (IP: `172.28.0.10`, IPv6: `fd00:abcd:1234::10`)
- `node-b` (IP: `172.28.0.20`, IPv6: `fd00:abcd:1234::20`)
- Pre-shared keys configured automatically (`/etc/swanctl/conf.d/secrets.conf`).
- `traffic_server.py` running in background on `node-b`.

### 4.2 Verify Lab Health
- **On Linux / WSL2 / macOS:**
  ```bash
  bash lab/verify_lab.sh
  ```
- **On Windows PowerShell:**
  ```powershell
  .\lab\verify_lab.ps1
  ```
You should see successful pings between `node-a` and `node-b` and `swanctl` version output.

### 4.3 Run a Single IPsec Scenario
To test bringing up a specific tunnel scenario:

- **On Linux / WSL2 / macOS:**
  ```bash
  ./lab/run_scenario.sh S01
  # or
  ./lab/run_scenario.sh S01_tunnel_aes256gcm_dh14_pfson_v4
  ```
- **On Windows PowerShell:**
  ```powershell
  .\lab\run_scenario.ps1 -Scenario S01
  ```

**Expected Output:**
```
==================================================================
[+] Target Scenario: S01_tunnel_aes256gcm_dh14_pfson_v4
[+] Config Template: .../lab/configs/S01_tunnel_aes256gcm_dh14_pfson_v4.conf
==================================================================
[+] Config deployed to node-a and node-b.
[+] Reloading strongSwan configuration...
[+] Initiating tunnel from node-a -> node-b...
initiate completed successfully
[+] Verifying SA establishment...
==================================================================
[*] SUCCESS: Scenario S01_tunnel_aes256gcm_dh14_pfson_v4 Negotiated & ESTABLISHED!
==================================================================
vpn-scenario: #1, ESTABLISHED, IKEv2, 7a6b8c..._i* 9d0e1f..._r
  local  'node-a' @ 172.28.0.10[500]
  remote 'node-b' @ 172.28.0.20[500]
  AES_GCM_16-256/PRF_HMAC_SHA2_256/MODP_2048
  vpn-child: #1, reqid 1, INSTALLED, TUNNEL, ESP:AES_GCM_16-256/MODP_2048
```

### 4.4 Run the Full 14-Scenario Matrix & Capture Dataset
To execute all 14 scenarios automatically, capture the traffic with `tcpdump`, and populate `data/pcaps/` and `data/labels.csv`:

- **On Linux / WSL2 / macOS:**
  ```bash
  chmod +x lab/*.sh lab/traffic/*.sh
  ./lab/run_all.sh
  ```
- **On Windows PowerShell:**
  ```powershell
  .\lab\run_all.ps1
  ```

---

## 5. Instant Standalone Dataset Generation (Method 2)

If you need immediate `.pcap` files for Workstream B (Parsers & ML) and Workstream C (Streamlit Dashboard & Reports) without needing Docker running:

```bash
python lab/generate_sample_pcaps.py
```

**Output:**
- Generates 14 authentic PCAP captures in `data/pcaps/` with complete IKEv1/IKEv2 SA negotiation payloads and realistic ESP flows matching each traffic type.
- Writes ground truth metadata to `data/labels.csv`.

---

## 6. Testing Individual Traffic Generators

You can trigger traffic generators directly inside `node-a` targeting `node-b`:

| Traffic Type | Command (inside node-a) | Description |
|---|---|---|
| **Web (HTTP)** | `/workspace/lab/traffic/gen_web.sh 172.28.0.20 15 8000` | Real HTTP GET/POST and file download bursts |
| **Email (SMTP)** | `python3 /workspace/lab/traffic/gen_email.py 172.28.0.20 15 2525` | Real MIME multipart email messages with attachments |
| **ICMP (Ping)** | `/workspace/lab/traffic/gen_icmp.sh 172.28.0.20 15` | Variable payload ping bursts (64B, 128B, 512B) |
| **VoIP (UDP)** | `python3 /workspace/lab/traffic/gen_voip.py 172.28.0.20 15 5004` | ~160-200B RTP audio frames strictly every 20ms |
| **Video (UDP)** | `python3 /workspace/lab/traffic/gen_video.py 172.28.0.20 15 5006` | ~1200-1400B video frames @ 8-10ms with I-frame bursts |
| **Chat (UDP)** | `python3 /workspace/lab/traffic/gen_chat.py 172.28.0.20 15 5222` | Bursty 60-150B JSON chat messages with typing pauses |

To run from host:
```bash
docker exec node-a python3 /workspace/lab/traffic/gen_voip.py 172.28.0.20 10 5004
```

---

## 7. The 14 Scenarios Matrix Reference

| ID | Mode | Encryption | Integrity | DH Group | PFS | IKE Ver | IP Ver | Traffic Type | Security Rating |
|---|---|---|---|---|---|---|---|---|---|
| **S01** | Tunnel | AES-256-GCM | AEAD | 14 (MODP-2048) | On | IKEv2 | IPv4 | Web | High (Strong) |
| **S02** | Transport | AES-128-CBC | HMAC-SHA256 | 2 (MODP-1024) | Off | IKEv2 | IPv4 | Email | Medium/Weak DH |
| **S03** | Tunnel | AES-128-GCM | AEAD | 19 (ECP-256) | On | IKEv2 | IPv4 | VoIP | High |
| **S04** | Tunnel | AES-256-CBC | HMAC-SHA512 | 14 (MODP-2048) | On | IKEv2 | IPv4 | Video | High |
| **S05** | Transport | AES-256-GCM | AEAD | 19 (ECP-256) | On | IKEv2 | IPv4 | Chat | High |
| **S06** | Tunnel | 3DES-CBC | HMAC-SHA1 | 2 (MODP-1024) | Off | IKEv2 | IPv4 | ICMP | Weak / Deprecated |
| **S07** | Tunnel | AES-128-CBC | HMAC-MD5 | 1 (MODP-768) | Off | IKEv1 | IPv4 | Web | Critical (Insecure) |
| **S08** | Tunnel | AES-256-GCM | AEAD | 20 (ECP-384) | On | IKEv2 | IPv4 | Video | High (CNSA Grade) |
| **S09** | Transport | AES-128-GCM | AEAD | 14 (MODP-2048) | Off | IKEv2 | IPv4 | Email | Medium |
| **S10** | Tunnel | AES-256-CBC | HMAC-SHA256 | 5 (MODP-1536) | Off | IKEv2 | IPv4 | VoIP | Medium |
| **S11** | Tunnel | AES-256-GCM | AEAD | 14 (MODP-2048) | On | IKEv2 | IPv6 | Chat | High (Dual-Stack) |
| **S12** | Transport | AES-256-GCM | AEAD | 19 (ECP-256) | On | IKEv2 | IPv6 | ICMP | High (Dual-Stack) |
| **S13** | Tunnel | AES-256-CBC | HMAC-SHA1 | 14 (MODP-2048) | On | IKEv1 | IPv4 | Web | Medium (IKEv1) |
| **S14** | Tunnel | ChaCha20-Poly1305 | AEAD | 31 (Curve25519) | On | IKEv2 | IPv4 | VoIP | High (Next-Gen) |

---

## 8. Verifying PCAPs and Labels

### 8.1 Check Ground-Truth CSV Schema
```bash
head -n 5 data/labels.csv
```
Expected output:
```csv
scenario_id,mode,encryption,integrity,dh_group,pfs,ike_version,ip_version,traffic_type,pcap_path
S01,tunnel,AES-256-GCM,AEAD,14,true,IKEv2,IPv4,web,data/pcaps/S01_tunnel_aes256gcm_dh14_pfson_ipv4_web.pcap
S02,transport,AES-128-CBC,HMAC-SHA256,2,false,IKEv2,IPv4,email,data/pcaps/S02_transport_aes128cbc_dh2_pfsoff_ipv4_email.pcap
```

### 8.2 Inspect PCAP with Scapy
```bash
python -c "from scapy.all import rdpcap, ESP, UDP; pkts = rdpcap('data/pcaps/S01_tunnel_aes256gcm_dh14_pfson_ipv4_web.pcap'); print('Total:', len(pkts), 'IKE:', len([p for p in pkts if UDP in p]), 'ESP:', len([p for p in pkts if ESP in p or p.haslayer('ESP')]))"
```

### 8.3 Inspect PCAP with Wireshark / TShark
```bash
tshark -r data/pcaps/S01_tunnel_aes256gcm_dh14_pfson_ipv4_web.pcap -c 10
```

---

## 9. Troubleshooting & Tips

1. **Docker XFRM/Kernel Error:**
   - If `swanctl --initiate` returns `installing connection failed`, ensure the containers are running with `privileged: true` and `cap_add: [NET_ADMIN, NET_RAW, SYS_MODULE]`.
   - If using cloud Linux containers without root kernel access, run `python lab/generate_sample_pcaps.py` as an immediate working fallback.

2. **VICI Socket Timeout:**
   - Verify `charon` is running inside container: `docker exec node-a pgrep -l charon`.
   - If not running, start it: `docker exec node-a /usr/lib/ipsec/charon &`.

3. **Cleaning Up Lab Resources:**
   - To stop and remove containers:
     ```bash
     docker compose -f lab/docker-compose.yml down -v
     ```
