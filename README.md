# AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
### SIH26160 — 1-Day Working Prototype Build

This repository contains the complete implementation of an AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework.

---

## Architecture & Workstream Status

- **[Workstream A: Network & VPN Testbed Lab](file:///D:/ENGINEERING%20PROJECTS/IPsec%20VPN/run.md)** (Phases 0–3) — **COMPLETE**
  - Real strongSwan VPN dual-node Docker lab (`node-a` and `node-b`)
  - 14-scenario configuration matrix covering Tunnel/Transport, AES-GCM, ChaCha20-Poly1305, 3DES, DH groups (1, 2, 5, 14, 19, 20, 31), PFS on/off, IKEv1/IKEv2, IPv4/IPv6
  - 6 realistic traffic generators (Web, Email, ICMP, VoIP, Video, Chat)
  - Automated scenario switching & capture scripts (`run_scenario.sh`, `run_all.sh`, `run_scenario.ps1`, `run_all.ps1`)
  - Standalone dataset generator (`lab/generate_sample_pcaps.py`)
  - Initialized labeled dataset in `data/pcaps/` and `data/labels.csv`
- **Workstream B: AI/ML & Parsers** (Phases 4–5) — Ready for integration
- **Workstream C: Assessment Engine, Streamlit Dashboard & Reports** (Phases 6–9) — Ready for integration

---

## Quick Start Guide

Refer to **[`run.md`](file:///D:/ENGINEERING%20PROJECTS/IPsec%20VPN/run.md)** for full instructions on running the lab and testing Workstream A.

### 1. Install Dependencies
```bash
python -m pip install -r requirements.txt
```

### 2. Generate / Verify Dataset
```bash
python lab/generate_sample_pcaps.py
```

### 3. Launch Docker Lab (Optional / Real StrongSwan)
```bash
docker compose -f lab/docker-compose.yml up -d --build
bash lab/verify_lab.sh
```

---

## References & Compliance
- [Implementation Specification](file:///D:/ENGINEERING%20PROJECTS/IPsec%20VPN/implementation.md)
- NIST SP 800-77 Rev. 1 (*Guide to IPsec VPNs*)
- RFC 8247 (*Cryptographic Algorithm Implementation Requirements and Key Management Guidelines for IKEv2*)
- RFC 7296 (*Internet Key Exchange Protocol Version 2*)
- RFC 4303 (*IP Encapsulating Security Payload*)
