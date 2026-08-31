# IMPLEMENTATION.md
## AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework
### SIH26160 — 1-Day Working Prototype Build Spec (Team of 3 + AI Coding Agents)

> **Read this whole file before writing any code.** This version uses a
> **real IPsec VPN lab** (real strongSwan tunnels, real negotiated crypto,
> real captured packets) instead of synthetically crafted packets. It is
> split into 3 parallel workstreams so a team of 3 people (each optionally
> paired with their own AI coding agent) can build simultaneously instead of
> waiting on each other, plus a shared integration pass at the end.

---

## 1. Scope Decisions (read first)

**What "real" means here:** two Linux nodes will run actual strongSwan
(the same open-source IPsec software used in real enterprise deployments),
actually negotiate IKE, actually establish ESP-protected tunnels under many
different configurations, and actually carry traffic that gets genuinely
encrypted. We capture that real traffic with `tcpdump`. Nothing about the
protocol negotiation or encryption is faked.

The one place we simplify is **application content**: instead of installing
a full VoIP softphone, a Zoom client, and a WhatsApp client in a day, we use
small scripts that generate traffic with the *same size/timing pattern* as
real VoIP, video, chat, etc. (e.g., a script sending 160-byte UDP packets
every 20ms mimics real VoIP/RTP traffic at the network level). This is
honestly disclosed in the report. Web, email, and ICMP traffic are generated
using real, standard tools (curl, a real SMTP exchange, real `ping`) so those
are fully genuine end-to-end.

| Full PS Requirement | Day-1 Real-Lab Approach |
|---|---|
| a) VPN Testbed Generation (Tunnel/Transport, AES-128/256/GCM/CBC+HMAC, DH groups, PFS on/off, IPv4/IPv6) | **Two Docker containers (or two lightweight Linux VMs) each running real strongSwan**, with an automation script that rewrites the strongSwan config and re-establishes the tunnel for each of ~10-14 required configuration combinations. |
| b) Traffic Capture | `tcpdump` runs on the link between the two real nodes for every scenario, capturing real IKE negotiation and real ESP packets — saved as `.pcap` files, exactly like a real analyst would collect them. |
| c) AI-Based Protocol Identification | Deterministic parser (Scapy/pyshark) extracts every field genuinely visible on the wire from the real captures (IKE version, proposals, DH group, transform IDs, SPI). A trained ML classifier (scikit-learn RandomForest) predicts the **traffic type inside the encrypted ESP payload** from packet-size/timing statistics — the genuine AI component, since real ESP payload is genuinely encrypted and unreadable. |
| d) Security Assessment | Rule-based scoring engine mapping the real negotiated parameters to a weighted score against a best-practice table (NIST SP 800-77 / RFC 8247). |
| e) Reporting | Auto-generated Executive + Technical PDF reports, plus the live dashboard. |
| Interactive Dashboard | Streamlit app. |
| Dataset for training/testing | The real captured `.pcap` files + a `labels.csv` recording exactly which config was active during each capture (we know this because we configured it — same principle as how any labeled network-traffic dataset is built). |
| Demonstration video | Recorded after the build — screen capture of a real tunnel negotiating live plus the dashboard analyzing it. |

**Explicitly out of scope for Day 1** (state this openly in the report/demo):
AH packets (optional in the PS — attempt only if ahead of schedule), a
multi-site full enterprise topology, real third-party app traffic
(actual WhatsApp/Zoom binaries), production hardening of the tool itself.

---

## 2. Tech Stack

| Layer | Technology | Why |
|---|---|---|
| **VPN engine (the real part)** | **strongSwan** (open-source IPsec/IKE implementation) | Industry-standard, well documented, supports every cipher/mode/DH-group combination the PS asks for via config files. |
| **Lab hosts** | **Docker containers with `--cap-add=NET_ADMIN --privileged`** on a Linux host (native Linux, WSL2, or a cloud Linux VM) — **fallback: two lightweight Ubuntu VMs** (VirtualBox/Multipass) if Docker's kernel doesn't expose IPsec (XFRM) support | Containers are fastest to spin up and automate; VMs are the safe fallback since they always have a full real kernel. |
| **Traffic capture** | `tcpdump` (built into the lab nodes) | Standard, real packet capture — same tool a real analyst uses. |
| **Traffic generation** | `curl` + `python -m http.server` (web), real SMTP exchange via `python smtpd`/`aiosmtplib` (email), real `ping` (ICMP), small Python/Scapy scripts sending UDP at VoIP/video-like size & timing (voip, video, chat) | Keeps the *tunnel and crypto* 100% real; only mimics application content where installing real apps isn't feasible in a day. |
| **Automation/orchestration** | Bash + Python scripts, `docker-compose`, strongSwan's `swanctl`/`ipsec` CLI | Lets one script flip through ~10-14 configurations automatically instead of manual re-setup each time. |
| **Packet parsing** | `scapy` (primary), `pyshark` (optional cross-check) | Reads the real .pcap files and extracts IKE/ESP fields. |
| **Machine learning** | `scikit-learn` (RandomForestClassifier), `pandas`, `numpy` | Trains the traffic-type classifier on packet statistics. |
| **Dashboard** | `streamlit`, `plotly` | Fastest realistic path to a polished interactive UI. |
| **Report generation** | `reportlab` | Executive + Technical PDF reports. |
| **Storage** | Flat files (`data/`, `models/`, `reports/`) | No DB needed for a one-day prototype. |

Install (on each lab node / dev machine as relevant):
```bash
# On the two lab nodes (containers or VMs):
apt-get update && apt-get install -y strongswan strongswan-swanctl tcpdump curl iproute2 python3

# On the analysis/dashboard machine:
pip install scapy pyshark scikit-learn pandas numpy streamlit plotly reportlab joblib --break-system-packages
```

**Important pre-check (do this before committing to Docker):** run
`lsmod | grep -E "esp4|ah4|xfrm"` and `modprobe esp4` on your Linux host.
If kernel IPsec modules aren't available (common on some managed/cloud
sandboxes and on Docker Desktop for Mac/Windows without a real Linux kernel
underneath), switch immediately to the two-VM fallback — don't lose hours
debugging container kernel limitations.

---

## 3. Team Split & Parallel Work Plan (3 people)

Building this sequentially (lab → parser → AI → dashboard) wastes two of your
three people for most of the day. Instead, **split by layer** and work in
parallel, meeting up for two short sync points.

### Step 0 (all 3 people together, ~20 min): Agree on the contracts

Before splitting up, agree as a group on three things — write them down
somewhere shared (a doc, a Slack message, a comment in the repo):

1. **Pcap naming + `labels.csv` schema** — e.g. filename pattern
   `S01_tunnel_aes256gcm_dh14_pfson_ipv4_web.pcap`, and labels.csv columns:
   `scenario_id, mode, encryption, integrity, dh_group, pfs, ike_version, ip_version, traffic_type, pcap_path`.
2. **The pipeline's output shape** — the exact dict `analyze_pcap()` returns
   (see Phase 7). Everyone codes against this shape from minute one, even
   before it's real.
3. **Where files live** — the folder structure in §5, so paths don't need
   renegotiating later.

Once these three things are agreed, the group splits and works independently
until the sync points below.

### Workstream A — Network/VPN Lead (owns Phases 0-3)
**Builds:** the real strongSwan lab, the config-switching automation, real
traffic generation, and real packet capture.
**Deliverable everyone else needs:** a growing folder of real `.pcap` files
plus a matching `labels.csv`. **Ships the first 2-3 sample pcaps as early as
possible** (even before all ~12 scenarios are automated) so Workstream B
isn't blocked.

### Workstream B — AI/ML Lead (owns Phases 4-5)
**Builds:** the IKE/ESP parsers and the ML traffic-type classifier.
**Can start immediately** using the naming/schema contract from Step 0 —
write the parser against *any* real pcap (even one manually captured by
Workstream A in the first 30 minutes) and refine as more scenarios arrive.
**Deliverable everyone else needs:** a working `predict_traffic()` function
and parser functions with a stable output shape.

### Workstream C — App/Product Lead (owns Phases 6-9)
**Builds:** the security scoring rules, the pipeline glue, the Streamlit
dashboard, and the PDF reports.
**Can start immediately** by building the security rules engine (needs no
pcaps at all — it's a pure lookup-table function) and the dashboard UI
against **mock/fake data matching the agreed output shape**. Swaps in the
real pipeline once A and B deliver their pieces.

### Sync Point 1 (~midday): Integration check-in
Each person shows their piece working standalone:
- A: "here's a real tunnel negotiating live + 5 captured pcaps so far"
- B: "here's the parser reading one of A's real pcaps correctly + a first classifier version"
- C: "here's the dashboard running end-to-end against fake data"
Fix any contract mismatches now, while it's cheap.

### Sync Point 2 (final 1-2 hrs, all 3 together): Final integration
Wire B's real parser/classifier and A's real pcaps into C's dashboard and
pipeline, replacing the mock data. Run the full Definition of Done checklist
(§9) together. Record the demo video together.

| Person | Owns | Needs from others | Delivers to others |
|---|---|---|---|
| A — Network/VPN | Phases 0-3 | Nothing to start | Real pcaps + labels.csv |
| B — AI/ML | Phases 4-5 | A's first pcaps (ASAP, not all of them) | Parser functions + `predict_traffic()` |
| C — App/Product | Phases 6-9 | Agreed output-dict shape only, to start | Working dashboard + reports, wired to A+B at the end |

---

## 4. Phased Execution Protocol (applies within each workstream)

Whether a human or an AI coding agent is doing the work for a given
workstream, follow this rule for every phase listed in §6:

> **Stop after finishing each phase. Summarize in plain language what was
> just built, list the files created/changed, mention anything that didn't
> work as expected, and explicitly ask "Phase X complete — should I continue
> to Phase X+1?" Do not start the next phase without an explicit go-ahead.**

This applies per-workstream — Workstream A's agent checkpoints independently
from Workstream B's and C's. Don't batch phases together even if they seem
quick; if something partially fails (e.g., a strongSwan config won't
negotiate), stop and report rather than pushing forward.

---

## 5. Project Structure

```
ipsec-analyzer/
├── implementation.md
├── requirements.txt
├── README.md
├── lab/
│   ├── docker-compose.yml             # defines node-a / node-b containers
│   ├── configs/
│   │   ├── S01_tunnel_aes256gcm_dh14_pfson.conf   # one strongSwan config per scenario
│   │   ├── S02_transport_aes128cbc_dh2_pfsoff.conf
│   │   └── ...
│   ├── run_scenario.sh                # brings tunnel up with a given config, verifies it negotiated
│   └── traffic/
│       ├── gen_web.sh                 # curl-based web traffic
│       ├── gen_email.py               # real SMTP exchange
│       ├── gen_icmp.sh                # ping
│       ├── gen_voip.py                # scripted UDP, VoIP-like size/timing
│       ├── gen_video.py               # scripted UDP, video-like size/timing
│       └── gen_chat.py                # scripted small bursts
├── data/
│   ├── pcaps/                         # REAL captured pcaps land here
│   └── labels.csv                     # ground truth per pcap (what config/traffic was active)
├── src/
│   ├── parser/
│   │   ├── ike_parser.py
│   │   ├── esp_parser.py
│   │   └── feature_extractor.py
│   ├── ml/
│   │   ├── train_traffic_classifier.py
│   │   └── predict.py
│   ├── assessment/
│   │   ├── security_rules.py
│   │   └── risk_engine.py
│   ├── reporting/
│   │   ├── executive_report.py
│   │   └── technical_report.py
│   └── pipeline.py
├── models/
│   └── traffic_rf_model.joblib
├── reports/
├── app.py
└── tests/
    └── test_pipeline_smoke.py
```

---

## 6. Phased Build Plan

### PHASE 0 — Environment Setup [Owner: A, but B & C also run the pip install part] (≈20-30 min)

**Goal:** Confirm the real lab is even possible on your host, and get every
machine's dependencies installed.

**What to build:**
- Run the kernel pre-check from §2 (`lsmod | grep -E "esp4|ah4|xfrm"`, `modprobe esp4`). Decide Docker vs VM fallback **now**, not after Phase 1 fails.
- Stand up two bare containers/VMs (`node-a`, `node-b`) on a shared network, install `strongswan strongswan-swanctl tcpdump curl` on both.
- B and C install the Python requirements from §2 on the analysis machine.

**How to verify it worked:**
- `docker exec node-a ipsec --version` (or the VM equivalent) prints a strongSwan version.
- `node-a` can `ping` `node-b` over the shared network (before any IPsec is configured).

**Ask to continue with:**
"Phase 0 complete — [Docker/VM] lab is up, strongSwan is installed on both nodes, and plain ping works between them. Ready to start Phase 1: bringing up the first real tunnel?"

---

### PHASE 1 — First Real Tunnel (proof it genuinely works) [Owner: A] (≈1.5 hrs)

**Goal:** Get **one** real IPsec tunnel fully negotiating between the two
nodes before automating anything — this proves the lab works end-to-end.

**What to build:**
- Write one strongSwan config (e.g. `S01_tunnel_aes256gcm_dh14_pfson.conf`) for IKEv2, tunnel mode, AES-256-GCM, DH group 14, PFS on.
- Load it on both nodes (`swanctl --load-all` or classic `ipsec.conf`/`ipsec.secrets` with a pre-shared key).
- Bring the tunnel up (`swanctl --initiate` / `ipsec up`) and confirm SA establishment (`swanctl --list-sas` / `ipsec statusall`).
- Run `tcpdump -i eth0 -w data/pcaps/S01_manual_test.pcap` on node-a while sending a `ping` from node-a to node-b, confirm the ping packets appear as ESP (not plaintext ICMP) in the capture.

**How to verify it worked:**
- `swanctl --list-sas` shows an ESTABLISHED SA with the expected cipher.
- Opening the capture in Wireshark/`tshark -r` shows a UDP/500 IKE exchange followed by real ESP packets, not plaintext.

**Ask to continue with:**
"Phase 1 complete — a real IKEv2 tunnel (AES-256-GCM, DH14, PFS on) is negotiating successfully between the two nodes, and the ping traffic is confirmed encrypted in the capture. Ready to start Phase 2: automating this across all required configurations?"

---

### PHASE 2 — Config Matrix + Automated Scenario Switching [Owner: A] (≈2 hrs)

**Goal:** Turn the one manual tunnel from Phase 1 into an automated script
that cycles through every configuration the PS requires.

**What to build:**
- `lab/configs/` — one strongSwan config per scenario, covering: tunnel vs transport, AES-128 vs AES-256, GCM vs CBC+HMAC, DH groups {2, 14, 19}, PFS on/off, IKEv1 vs IKEv2, IPv4 and IPv6. Target **10-14 scenarios** (fewer than a synthetic approach would allow, since real negotiation takes longer to verify than crafting packets — better to have 10 solid real ones than 18 flaky ones).
- `lab/run_scenario.sh <config-name>`: loads the given config on both nodes, tears down any existing SA, brings the new tunnel up, polls `swanctl --list-sas` until ESTABLISHED (or times out and reports failure clearly), and returns success/failure.
- Loop this script over every config in `lab/configs/`, logging which scenarios negotiated successfully.

**How to verify it worked:**
- Running the loop end-to-end brings up and tears down at least 10 different real tunnels without manual intervention, logging a clear ✅/❌ per scenario.

**Ask to continue with:**
"Phase 2 complete — [N] of [M] scenarios negotiate automatically end-to-end (list any that failed and why). Ready to start Phase 3: generating and capturing real traffic through each tunnel?"

---

### PHASE 3 — Real Traffic Generation + Capture [Owner: A] (≈2 hrs)

**Goal:** For every scenario that negotiates successfully, generate real
traffic across the tunnel and capture it — this produces the actual labeled
dataset.

**What to build:**
- `lab/traffic/gen_web.sh`: `python -m http.server` on node-b, repeated `curl` requests from node-a.
- `lab/traffic/gen_email.py`: a minimal real SMTP client/server exchange (Python's built-in `smtpd`/`aiosmtplib` is fine) between the nodes.
- `lab/traffic/gen_icmp.sh`: real `ping` bursts.
- `lab/traffic/gen_voip.py`, `gen_video.py`, `gen_chat.py`: small Python/Scapy UDP senders using the size/timing values in the table below (real UDP packets, real encryption, application content is the honest simplification described in §1).

| Traffic type | Packet size | Interval | Real tool? |
|---|---|---|---|
| Web | Variable (real HTTP) | Real | fully real (curl) |
| Email | Variable (real SMTP) | Real | fully real |
| ICMP | ~64 bytes | ~1s | fully real (ping) |
| VoIP | ~160-200 bytes | ~20ms | Scripted UDP, real tunnel |
| Video | ~1200-1400 bytes | ~8-10ms | Scripted UDP, real tunnel |
| Chat | ~60-150 bytes | Bursty, irregular | Scripted UDP, real tunnel |

- Extend `run_scenario.sh` (or a new `run_all.sh`) to: bring up scenario → start `tcpdump -w data/pcaps/{scenario_id}_{traffic_type}.pcap` → run the matching traffic generator for ~30-60s → stop tcpdump → tear down tunnel → append a row to `data/labels.csv`.
- Run this across all successfully-negotiating scenarios × a rotating traffic type (don't need every scenario × every traffic type — aim for coverage of each crypto variation at least once, and each traffic type at least twice, to keep total runtime manageable).

**How to verify it worked:**
- `data/pcaps/` contains real captures with non-trivial file sizes; `tshark -r` on a couple of them shows real IKE + real ESP with the expected traffic-pattern signature.
- `data/labels.csv` has one accurate row per capture.

**Ask to continue with:**
"Phase 3 complete — captured [N] real labeled pcaps across [M] configurations and [K] traffic types. This is the dataset. Ready to hand off to Workstream B/C for parsing and analysis?"

---

### PHASE 4 — Parsers [Owner: B] (≈1.5 hrs)

**Goal:** Read a real pcap and pull out every field a real analyst (or our
AI/rules layers) needs.

**What to build:**
- `src/parser/ike_parser.py`: filter UDP 500/4500, extract IKE version, exchange type, SPIs, and decode the SA payload's proposed transforms into human labels using the lookup table in §7. Note real captures may include retransmissions/NAT-T markers — handle gracefully rather than assuming one clean exchange.
- `src/parser/esp_parser.py`: filter ESP (proto 50)/UDP 4500, extract SPI, sequence number (check monotonic increase → replay-protection indicator), packet sizes, inter-arrival times, direction.
- `src/parser/feature_extractor.py`: turn a parsed ESP flow into `[mean_pkt_size, std_pkt_size, mean_iat, std_iat, pkt_count, bidirectional_ratio, min_size, max_size]`.

**How to verify it worked:**
- Run against 2-3 of Workstream A's real pcaps; confirm the extracted encryption/DH/mode fields match what was actually configured for that scenario (cross-check against `labels.csv`).

**Ask to continue with:**
"Phase 4 complete — the parser correctly extracts protocol/crypto fields and traffic statistics from real captures, verified against 3 known scenarios. Ready to start Phase 5: training the AI traffic classifier?"

---

### PHASE 5 — ML Traffic Classifier [Owner: B] (≈1.5 hrs)

**Goal:** Train the real AI component on real captured traffic statistics.

**What to build:**
- `src/ml/train_traffic_classifier.py`: run `feature_extractor` over every pcap in `data/pcaps/`, join with `labels.csv`'s `traffic_type` column, 80/20 train/test split, `RandomForestClassifier(n_estimators=200, max_depth=8)`, print a classification report, save with `joblib.dump` to `models/traffic_rf_model.joblib`.
- `src/ml/predict.py`: `predict_traffic(feature_vector) -> (label, confidence)`.

**How to verify it worked:**
- Training completes and prints a classification report with reasonable accuracy (expect more real-world noise/confusion than a synthetic dataset would show — that's fine and worth noting honestly in the technical report).

**Ask to continue with:**
"Phase 5 complete — trained the classifier on real captured traffic, [X]% test accuracy. Ready to hand the parser + classifier to Workstream C for pipeline integration?"

---

### PHASE 6 — Security Assessment Engine [Owner: C] (≈1.5 hrs — can start Day 1 morning, needs no pcaps)

**Goal:** Turn parsed protocol/crypto fields into a security judgment.

**What to build:**
- `src/assessment/security_rules.py` — the scoring table from §7.
- `src/assessment/risk_engine.py` — weighted sum → 0-100 **Security Score**; **Risk Level** buckets (Critical <40, High 40-59, Medium 60-79, Low 80-100); **Threat Matrix** entries `{parameter, finding, severity, recommendation}`; attach the ML classifier's confidence as a separately-labeled **AI Confidence Score**.

**How to verify it worked:**
- Feed it two hand-written fake "parsed" dicts (one strong config, one weak) and confirm the strong one scores meaningfully higher with an empty threat matrix, and the weak one produces specific findings.

**Ask to continue with:**
"Phase 6 complete — scoring engine correctly rates strong vs weak configs and produces a threat matrix with real recommendations. Ready to start Phase 7: pipeline glue?"

---

### PHASE 7 — Pipeline Orchestration [Owner: C] (≈45 min)

**Goal:** One function connecting parser → ML → scoring.

**What to build:**
```python
def analyze_pcap(path: str) -> dict:
    ike_info = parse_ike(path)
    esp_flows = parse_esp(path)
    features = [extract_features(f) for f in esp_flows]
    traffic_preds = [predict_traffic(f) for f in features]
    findings = evaluate_security(ike_info)
    risk = compute_risk(findings)
    return {
        "ike_info": ike_info,
        # Flattened metadata dict for direct dashboard consumption.
        # All nine fields below must be populated (or set to "Unknown" if the
        # parser cannot determine the value from the capture).
        "ike_metadata": {
            "ike_version":      ike_info.get("ike_version", "Unknown"),   # e.g. "IKEv2"
            "ip_version":       ike_info.get("ip_version",  "Unknown"),   # e.g. "IPv4" / "IPv6"
            "mode":             ike_info.get("mode",        "Unknown"),   # "Tunnel" / "Transport"
            "encryption":       ike_info.get("encryption",  "Unknown"),   # e.g. "AES-256-GCM"
            "integrity":        ike_info.get("integrity",   "Unknown"),   # e.g. "AEAD" / "HMAC-SHA256"
            "dh_group":         ike_info.get("dh_group",    "Unknown"),   # e.g. "14 (MODP-2048)"
            "pfs":              ike_info.get("pfs",         "Unknown"),   # "Enabled" / "Disabled"
            "key_lifetime":     ike_info.get("key_lifetime","Unknown"),   # e.g. "3600s"
            "replay_protection":ike_info.get("replay_protection","Unknown"), # "Enabled" / "Disabled"
        },
        "traffic_predictions": traffic_preds,
        "findings": findings,
        "risk": risk,
        "generated_at": datetime.utcnow().isoformat(),
    }
```
Until B's real parser/classifier are ready, C can stub `parse_ike`/`parse_esp`/`predict_traffic` with fake data matching the agreed shape from §3 Step 0, and swap in the real functions at Sync Point 2.

**How to verify it worked:**
- Call `analyze_pcap()` against a real pcap once B's modules are wired in; confirm every key is populated sensibly, and in particular that `result["ike_metadata"]` contains all nine fields with non-`None` values.

**Ask to continue with:**
"Phase 7 complete — pipeline function works [against mock data / against a real pcap]. Ready to start Phase 8: the dashboard?"

---

### PHASE 8 — Streamlit Dashboard [Owner: C] (≈2 hrs — start against mock data, don't wait for A/B)

**Goal:** The visual interface the demo will actually show.

**What to build:**
`app.py`, single page:
1. Sidebar: pcap uploader or dropdown of bundled real scenarios; "Analyze" button.
2. Header cards: Security Score, Risk Level badge, AI Confidence badge.
3. **IPsec Protocol Metadata section** — a dedicated, clearly-labelled panel rendered from `analyze_pcap()["ike_metadata"]` that displays all nine of the following fields (each with a label and its parsed value; show "Unknown" if the field was not determinable from the capture):

   | Field               | Source key in `ike_metadata`  | Example value          |
   |---------------------|-------------------------------|------------------------|
   | IKE Version         | `ike_version`                 | IKEv2                  |
   | IP Version          | `ip_version`                  | IPv4 / IPv6            |
   | IPsec Mode          | `mode`                        | Tunnel / Transport     |
   | Encryption          | `encryption`                  | AES-256-GCM            |
   | Integrity           | `integrity`                   | AEAD / HMAC-SHA256     |
   | DH Group            | `dh_group`                    | 14 (MODP-2048)         |
   | PFS                 | `pfs`                         | Enabled / Disabled     |
   | Key Lifetime        | `key_lifetime`                | 3600s                  |
   | Replay Protection   | `replay_protection`           | Enabled / Disabled     |

4. Protocol Identification panel: IKE version, mode, encryption, integrity, DH group, PFS, key lifetime, each with a status icon (this panel may share or reference data from the IPsec Protocol Metadata section above).
5. Traffic Analysis panel: predicted traffic type + confidence, Plotly packet-size chart.
6. Threat Matrix table, severity-sorted.
7. Download buttons for both PDF reports.
8. (Stretch, only if ahead) batch comparison across all captured scenarios.

**How to verify it worked:**
- `streamlit run app.py` launches; analyzing a scenario populates every panel with real (or, pre-integration, mock) data.
- The IPsec Protocol Metadata section is visible and all nine field rows are rendered with non-empty values for at least three real scenarios from `data/pcaps/`.

**Ask to continue with:**
"Phase 8 complete — dashboard is live and functional. Ready to start Phase 9: reports and final integration?"

---

### PHASE 9 — Reports + Final Integration [Owner: C, joint at Sync Point 2] (≈1.5-2 hrs)

**Goal:** Produce the PDF deliverables, then merge all three workstreams
into one working system.

**What to build:**
- `src/reporting/executive_report.py`: 1-page plain-English PDF.
- `src/reporting/technical_report.py`: full parameter dump, rule-by-rule justification, threat matrix, ML feature vector + confidence, and an honest methodology section (real lab, scripted app-layer content for VoIP/video/chat — see §1).
- Swap C's mock pipeline functions for B's real parser/classifier and A's real pcaps.
- `tests/test_pipeline_smoke.py`: run `analyze_pcap` on a real bundled pcap, assert expected keys and score in [0,100].
- Write the real `README.md` (setup, how to reproduce the lab, honest limitations — see §10).
- Final cleanup: confirm the whole thing runs from a clean checkout.

**How to verify it worked:**
- Both PDFs generate correctly for 3+ real scenarios; smoke test passes; a fresh install + `streamlit run app.py` works with no manual fixes.

**Ask to continue with:**
"Phase 9 complete — full integration done, reports generate correctly, smoke test passes. This is the full prototype — everything in the Definition of Done (§9) should now be checkable. Anything you'd like adjusted before we call this done?"

---

## 7. Reference Tables the Agent Should Hardcode

**IKEv2 Encryption Transform IDs (subset, RFC 8247/IANA)**
```
1  = DES-IV64 (weak)      3 = 3DES (weak)          12 = AES-CBC
13 = AES-CTR              18 = AES-CCM-8           19 = AES-CCM-12
20 = AES-GCM-16 (preferred, AEAD)   28 = ChaCha20-Poly1305 (preferred, AEAD)
```
**IKEv2 DH Group Numbers**
```
1 = 768-bit MODP (weak)     2 = 1024-bit MODP (weak)
5 = 1536-bit MODP (medium)  14 = 2048-bit MODP (good)
19 = 256-bit ECP (strong)   20 = 384-bit ECP (strong)   31 = Curve25519 (strong)
```
**Integrity/PRF**
```
HMAC-MD5-96 (weak) < HMAC-SHA1-96 (medium) < HMAC-SHA2-256-128 (strong) < HMAC-SHA2-512-256 (strong)
```
**Security Scoring Table**

| Parameter | Strong (10 pts) | Medium (5 pts) | Weak (0 pts) |
|---|---|---|---|
| Encryption | AES-256-GCM | AES-256-CBC / AES-128-GCM | AES-128-CBC, 3DES, DES, NULL |
| Integrity/Auth | Built into AEAD, or HMAC-SHA-256/384/512 | HMAC-SHA1 | MD5, NULL |
| DH Group | 19, 20, 21, 31 (ECC) / 14+ (MODP ≥2048-bit) | 5 (1536-bit) | 1, 2 (768/1024-bit) |
| PFS | Enabled | — | Disabled |
| IKE Version | IKEv2 | — | IKEv1 |
| Key Lifetime | ≤ 8 hours / 100MB | 8-24 hrs | > 24 hrs or unlimited |
| Replay Protection | Enabled (sequence check on) | — | Disabled |
| Mode | Tunnel (site-to-site/remote access) | Transport (context-dependent) | — |

---

## 8. Time Budget Summary

Because the three workstreams run in parallel, wall-clock time is much
shorter than the sum of all phases.

| Phase | Owner | Hours (person-time) |
|---|---|---|
| 0. Environment setup | A (+B, C install deps) | 0.5 |
| 1. First real tunnel | A | 1.5 |
| 2. Config matrix + automated switching | A | 2.0 |
| 3. Real traffic generation + capture | A | 2.0 |
| 4. Parsers | B | 1.5 |
| 5. ML classifier | B | 1.5 |
| 6. Security assessment engine | C | 1.5 |
| 7. Pipeline orchestration | C | 0.75 |
| 8. Streamlit dashboard | C | 2.0 |
| 9. Reports + final integration | C, then all 3 | 1.5-2.0 |
| **Wall-clock estimate with 3 people in parallel** | | **~8-9 hrs** (A's track is the long pole; B and C should be ready and waiting at Sync Point 2) |

If Workstream A falls behind (real lab automation is the highest-risk part —
budget contingency time there first), trim scenario count in Phase 2/3
rather than cutting corners on Phase 1's "does this genuinely work" proof.

---

## 9. Definition of Done for the Demo

- [ ] A real strongSwan tunnel can be shown negotiating live during the demo (not just pre-recorded captures).
- [ ] At least 8-10 real captured scenarios exist in `data/pcaps/` with an accurate `labels.csv`.
- [ ] `streamlit run app.py` launches without errors.
- [ ] Dashboard shows: security score, risk badge, protocol ID table, traffic-type prediction + confidence, threat matrix.
- [ ] Both PDF reports generate and download correctly.
- [ ] README explains the lab setup, how to reproduce it, and honestly lists what's fully real vs. scripted (app-layer content for VoIP/video/chat) as documented in §1/§10.
- [ ] One clean run recorded as the demo video after everything above passes.

---

## 10. Honesty / Judge-Facing Notes (keep these in README and technical report)

State plainly, in the delivered documentation:
- The IPsec tunnels, IKE negotiation, and ESP encryption in this prototype
  are **fully real**, produced by an actual strongSwan deployment across two
  Linux nodes — not simulated or hand-crafted packets.
- Web, email, and ICMP traffic are generated with real standard tools
  (curl, a real SMTP exchange, real ping). VoIP, video, and chat traffic use
  small scripts that reproduce the same packet size/timing signature as the
  real protocols, since installing full third-party VoIP/video/chat clients
  wasn't feasible in a one-day build — this is disclosed, not hidden.
- Traffic-type-inside-ESP prediction is based on **metadata/statistical
  traffic analysis** (packet size, timing, direction) since real ESP payload
  is genuinely encrypted and unreadable — this is standard, real-world
  traffic-fingerprinting methodology, not a claim of decrypting payload.
- All crypto-strength rules are traceable to public references (NIST SP
  800-77 Rev.1, RFC 8247) — cite these in the technical report's methodology
  section rather than presenting the scoring table as novel research.
