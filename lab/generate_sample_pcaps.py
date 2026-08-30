#!/usr/bin/env python3
"""
generate_sample_pcaps.py — High-Fidelity Dataset Generator for IPsec PCAPs
Part of Workstream A (AI-Powered IPsec Protocol Analyzer)

Generates valid .pcap files matching the 14 test scenarios and 6 traffic types
with accurate IKE proposals (transforms, DH groups, SPIs) and ESP packet flows
(packet sizes, inter-arrival times, sequence numbers).
Also initializes / updates data/labels.csv.
"""

import os
import sys
import time
import random
import struct

try:
    from scapy.all import IP, IPv6, UDP, Raw, wrpcap
    from scapy.layers.ipsec import ESP
    from scapy.layers.isakmp import ISAKMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(WORKSPACE_DIR, "data")
PCAPS_DIR = os.path.join(DATA_DIR, "pcaps")
LABELS_FILE = os.path.join(DATA_DIR, "labels.csv")

# Scenario definitions matching implementation.md & lab/configs
SCENARIOS = [
    {
        "id": "S01",
        "name": "S01_tunnel_aes256gcm_dh14_pfson_v4",
        "mode": "tunnel",
        "encryption": "AES-256-GCM",
        "enc_type_id": 20, # AES-GCM-16
        "key_len": 256,
        "integrity": "AEAD",
        "dh_group": 14, # MODP-2048
        "pfs": "true",
        "ike_version": "IKEv2",
        "ip_version": "IPv4",
        "traffic_type": "web",
    },
    {
        "id": "S02",
        "name": "S02_transport_aes128cbc_sha256_dh2_pfsoff_v4",
        "mode": "transport",
        "encryption": "AES-128-CBC",
        "enc_type_id": 12, # AES-CBC
        "key_len": 128,
        "integrity": "HMAC-SHA256",
        "integ_type_id": 12,
        "dh_group": 2, # MODP-1024
        "pfs": "false",
        "ike_version": "IKEv2",
        "ip_version": "IPv4",
        "traffic_type": "email",
    },
    {
        "id": "S03",
        "name": "S03_tunnel_aes128gcm_dh19_pfson_v4",
        "mode": "tunnel",
        "encryption": "AES-128-GCM",
        "enc_type_id": 20,
        "key_len": 128,
        "integrity": "AEAD",
        "dh_group": 19, # 256-bit ECP
        "pfs": "true",
        "ike_version": "IKEv2",
        "ip_version": "IPv4",
        "traffic_type": "voip",
    },
    {
        "id": "S04",
        "name": "S04_tunnel_aes256cbc_sha512_dh14_pfson_v4",
        "mode": "tunnel",
        "encryption": "AES-256-CBC",
        "enc_type_id": 12,
        "key_len": 256,
        "integrity": "HMAC-SHA512",
        "integ_type_id": 14,
        "dh_group": 14,
        "pfs": "true",
        "ike_version": "IKEv2",
        "ip_version": "IPv4",
        "traffic_type": "video",
    },
    {
        "id": "S05",
        "name": "S05_transport_aes256gcm_dh19_pfson_v4",
        "mode": "transport",
        "encryption": "AES-256-GCM",
        "enc_type_id": 20,
        "key_len": 256,
        "integrity": "AEAD",
        "dh_group": 19,
        "pfs": "true",
        "ike_version": "IKEv2",
        "ip_version": "IPv4",
        "traffic_type": "chat",
    },
    {
        "id": "S06",
        "name": "S06_tunnel_3des_sha1_dh2_pfsoff_v4",
        "mode": "tunnel",
        "encryption": "3DES-CBC",
        "enc_type_id": 3,
        "key_len": 192,
        "integrity": "HMAC-SHA1",
        "integ_type_id": 2,
        "dh_group": 2,
        "pfs": "false",
        "ike_version": "IKEv2",
        "ip_version": "IPv4",
        "traffic_type": "icmp",
    },
    {
        "id": "S07",
        "name": "S07_tunnel_aes128cbc_md5_dh1_pfsoff_v4",
        "mode": "tunnel",
        "encryption": "AES-128-CBC",
        "enc_type_id": 12,
        "key_len": 128,
        "integrity": "HMAC-MD5",
        "integ_type_id": 1,
        "dh_group": 1, # 768-bit MODP
        "pfs": "false",
        "ike_version": "IKEv1",
        "ip_version": "IPv4",
        "traffic_type": "web",
    },
    {
        "id": "S08",
        "name": "S08_tunnel_aes256gcm_dh20_pfson_v4",
        "mode": "tunnel",
        "encryption": "AES-256-GCM",
        "enc_type_id": 20,
        "key_len": 256,
        "integrity": "AEAD",
        "dh_group": 20, # 384-bit ECP
        "pfs": "true",
        "ike_version": "IKEv2",
        "ip_version": "IPv4",
        "traffic_type": "video",
    },
    {
        "id": "S09",
        "name": "S09_transport_aes128gcm_dh14_pfsoff_v4",
        "mode": "transport",
        "encryption": "AES-128-GCM",
        "enc_type_id": 20,
        "key_len": 128,
        "integrity": "AEAD",
        "dh_group": 14,
        "pfs": "false",
        "ike_version": "IKEv2",
        "ip_version": "IPv4",
        "traffic_type": "email",
    },
    {
        "id": "S10",
        "name": "S10_tunnel_aes256cbc_sha256_dh5_pfsoff_v4",
        "mode": "tunnel",
        "encryption": "AES-256-CBC",
        "enc_type_id": 12,
        "key_len": 256,
        "integrity": "HMAC-SHA256",
        "integ_type_id": 12,
        "dh_group": 5, # 1536-bit MODP
        "pfs": "false",
        "ike_version": "IKEv2",
        "ip_version": "IPv4",
        "traffic_type": "voip",
    },
    {
        "id": "S11",
        "name": "S11_tunnel_aes256gcm_dh14_pfson_v6",
        "mode": "tunnel",
        "encryption": "AES-256-GCM",
        "enc_type_id": 20,
        "key_len": 256,
        "integrity": "AEAD",
        "dh_group": 14,
        "pfs": "true",
        "ike_version": "IKEv2",
        "ip_version": "IPv6",
        "traffic_type": "chat",
    },
    {
        "id": "S12",
        "name": "S12_transport_aes256gcm_dh19_pfson_v6",
        "mode": "transport",
        "encryption": "AES-256-GCM",
        "enc_type_id": 20,
        "key_len": 256,
        "integrity": "AEAD",
        "dh_group": 19,
        "pfs": "true",
        "ike_version": "IKEv2",
        "ip_version": "IPv6",
        "traffic_type": "icmp",
    },
    {
        "id": "S13",
        "name": "S13_tunnel_ikev1_aes256cbc_sha1_dh14_pfson_v4",
        "mode": "tunnel",
        "encryption": "AES-256-CBC",
        "enc_type_id": 12,
        "key_len": 256,
        "integrity": "HMAC-SHA1",
        "integ_type_id": 2,
        "dh_group": 14,
        "pfs": "true",
        "ike_version": "IKEv1",
        "ip_version": "IPv4",
        "traffic_type": "web",
    },
    {
        "id": "S14",
        "name": "S14_tunnel_chacha20poly1305_curve25519_pfson_v4",
        "mode": "tunnel",
        "encryption": "CHACHA20-POLY1305",
        "enc_type_id": 28,
        "key_len": 256,
        "integrity": "AEAD",
        "dh_group": 31, # Curve25519
        "pfs": "true",
        "ike_version": "IKEv2",
        "ip_version": "IPv4",
        "traffic_type": "voip",
    },
]

def build_ike_init_payload(scenario, initiator_spi, responder_spi):
    """Constructs a valid IKE_SA_INIT payload with specified transforms and DH group."""
    is_v2 = (scenario["ike_version"] == "IKEv2")
    version_byte = 0x20 if is_v2 else 0x10
    exchange_type = 34 if is_v2 else 2 # IKE_SA_INIT (34) or Identity Protection / Main Mode (2)
    
    # 28-byte IKE Header
    # init_spi (8B), resp_spi (8B), next_payload (1B), version (1B), exchange (1B), flags (1B), msg_id (4B), length (4B)
    flags = 0x08 # Initiator flag
    msg_id = 0
    
    # SA Proposal payload
    # Transform 1: Encryption
    enc_id = scenario["enc_type_id"]
    dh_id = scenario["dh_group"]
    
    # Build a structured binary SA proposal payload
    # Next payload: 33 (SA), 0 (None)
    # Type 1: Encryption (Transform type 1), Type 2: PRF (Transform type 2), Type 3: Integrity (Transform type 3), Type 4: DH (Transform type 4)
    transforms_bin = bytearray()
    
    # Transform: Encryption
    # Last/More (1B), Reserved (1B), Trans Length (2B), Trans Type (1B), Reserved (1B), Trans ID (2B), Attribute (Key length if applicable)
    if "key_len" in scenario and scenario["key_len"] in (128, 256):
        # Attribute: AF=1 (0x80), AttrType=14 (Key Length), Value=key_len
        attr = struct.pack("!HH", 0x800E, scenario["key_len"])
        transforms_bin += struct.pack("!BBHBBH", 3, 0, 8 + len(attr), 1, 0, enc_id) + attr
    else:
        transforms_bin += struct.pack("!BBHBBH", 3, 0, 8, 1, 0, enc_id)
        
    # Transform: PRF (SHA256 = 5 or SHA384 = 6)
    transforms_bin += struct.pack("!BBHBBH", 3, 0, 8, 2, 0, 5)
    
    # Transform: Integrity (if not pure AEAD)
    if scenario["integrity"] != "AEAD":
        integ_id = scenario.get("integ_type_id", 12)
        transforms_bin += struct.pack("!BBHBBH", 3, 0, 8, 3, 0, integ_id)
        
    # Transform: DH Group (Last transform = 0)
    transforms_bin += struct.pack("!BBHBBH", 0, 0, 8, 4, 0, dh_id)
    
    # Proposal Header: Last=0, Reserved=0, PropLen=8+len(transforms), PropNum=1, ProtoID=1 (IKE), SPISize=0, NumTransforms
    num_transforms = 4 if scenario["integrity"] != "AEAD" else 3
    prop_hdr = struct.pack("!BBHBBBB", 0, 0, 8 + len(transforms_bin), 1, 1, 0, num_transforms)
    sa_payload_content = prop_hdr + transforms_bin
    
    # SA Payload Header: NextPayload=34 (KE), Critical=0, Length=4+len
    sa_hdr = struct.pack("!BBH", 34, 0, 4 + len(sa_payload_content))
    
    # Key Exchange (KE) Payload: NextPayload=40 (Nonce), DH Group, Key Data
    ke_data = os.urandom(64) # Simulated DH Public Value
    ke_hdr = struct.pack("!BBHHH", 40, 0, 8 + len(ke_data), dh_id, 0)
    
    # Nonce (Ni) Payload: NextPayload=0, Nonce Data
    nonce_data = os.urandom(32)
    nonce_hdr = struct.pack("!BBH", 0, 0, 4 + len(nonce_data))
    
    body = sa_hdr + sa_payload_content + ke_hdr + ke_data + nonce_hdr + nonce_data
    total_len = 28 + len(body)
    
    ike_hdr = struct.pack("!QQBBBBII", initiator_spi, responder_spi, 33, version_byte, exchange_type, flags, msg_id, total_len)
    return ike_hdr + body

def generate_scenario_pcap(scenario, output_path):
    """Generates an authentic PCAP with IKE negotiation and ESP traffic flow."""
    packets = []
    
    is_v6 = (scenario["ip_version"] == "IPv6")
    src_ip = "172.28.0.10" if not is_v6 else "fd00:abcd:1234::10"
    dst_ip = "172.28.0.20" if not is_v6 else "fd00:abcd:1234::20"
    
    init_spi = random.getrandbits(64)
    resp_spi = random.getrandbits(64)
    esp_spi = random.randint(0x10000000, 0xFFFFFFFF)
    
    base_time = time.time() - 300.0 # 5 minutes ago
    curr_time = base_time
    
    # 1. IKE_SA_INIT Request (node-a -> node-b)
    ike_req_bytes = build_ike_init_payload(scenario, init_spi, 0)
    if not is_v6:
        pkt_ike1 = IP(src=src_ip, dst=dst_ip) / UDP(sport=500, dport=500) / Raw(load=ike_req_bytes)
    else:
        pkt_ike1 = IPv6(src=src_ip, dst=dst_ip) / UDP(sport=500, dport=500) / Raw(load=ike_req_bytes)
    pkt_ike1.time = curr_time
    packets.append(pkt_ike1)
    
    # 2. IKE_SA_INIT Response (node-b -> node-a)
    curr_time += 0.015
    ike_resp_bytes = build_ike_init_payload(scenario, init_spi, resp_spi)
    if not is_v6:
        pkt_ike2 = IP(src=dst_ip, dst=src_ip) / UDP(sport=500, dport=500) / Raw(load=ike_resp_bytes)
    else:
        pkt_ike2 = IPv6(src=dst_ip, dst=src_ip) / UDP(sport=500, dport=500) / Raw(load=ike_resp_bytes)
    pkt_ike2.time = curr_time
    packets.append(pkt_ike2)
    
    # 3. IKE_AUTH Request (Encrypted IKE payload)
    curr_time += 0.020
    ike_auth_req = os.urandom(220)
    if not is_v6:
        pkt_ike3 = IP(src=src_ip, dst=dst_ip) / UDP(sport=4500, dport=4500) / Raw(load=b"\x00\x00\x00\x00" + struct.pack("!QQBBBBII", init_spi, resp_spi, 46, 0x20, 35, 0x08, 1, 28 + len(ike_auth_req)) + ike_auth_req)
    else:
        pkt_ike3 = IPv6(src=src_ip, dst=dst_ip) / UDP(sport=4500, dport=4500) / Raw(load=b"\x00\x00\x00\x00" + struct.pack("!QQBBBBII", init_spi, resp_spi, 46, 0x20, 35, 0x08, 1, 28 + len(ike_auth_req)) + ike_auth_req)
    pkt_ike3.time = curr_time
    packets.append(pkt_ike3)
    
    # 4. IKE_AUTH Response
    curr_time += 0.025
    ike_auth_resp = os.urandom(180)
    if not is_v6:
        pkt_ike4 = IP(src=dst_ip, dst=src_ip) / UDP(sport=4500, dport=4500) / Raw(load=b"\x00\x00\x00\x00" + struct.pack("!QQBBBBII", init_spi, resp_spi, 46, 0x20, 35, 0x20, 1, 28 + len(ike_auth_resp)) + ike_auth_resp)
    else:
        pkt_ike4 = IPv6(src=dst_ip, dst=src_ip) / UDP(sport=4500, dport=4500) / Raw(load=b"\x00\x00\x00\x00" + struct.pack("!QQBBBBII", init_spi, resp_spi, 46, 0x20, 35, 0x20, 1, 28 + len(ike_auth_resp)) + ike_auth_resp)
    pkt_ike4.time = curr_time
    packets.append(pkt_ike4)
    
    # 5. ESP Traffic Generation matching application type
    traffic_type = scenario["traffic_type"]
    num_packets = 120
    seq_out = 1
    seq_in = 1
    
    curr_time += 0.1
    
    for i in range(num_packets):
        direction = 1 # A -> B
        if traffic_type == "web":
            # Web: Request (small) followed by bursts of responses (medium/large)
            if i % 8 == 0:
                direction = 1
                payload_len = random.randint(150, 350)
                iat = random.uniform(0.3, 0.8)
            else:
                direction = 2
                payload_len = random.choice([ random.randint(600, 1400), random.randint(1200, 1420) ])
                iat = random.uniform(0.005, 0.04)
        elif traffic_type == "email":
            # Email: Interactive command/response then MIME bursts
            if i < 20:
                direction = 1 if i % 2 == 0 else 2
                payload_len = random.randint(80, 180)
                iat = random.uniform(0.2, 0.5)
            else:
                direction = 1
                payload_len = random.randint(900, 1400)
                iat = random.uniform(0.01, 0.05)
        elif traffic_type == "icmp":
            # ICMP: Steady ~1s intervals, symmetric 64-512 byte pairs
            direction = 1 if i % 2 == 0 else 2
            payload_len = random.choice([84, 148, 532])
            iat = 0.005 if direction == 2 else random.uniform(0.5, 1.0)
        elif traffic_type == "voip":
            # VoIP: Strictly 160-200 bytes, ~20ms interval (+/- 1ms jitter)
            direction = 1 if i % 2 == 0 else 2
            payload_len = random.randint(160, 200)
            iat = random.uniform(0.019, 0.021)
        elif traffic_type == "video":
            # Video: Large MTU packets (1200-1400 bytes) at 8-10ms intervals with periodic frame clusters
            direction = 1
            payload_len = random.randint(1250, 1420)
            iat = random.uniform(0.007, 0.011)
        elif traffic_type == "chat":
            # Chat: Bursty small messages (60-150 bytes), long pauses
            direction = 1 if random.random() > 0.5 else 2
            payload_len = random.randint(60, 150)
            if i % 6 == 0:
                iat = random.uniform(2.0, 4.0) # Pause between typing
            else:
                iat = random.uniform(0.1, 0.3) # Fast typing burst
        else:
            payload_len = 250
            iat = 0.05
            
        curr_time += iat
        
        # Build ESP packet
        if direction == 1:
            p_src, p_dst = src_ip, dst_ip
            seq_num = seq_out
            seq_out += 1
        else:
            p_src, p_dst = dst_ip, src_ip
            seq_num = seq_in
            seq_in += 1
            
        esp_payload = os.urandom(payload_len)
        
        # In Scapy, ESP layer takes spi, seq, data
        esp_pkt = ESP(spi=esp_spi, seq=seq_num, data=esp_payload)
        
        if not is_v6:
            full_pkt = IP(src=p_src, dst=p_dst, proto=50) / esp_pkt
        else:
            full_pkt = IPv6(src=p_src, dst=p_dst, nh=50) / esp_pkt
            
        full_pkt.time = curr_time
        packets.append(full_pkt)
        
    wrpcap(output_path, packets)
    return len(packets)

def main():
    if not SCAPY_AVAILABLE:
        print("[-] Error: Scapy is required to generate PCAPs. Run: pip install scapy")
        sys.exit(1)
        
    os.makedirs(PCAPS_DIR, exist_ok=True)
    
    print(f"==================================================================")
    print(f"[+] Generating High-Fidelity Dataset across {len(SCENARIOS)} IPsec Scenarios")
    print(f"[+] Destination Directory: {PCAPS_DIR}")
    print(f"==================================================================")
    
    labels_rows = []
    
    for sc in SCENARIOS:
        s_id = sc["id"]
        mode = sc["mode"]
        enc_tag = sc["encryption"].lower().replace("-", "").replace("_", "")
        dh = sc["dh_group"]
        pfs_tag = "pfson" if sc["pfs"] == "true" else "pfsoff"
        ip_tag = sc["ip_version"].lower()
        traffic = sc["traffic_type"]
        
        pcap_filename = f"{s_id}_{mode}_{enc_tag}_dh{dh}_{pfs_tag}_{ip_tag}_{traffic}.pcap"
        pcap_full_path = os.path.join(PCAPS_DIR, pcap_filename)
        rel_pcap_path = f"data/pcaps/{pcap_filename}"
        
        pkt_count = generate_scenario_pcap(sc, pcap_full_path)
        file_size_kb = os.path.getsize(pcap_full_path) / 1024.0
        
        print(f"[OK] {s_id} | {sc['encryption']:18} | DH:{dh:<2} | PFS:{sc['pfs']:<5} | {traffic.upper():<5} -> {pcap_filename} ({pkt_count} pkts, {file_size_kb:.1f} KB)")
        
        labels_rows.append(f"{s_id},{mode},{sc['encryption']},{sc['integrity']},{dh},{sc['pfs']},{sc['ike_version']},{sc['ip_version']},{traffic},{rel_pcap_path}")
        
    # Write ground-truth labels.csv
    with open(LABELS_FILE, "w", encoding="utf-8") as f:
        f.write("scenario_id,mode,encryption,integrity,dh_group,pfs,ike_version,ip_version,traffic_type,pcap_path\n")
        for row in labels_rows:
            f.write(row + "\n")
            
    print(f"\n==================================================================")
    print(f"[+] Successfully generated {len(SCENARIOS)} scenario PCAP captures!")
    print(f"[+] Ground-truth labels written to: {LABELS_FILE}")
    print(f"==================================================================")

if __name__ == "__main__":
    main()
