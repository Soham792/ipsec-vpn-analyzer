"""
ESP (Encapsulating Security Payload) Parser Module.
Parses raw .pcap files using Scapy to extract ESP packet lengths, sequence numbers, and flow directions.
Supports IPv4, IPv6 (direct ESP, extension headers, CookedLinux encapsulation), and UDP port 4500 NAT-T ESP.
"""

import os
import struct
from typing import List, Dict, Any

try:
    from scapy.all import rdpcap, IP, IPv6, UDP, Raw
    from scapy.layers.ipsec import ESP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def parse_esp(pcap_path: str) -> List[Dict[str, Any]]:
    """
    Filter for IP protocol 50 (ESP) and NAT-T ESP packets in a PCAP file,
    extracting packet lengths, sequence numbers, timestamps, and flow directions.
    Supports IPv4, IPv6 (including extension headers and CookedLinux encapsulation),
    and UDP port 4500 NAT-T ESP.

    Args:
        pcap_path (str): Path to the .pcap file.

    Returns:
        list: List of dictionaries for each ESP packet:
            [
                {
                    "length": int,
                    "sequence_number": int,
                    "flow_direction": str,  # 'forward' or 'backward'
                    "timestamp": float,
                    "src": str,
                    "dst": str
                },
                ...
            ]
    """
    esp_packets = []

    if not os.path.exists(pcap_path):
        return esp_packets

    if not SCAPY_AVAILABLE:
        return esp_packets

    try:
        packets = rdpcap(pcap_path)
    except Exception:
        return esp_packets

    initial_src = None

    for pkt in packets:
        is_esp = False
        seq_num = 0
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        pkt_len = len(pkt)
        ts = float(getattr(pkt, "time", 0.0))

        # Check IPv4
        if pkt.haslayer(IP):
            src_ip = str(pkt[IP].src)
            dst_ip = str(pkt[IP].dst)
            if pkt[IP].proto == 50 or pkt.haslayer(ESP):
                is_esp = True
                pkt_len = int(getattr(pkt[IP], "len", len(pkt)))

        # Check IPv6 (Next Header 50, extension headers, or decoded ESP layer)
        elif pkt.haslayer(IPv6):
            src_ip = str(pkt[IPv6].src)
            dst_ip = str(pkt[IPv6].dst)
            ipv6_nh = getattr(pkt[IPv6], "nh", None)
            if ipv6_nh in (50, 0x32, "ESP", "ESP Header") or pkt.haslayer(ESP):
                is_esp = True
                plen = getattr(pkt[IPv6], "plen", 0)
                pkt_len = (plen + 40) if plen > 0 else len(pkt)
            else:
                # Check for IPv6 extension header chain ending in ESP
                curr = pkt[IPv6].payload
                while curr and curr != b"":
                    if hasattr(curr, "nh") and getattr(curr, "nh") in (50, 0x32, "ESP", "ESP Header"):
                        is_esp = True
                        break
                    if hasattr(curr, "payload"):
                        curr = curr.payload
                    else:
                        break

        # Check standalone ESP layer if not wrapped in standard IP/IPv6
        elif pkt.haslayer(ESP):
            is_esp = True
            pkt_len = len(pkt)
            if hasattr(pkt, "src") and hasattr(pkt, "dst"):
                src_ip = str(pkt.src)
                dst_ip = str(pkt.dst)

        # NAT-T ESP encapsulated in UDP port 4500 (IPv4 or IPv6)
        if not is_esp and pkt.haslayer(UDP):
            udp = pkt[UDP]
            if udp.sport == 4500 or udp.dport == 4500:
                payload = bytes(udp.payload)
                # If first 4 bytes are NOT 0x00000000 (Non-ESP Marker), it is encapsulated ESP
                if len(payload) >= 8 and payload[:4] != b"\x00\x00\x00\x00":
                    is_esp = True
                    pkt_len = len(payload)
                    if pkt.haslayer(IP):
                        src_ip = str(pkt[IP].src)
                        dst_ip = str(pkt[IP].dst)
                    elif pkt.haslayer(IPv6):
                        src_ip = str(pkt[IPv6].src)
                        dst_ip = str(pkt[IPv6].dst)

        if not is_esp:
            continue

        # Extract sequence number
        if pkt.haslayer(ESP):
            seq_num = int(getattr(pkt[ESP], "seq", 0))
        else:
            # Fallback to byte extraction from raw ESP payload (SPI=4 bytes, SEQ=4 bytes)
            raw_data = None
            if pkt.haslayer(Raw):
                raw_data = bytes(pkt[Raw])
            elif pkt.haslayer(UDP):
                raw_data = bytes(pkt[UDP].payload)

            if raw_data and len(raw_data) >= 8:
                try:
                    _, seq_num = struct.unpack("!II", raw_data[:8])
                except struct.error:
                    seq_num = 0

        if initial_src is None:
            initial_src = src_ip

        direction = "forward" if src_ip == initial_src else "backward"

        esp_packets.append(
            {
                "length": pkt_len,
                "sequence_number": seq_num,
                "flow_direction": direction,
                "timestamp": ts,
                "src": src_ip,
                "dst": dst_ip,
            }
        )

    return esp_packets
