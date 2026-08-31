"""
IKE (Internet Key Exchange) Protocol Parser Module.
Parses raw .pcap files using Scapy to extract IKE parameters.
"""

import os
from typing import Dict, Any

try:
    import scapy.packet
    from scapy.all import rdpcap, UDP, IP, IPv6, ISAKMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


EXCHANGE_TYPES = {
    2: "Main Mode",
    4: "Aggressive Mode",
    5: "Quick Mode",
    32: "IKE_SA_INIT",
    33: "IKE_AUTH",
    34: "CREATE_CHILD_SA",
    35: "INFORMATIONAL",
    37: "IKE_SESSION_RESUME",
}

ENCRYPTION_ALGS = {
    1: "DES",
    2: "IDEA",
    3: "Blowfish",
    5: "3DES",
    7: "AES-CBC",
    12: "AES-GCM-16",
    13: "AES-CCM-8",
    18: "AES-GCM-8",
    19: "AES-GCM-12",
    20: "AES-GCM-16",
}

DH_GROUPS = {
    1: "Group 1 (768-bit MODP)",
    2: "Group 2 (1024-bit MODP)",
    5: "Group 5 (1536-bit MODP)",
    14: "Group 14 (2048-bit MODP)",
    15: "Group 15 (3072-bit MODP)",
    16: "Group 16 (4096-bit MODP)",
    19: "Group 19 (256-bit ECP)",
    20: "Group 20 (384-bit ECP)",
    21: "Group 21 (521-bit ECP)",
}


def _scan_attributes(raw_bytes: bytes, encryptions_found: set, dh_groups_found: set):
    """Fallback scanner for raw ISAKMP/IKE payload bytes."""
    if len(raw_bytes) < 4:
        return

    i = 0
    while i <= len(raw_bytes) - 4:
        attr_header = int.from_bytes(raw_bytes[i : i + 2], "big")
        af = (attr_header >> 15) & 1
        attr_type = attr_header & 0x7FFF

        if af == 1:  # Basic attribute
            val = int.from_bytes(raw_bytes[i + 2 : i + 4], "big")
            if attr_type == 1 and val in ENCRYPTION_ALGS:
                encryptions_found.add(ENCRYPTION_ALGS[val])
            elif attr_type == 4 and val in DH_GROUPS:
                dh_groups_found.add(DH_GROUPS[val])
            i += 4
        else:  # Variable attribute
            val_len = int.from_bytes(raw_bytes[i + 2 : i + 4], "big")
            i += 4 + val_len
            if val_len <= 0:
                break


def parse_ike(pcap_path: str) -> Dict[str, Any]:
    """
    Parse a PCAP file using Scapy to extract IKE / ISAKMP protocol details.

    Args:
        pcap_path (str): Path to the .pcap file.

    Returns:
        dict: Dictionary containing:
            - version (str): IKE version (e.g., 'IKEv2', 'IKEv1', 'Unknown')
            - exchange_type (str): Exchange mode/type (e.g., 'IKE_SA_INIT', 'Main Mode')
            - encryption (str): Extracted encryption algorithm
            - dh_group (str): Extracted Diffie-Hellman group
            - pfs (bool): Perfect Forward Secrecy status
    """
    result = {
        "version": "Unknown",
        "exchange_type": "Unknown",
        "encryption": "Unknown",
        "dh_group": "Unknown",
        "pfs": False,
    }

    if not os.path.exists(pcap_path):
        return result

    if not SCAPY_AVAILABLE:
        return result

    try:
        packets = rdpcap(pcap_path)
    except Exception:
        return result

    versions_found = set()
    exchange_types_found = set()
    encryptions_found = set()
    dh_groups_found = set()
    pfs_detected = False

    for pkt in packets:
        # Filter UDP 500 (IKE) or 4500 (IKE NAT-T)
        if not pkt.haslayer(UDP):
            continue
        udp = pkt[UDP]
        if udp.sport not in (500, 4500) and udp.dport not in (500, 4500):
            continue

        if pkt.haslayer(ISAKMP):
            isakmp = pkt[ISAKMP]

            # Version extraction
            vers = getattr(isakmp, "version", getattr(isakmp, "vers", None))
            if vers is not None:
                major = (vers >> 4) & 0x0F
                minor = vers & 0x0F
                if major == 2:
                    versions_found.add("IKEv2")
                elif major == 1:
                    versions_found.add("IKEv1")
                else:
                    versions_found.add(f"IKEv{major}.{minor}")

            # Exchange type extraction
            exch = getattr(isakmp, "exch_type", None)
            if exch is not None:
                exch_name = EXCHANGE_TYPES.get(exch, f"Type_{exch}")
                exchange_types_found.add(exch_name)
                # PFS detection (Quick Mode in v1 or CREATE_CHILD_SA in v2)
                if exch in (5, 34):
                    pfs_detected = True

            # Inspect sub-payloads inside ISAKMP
            layer = isakmp.payload
            while layer and not isinstance(layer, scapy.packet.NoPayload):
                layer_name = type(layer).__name__

                if "Key_Exchange" in layer_name or "KE" in layer_name:
                    if exch in (5, 34):
                        pfs_detected = True

                if hasattr(layer, "transforms"):
                    transforms = getattr(layer, "transforms", [])
                    for t in transforms:
                        enc = getattr(t, "enc", None) or getattr(t, "encryption", None) or getattr(t, "trans_id", None)
                        if enc in ENCRYPTION_ALGS:
                            encryptions_found.add(ENCRYPTION_ALGS[enc])

                        dh = getattr(t, "dh", None) or getattr(t, "group", None)
                        if dh in DH_GROUPS:
                            dh_groups_found.add(DH_GROUPS[dh])
                            if exch in (5, 34):
                                pfs_detected = True

                # Raw payload fallback
                if isinstance(layer, Raw):
                    raw_bytes = bytes(layer)
                    _scan_attributes(raw_bytes, encryptions_found, dh_groups_found)

                layer = layer.payload

    if versions_found:
        result["version"] = ", ".join(sorted(versions_found))
    if exchange_types_found:
        result["exchange_type"] = ", ".join(sorted(exchange_types_found))
    if encryptions_found:
        result["encryption"] = ", ".join(sorted(encryptions_found))
    if dh_groups_found:
        result["dh_group"] = ", ".join(sorted(dh_groups_found))
    result["pfs"] = pfs_detected

    return result
