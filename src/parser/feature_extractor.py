"""
Statistical Feature Extractor Module for ESP Flows.
Extracts an 8-feature statistical array from raw ESP traffic flows.
"""

from typing import List, Dict, Any, Union
import numpy as np


def extract_features(esp_flows: List[Union[Dict[str, Any], Any]]) -> List[float]:
    """
    Computes an 8-feature statistical array from raw ESP flows.

    Features:
        0: mean_size (float) - Mean ESP packet size
        1: std_size (float) - Standard deviation of packet sizes
        2: mean_iat (float) - Mean inter-arrival time between packets
        3: std_iat (float) - Standard deviation of inter-arrival times
        4: pkt_count (int/float) - Total packet count
        5: bidirectional_ratio (float) - Ratio of forward packets to total packets
        6: min_size (float) - Minimum ESP packet size
        7: max_size (float) - Maximum ESP packet size

    Args:
        esp_flows (list): List of ESP packet dictionaries (e.g. from parse_esp).

    Returns:
        list: 8-element numerical feature array.
    """
    if not esp_flows:
        return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

    sizes = []
    timestamps = []
    fwd_count = 0
    bwd_count = 0

    for item in esp_flows:
        if isinstance(item, dict):
            size = item.get("length", 0)
            ts = item.get("timestamp", 0.0)
            direction = item.get("flow_direction", "forward")
        else:
            # Fallback if passed as tuple (size, timestamp, direction, ...)
            size = item[0] if len(item) > 0 else 0
            ts = item[1] if len(item) > 1 else 0.0
            direction = item[2] if len(item) > 2 else "forward"

        sizes.append(float(size))
        timestamps.append(float(ts))

        if direction == "forward":
            fwd_count += 1
        else:
            bwd_count += 1

    pkt_count = len(sizes)
    if pkt_count == 0:
        return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]

    # Packet size metrics
    mean_size = float(np.mean(sizes))
    std_size = float(np.std(sizes)) if pkt_count > 1 else 0.0
    min_size = float(np.min(sizes))
    max_size = float(np.max(sizes))

    # Inter-arrival time (IAT) metrics
    if pkt_count > 1:
        # Sort timestamps to ensure proper chronological order
        timestamps.sort()
        iats = [timestamps[i] - timestamps[i - 1] for i in range(1, pkt_count)]
        mean_iat = float(np.mean(iats))
        std_iat = float(np.std(iats)) if len(iats) > 1 else 0.0
    else:
        mean_iat = 0.0
        std_iat = 0.0

    # Bidirectional ratio (forward packet fraction)
    bidirectional_ratio = float(fwd_count / pkt_count)

    return [
        mean_size,
        std_size,
        mean_iat,
        std_iat,
        float(pkt_count),
        bidirectional_ratio,
        min_size,
        max_size,
    ]
