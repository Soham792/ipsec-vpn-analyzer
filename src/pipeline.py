"""
Pipeline Orchestration Module.

One function, analyze_pcap(), connects everything upstream (Workstream A's
real captures, Workstream B's parser + ML classifier) to the security
assessment engine (Phase 6) and returns a single dict the dashboard and
report generators can consume without knowing about any of the pieces
underneath.

    def analyze_pcap(path: str) -> dict:
        ike_info = parse_ike(path)
        esp_flows = parse_esp(path)
        features = extract_features(esp_flows)
        traffic_pred = predict_traffic(features)
        findings = evaluate_security(ike_info)
        risk = compute_risk(findings)
        return {...}

This matches the shape sketched in implementation.md Phase 7, with one
addition: _enrich_ike_info(). ike_parser.parse_ike() only extracts what's
genuinely decodable from the IKE bytes on the wire (version, exchange
type, encryption, dh_group, pfs) — it does not (and honestly cannot,
from the transform IDs alone) recover mode, integrity algorithm, IP
version, key lifetime, or replay-protection status. Where the pcap being
analyzed is one of the bundled, already-labeled dataset scenarios in
data/labels.csv, those fields are genuinely known — they were the actual
configuration Workstream A negotiated — so _enrich_ike_info() looks them
up by matching the pcap's filename and folds them in. For a pcap that
isn't part of the bundled dataset (e.g. someone uploads an unfamiliar
capture through the dashboard), no such lookup is possible and those
fields are correctly left "Unknown" rather than guessed.
"""

import glob
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import pandas as pd

from src.parser.ike_parser import parse_ike
from src.parser.esp_parser import parse_esp
from src.parser.feature_extractor import extract_features
from src.ml.predict import predict_traffic
from src.assessment.risk_engine import evaluate_security, compute_risk

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_LABELS_CSV = os.path.join(PROJECT_ROOT, "data", "labels.csv")
DEFAULT_CONFIGS_DIR = os.path.join(PROJECT_ROOT, "lab", "configs")

# Cached at module load on first use; the bundled dataset doesn't change
# during a dashboard session, so re-reading the CSV on every pcap would
# be wasted I/O.
_labels_cache: Optional[pd.DataFrame] = None


def _load_labels(labels_csv: str = DEFAULT_LABELS_CSV) -> pd.DataFrame:
    global _labels_cache
    if _labels_cache is None:
        if os.path.exists(labels_csv):
            _labels_cache = pd.read_csv(labels_csv)
        else:
            _labels_cache = pd.DataFrame()
    return _labels_cache


def _find_label_row(pcap_path: str, labels_csv: str = DEFAULT_LABELS_CSV) -> Optional[pd.Series]:
    """Match a pcap (by basename, so absolute/relative/OS path differences
    don't matter) against the bundled ground-truth dataset."""
    df = _load_labels(labels_csv)
    if df.empty or "pcap_path" not in df.columns:
        return None
    target = os.path.basename(pcap_path)
    matches = df[df["pcap_path"].apply(lambda p: os.path.basename(str(p)) == target)]
    if matches.empty:
        return None
    return matches.iloc[0]


def _rekey_hours_from_config(scenario_id: str, configs_dir: str = DEFAULT_CONFIGS_DIR) -> Optional[float]:
    """Read the real rekey_time this scenario's strongSwan config actually
    negotiated with, rather than assuming a value."""
    pattern = os.path.join(configs_dir, f"{scenario_id}_*.conf")
    matches = glob.glob(pattern)
    if not matches:
        return None
    try:
        with open(matches[0], "r", encoding="utf-8") as fh:
            text = fh.read()
        m = re.search(r"rekey_time\s*=\s*(\d+)s", text)
        if m:
            return round(int(m.group(1)) / 3600.0, 2)
    except OSError:
        pass
    return None


def _replay_protection_from_config(scenario_id: str, configs_dir: str = DEFAULT_CONFIGS_DIR) -> Optional[bool]:
    """strongSwan enables anti-replay checking by default; a config would
    have to explicitly set replay_window = 0 to disable it. None of the
    bundled scenarios do, but this checks rather than assumes."""
    pattern = os.path.join(configs_dir, f"{scenario_id}_*.conf")
    matches = glob.glob(pattern)
    if not matches:
        return None
    try:
        with open(matches[0], "r", encoding="utf-8") as fh:
            text = fh.read()
        m = re.search(r"replay_window\s*=\s*(\d+)", text)
        if m:
            return int(m.group(1)) != 0
        return True  # strongSwan default when unspecified
    except OSError:
        return None


def _enrich_ike_info(pcap_path: str, ike_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fold in mode / integrity / ip_version / key_lifetime_hours /
    replay_protection from the bundled dataset when the pcap is a known
    scenario, plus backfill any field parse_ike genuinely failed to
    decode ("Unknown") from the same ground truth. Every backfilled or
    added field is recorded in `_enrichment_notes` so the technical
    report can disclose exactly what came off the wire versus what came
    from known lab configuration.
    """
    enriched = dict(ike_info)
    notes = []

    row = _find_label_row(pcap_path)
    if row is None:
        enriched.setdefault("mode", None)
        enriched.setdefault("integrity", None)
        enriched.setdefault("ip_version", None)
        enriched.setdefault("key_lifetime_hours", None)
        enriched.setdefault("replay_protection", None)
        enriched["_enrichment_notes"] = [
            "This capture did not match a bundled dataset scenario in data/labels.csv, "
            "so mode, integrity, IP version, key lifetime, and replay-protection status "
            "could not be determined and are reported as Unknown."
        ]
        return enriched

    scenario_id = str(row.get("scenario_id", ""))
    enriched["mode"] = row.get("mode")
    enriched["integrity"] = row.get("integrity")
    enriched["ip_version"] = row.get("ip_version")
    notes.append(
        f"mode/integrity/ip_version sourced from data/labels.csv ground truth for scenario {scenario_id}."
    )

    lifetime = _rekey_hours_from_config(scenario_id)
    enriched["key_lifetime_hours"] = lifetime
    notes.append(
        f"key_lifetime_hours read from lab/configs/{scenario_id}_*.conf rekey_time."
        if lifetime is not None
        else "key_lifetime_hours could not be read from the scenario's strongSwan config."
    )

    replay = _replay_protection_from_config(scenario_id)
    enriched["replay_protection"] = replay
    notes.append(
        "replay_protection reflects strongSwan's default anti-replay window "
        f"(no override found in scenario {scenario_id}'s config)."
        if replay is not None
        else "replay_protection could not be determined from the scenario's config."
    )

    # Backfill wire-parse fields only where parse_ike genuinely couldn't
    # decode them, and say so explicitly rather than presenting a
    # dataset value as if it came off the wire.
    for field in ("encryption", "dh_group", "ike_version"):
        if str(enriched.get(field, "")).strip().lower() in ("", "unknown") and field in row:
            enriched[field] = row[field]
            notes.append(
                f"{field} could not be decoded from the capture's IKE payload and was "
                f"backfilled from the known configuration for scenario {scenario_id}."
            )
    if enriched.get("pfs") is False and str(row.get("pfs", "")).strip().lower() == "true":
        # parse_ike only flags PFS when it observes a Key Exchange payload
        # in a rekey/child-SA exchange; a short capture may simply not
        # contain one even though PFS is configured on. Don't silently
        # overwrite a wire observation of "no PFS seen" with the config's
        # intent — flag the discrepancy instead so a reviewer can judge.
        notes.append(
            f"Note: parse_ike did not observe a PFS key exchange in this capture, but "
            f"scenario {scenario_id}'s configuration negotiates PFS on \u2014 the capture "
            "may simply be too short to include a rekey. Reported as observed (PFS off)."
        )

    enriched["_enrichment_notes"] = notes
    return {k: _to_native(v) for k, v in enriched.items()}


def _to_native(value: Any) -> Any:
    """Convert pandas/numpy scalar types (numpy.int64, numpy.bool_, NaN,
    etc.) to plain Python types so downstream JSON/report/dashboard code
    never has to special-case them."""
    if isinstance(value, list):
        return value
    if value is None:
        return None
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    if hasattr(value, "item"):  # numpy scalar (int64, float64, bool_, ...)
        return value.item()
    return value


def analyze_pcap(path: str) -> Dict[str, Any]:
    """
    Run the full analysis pipeline against a single .pcap file:
    protocol parsing -> ESP feature extraction -> ML traffic
    classification -> security scoring.

    Returns:
        {
            "pcap_path": str,
            "ike_info": dict,              # parse_ike() output, enriched (see _enrich_ike_info)
            "esp_packet_count": int,
            "traffic_prediction": {"label": str, "confidence": float},
            "findings": [ ... ],           # evaluate_security() output
            "risk": {                      # compute_risk() output
                "security_score": float, "risk_level": str,
                "threat_matrix": [...], "scored_parameter_count": int,
                "total_parameter_count": int,
            },
            "generated_at": str,           # ISO-8601 UTC timestamp
        }

    Every stage degrades gracefully: a missing or unreadable pcap yields
    parse_ike/parse_esp's own empty-result defaults rather than raising,
    so the dashboard can show "no data" instead of crashing on a bad
    upload.
    """
    ike_info_raw = parse_ike(path)
    ike_info = _enrich_ike_info(path, ike_info_raw)

    esp_flows = parse_esp(path)
    features = extract_features(esp_flows)
    if esp_flows:
        label, confidence = predict_traffic(features)
    else:
        # extract_features() returns an all-zero vector for an empty flow,
        # which the classifier will still confidently label as *something*
        # (e.g. "chat", since near-zero packet counts look superficially
        # like a sparse chat burst). That's a spurious answer, not a real
        # prediction, so don't return it as one — this also covers the
        # S11 IPv6 boundary case documented in the project README, where
        # ESP transmission was 0 due to an IPv4 socket binding in the
        # traffic generator.
        label, confidence = "insufficient_data", 0.0

    findings = evaluate_security(ike_info)
    risk = compute_risk(findings)

    return {
        "pcap_path": path,
        "ike_info": ike_info,
        "esp_packet_count": len(esp_flows),
        "traffic_prediction": {"label": label, "confidence": confidence},
        "findings": findings,
        "risk": risk,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
