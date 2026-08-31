"""
Risk Engine Module.

Turns the per-parameter classifications from security_rules.py into:
  - a findings list (one entry per evaluated parameter),
  - a composite 0-100 Security Score,
  - a Risk Level bucket (Critical / High / Medium / Low),
  - a severity-sorted Threat Matrix listing only the parameters that
    fell short of "Strong" (a fully strong configuration therefore
    produces an empty threat matrix).

Matches the two-call shape used by src/pipeline.py:

    findings = evaluate_security(ike_info)
    risk = compute_risk(findings)

`ike_info` is a plain dict of whatever protocol/crypto fields are known
for the tunnel being assessed. Every key is optional — parameters absent
from the dict are classified "Unknown" by security_rules.py and excluded
from the score's denominator (see compute_risk), not penalized as weak.
Recognized keys: encryption, integrity, dh_group, pfs, ike_version,
key_lifetime_hours, replay_protection, mode.
"""

from typing import Any, Dict, List, Optional

from src.assessment.security_rules import PARAMETER_CLASSIFIERS

# Maps each scoring-table parameter name to the ike_info dict key that
# supplies its value, so evaluate_security() can drive PARAMETER_CLASSIFIERS
# generically instead of one hardcoded if-branch per parameter.
PARAMETER_INPUT_KEYS: Dict[str, str] = {
    "Encryption": "encryption",
    "Integrity": "integrity",
    "DH Group": "dh_group",
    "PFS": "pfs",
    "IKE Version": "ike_version",
    "Key Lifetime": "key_lifetime_hours",
    "Replay Protection": "replay_protection",
    "Mode": "mode",
}

# Recommendation text shown in the threat matrix, per parameter, for a
# non-Strong finding. Kept separate from security_rules.py's classify_*
# notes (which explain *why* a value scored as it did) so the threat
# matrix can show "what's wrong" and "what to do about it" side by side.
RECOMMENDATIONS: Dict[str, str] = {
    "Encryption": "Renegotiate using AES-256-GCM or ChaCha20-Poly1305 (RFC 8247 MUST/SHOULD ciphers).",
    "Integrity": "Move to an AEAD cipher suite or HMAC-SHA2-256/384/512 for integrity.",
    "DH Group": "Raise the Diffie-Hellman group to \u226514 (2048-bit MODP) or an ECC group (19/20/21/31).",
    "PFS": "Enable Perfect Forward Secrecy so a compromised long-term key cannot expose past sessions.",
    "IKE Version": "Migrate the peer configuration to IKEv2.",
    "Key Lifetime": "Lower the SA key lifetime to 8 hours or less to shrink the exposure window.",
    "Replay Protection": "Enable ESP anti-replay (sequence number) checking on both peers.",
    "Mode": "Use Tunnel mode for site-to-site/remote-access deployments; Transport mode is acceptable only for host-to-host links where header exposure is an accepted trade-off.",
}

# Values that indicate a parameter isn't merely sub-optimal but provides
# effectively no protection at all — these are escalated to "Critical"
# severity in the threat matrix instead of the default "High" for a
# Weak-banded finding.
_CRITICAL_MARKERS = ("NULL", "DES", "MD5")

RISK_LEVEL_THRESHOLDS = (
    (80, "Low"),
    (60, "Medium"),
    (40, "High"),
    (0, "Critical"),
)


def evaluate_security(ike_info: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Classify every recognized parameter in `ike_info` and return one
    finding dict per parameter:

        {
            "parameter": "Encryption",
            "value": "AES-128-CBC",
            "band": "Weak",              # Strong / Medium / Weak / Unknown
            "points": 0,                 # 10 / 5 / 0 / None
            "note": "AES-128-CBC combines a shorter key with a non-AEAD mode.",
        }

    Always returns exactly len(PARAMETER_CLASSIFIERS) findings, in the
    same fixed parameter order, whether or not `ike_info` supplied every
    key — a missing key simply classifies as "Unknown".
    """
    ike_info = ike_info or {}
    findings: List[Dict[str, Any]] = []

    for parameter, classify in PARAMETER_CLASSIFIERS.items():
        input_key = PARAMETER_INPUT_KEYS[parameter]
        raw_value = ike_info.get(input_key)
        band, points, note = classify(raw_value)
        findings.append(
            {
                "parameter": parameter,
                "value": raw_value if raw_value not in (None, "") else "Unknown",
                "band": band,
                "points": points,
                "note": note,
            }
        )

    return findings


def _severity_for(finding: Dict[str, Any]) -> str:
    """Map a finding's band to a threat-matrix severity label."""
    band = finding["band"]
    if band == "Weak":
        value_str = str(finding["value"]).upper()
        if any(marker in value_str for marker in _CRITICAL_MARKERS):
            return "Critical"
        return "High"
    if band == "Medium":
        return "Medium"
    if band == "Unknown":
        return "Info"
    return "Low"  # unreached for Strong findings, which never enter the matrix


def _risk_level(score: float) -> str:
    for threshold, label in RISK_LEVEL_THRESHOLDS:
        if score >= threshold:
            return label
    return "Critical"  # unreachable safeguard; RISK_LEVEL_THRESHOLDS bottoms out at 0


def compute_risk(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Aggregate evaluate_security()'s findings into a composite score,
    risk level, and threat matrix.

    Returns:
        {
            "security_score": float,      # 0-100, rounded to 1 decimal
            "risk_level": str,             # Critical / High / Medium / Low
            "threat_matrix": [ ... ],      # severity-sorted, Strong findings excluded
            "scored_parameter_count": int, # how many parameters had a known band
            "total_parameter_count": int,  # len(findings), for transparency
            "low_confidence": bool,        # True when under half the parameters were known
            "coverage_note": str | None,   # human-readable caveat when low_confidence
        }

    Parameters classified "Unknown" (points is None) are excluded from
    both the numerator and denominator of the score, so an unparsed
    field never drags a genuinely strong tunnel's score down — it shows
    up instead as an "Info"-severity threat-matrix entry so the gap is
    still visible to a reviewer.
    """
    scored = [f for f in findings if f["points"] is not None]
    total_possible = len(scored) * 10
    earned = sum(f["points"] for f in scored)
    security_score = round((earned / total_possible) * 100, 1) if total_possible else 0.0

    # A score built from only a couple of known parameters is not the
    # same statement as one built from all eight — say so explicitly
    # rather than letting (for example) "1 of 8 parameters known, that
    # one was Strong" render identically to a fully-verified 100/Low.
    coverage = (len(scored) / len(findings)) if findings else 0.0
    low_confidence = coverage < 0.5

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Info": 3}
    threat_matrix = []
    for f in findings:
        if f["band"] == "Strong":
            continue
        severity = _severity_for(f)
        threat_matrix.append(
            {
                "parameter": f["parameter"],
                "finding": f["note"],
                "severity": severity,
                "recommendation": RECOMMENDATIONS.get(f["parameter"], "Review this parameter against RFC 8247 / NIST SP 800-77 Rev.1."),
            }
        )
    threat_matrix.sort(key=lambda t: severity_order.get(t["severity"], 99))

    return {
        "security_score": security_score,
        "risk_level": _risk_level(security_score),
        "threat_matrix": threat_matrix,
        "scored_parameter_count": len(scored),
        "total_parameter_count": len(findings),
        "low_confidence": low_confidence,
        "coverage_note": (
            f"Only {len(scored)} of {len(findings)} parameters could be determined from this "
            "capture; treat this score as provisional until the rest are known."
            if low_confidence
            else None
        ),
    }
