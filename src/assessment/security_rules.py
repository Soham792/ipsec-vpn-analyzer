"""
Security Rules Module.

Classifies individual negotiated IPsec / IKE parameters (encryption,
integrity, DH group, PFS, IKE version, key lifetime, replay protection,
mode) into Strong / Medium / Weak bands, following the scoring table in
implementation.md Section 7, which is itself grounded in NIST SP 800-77
Rev. 1 ("Guide to IPsec VPNs") and RFC 8247 ("Cryptographic Algorithm
Implementation Requirements and Key Management Guidelines for IKEv2").

This module is deliberately pure and stateless: every function takes a
value (or a small dict of related values) and returns a classification.
It does no file I/O, no scoring aggregation, and no pcap parsing — that
happens in risk_engine.py and pipeline.py respectively. Keeping the rules
isolated here means the reference tables can be audited or updated
in one place without touching the scoring or pipeline logic.

A known, honestly-disclosed limitation: src/parser/ike_parser.py extracts
the *encryption transform ID* from the wire (e.g. "AES-GCM-16"), but IKE
key length is carried in a separate ISAKMP attribute the current parser
does not decode, so raw-parsed encryption strings usually cannot
distinguish AES-128 from AES-256. Where the caller can supply a more
specific value (e.g. cross-referenced from data/labels.csv ground truth
for the bundled dataset, or a fuller pyshark-based decode in future work),
classify_encryption() will use that precision. Where only the generic
transform name is available, it classifies conservatively (never rounds
an unknown key length up to "Strong") and the returned note says so
explicitly, so the technical report can disclose it rather than hide it.
"""

from typing import Any, Dict, Optional, Tuple

# Points awarded per band, shared by every parameter so the aggregate
# score in risk_engine.py stays on a consistent 0-10 per-parameter scale.
STRONG = 10
MEDIUM = 5
WEAK = 0

# Band used when a parameter genuinely cannot be determined from the
# capture (e.g. a field the parser doesn't extract, or a value outside
# any known table entry). Treated as a neutral, informational gap rather
# than a security failure — it is surfaced as its own finding severity
# ("Info") rather than folded into "Weak", so an unparsed field doesn't
# silently make a strong tunnel look insecure.
UNKNOWN = None


def _norm(value: Optional[str]) -> str:
    """Uppercase + strip, tolerating None and mixed parser/label casing."""
    return (value or "").strip().upper()


def classify_encryption(value: Optional[str]) -> Tuple[str, Optional[int], str]:
    """
    Classify an encryption algorithm string.

    Accepts either a fully-specified label (e.g. "AES-256-GCM", as found
    in data/labels.csv) or a generic transform name without key length
    (e.g. "AES-GCM-16", as returned directly by ike_parser.parse_ike when
    only the wire transform ID is available).

    Returns:
        (band, points, note) where band is "Strong" / "Medium" / "Weak" /
        "Unknown", points is 10/5/0/None, and note explains the basis
        for the classification (useful for the threat matrix and report).
    """
    s = _norm(value)
    if not s or s == "UNKNOWN":
        return ("Unknown", UNKNOWN, "Encryption algorithm not present in capture/metadata.")

    is_chacha = "CHACHA20" in s
    is_gcm = "GCM" in s
    is_ccm = "CCM" in s
    is_cbc = "CBC" in s
    is_3des = "3DES" in s
    is_des = ("DES" in s) and not is_3des
    is_null = s == "NULL"
    has_256 = "256" in s
    has_128 = "128" in s

    if is_null or is_des:
        return ("Weak", WEAK, f"{value} provides no or negligible confidentiality.")
    if is_3des:
        return ("Weak", WEAK, "3DES is deprecated (64-bit block size, sweet32-class weaknesses).")

    if is_chacha:
        return ("Strong", STRONG, "ChaCha20-Poly1305 is an approved modern AEAD cipher (RFC 8439).")

    if is_gcm or is_ccm:
        family = "AES-GCM" if is_gcm else "AES-CCM"
        if has_256:
            return ("Strong", STRONG, f"{family}-256 is a NIST-recommended AEAD cipher.")
        if has_128:
            return ("Medium", MEDIUM, f"{family}-128 is acceptable AEAD but 256-bit keys are preferred.")
        # Generic transform name with no decodable key length.
        return (
            "Medium",
            MEDIUM,
            f"{family} negotiated (AEAD, no replay-vulnerable mode) but the capture's IKE "
            "attributes did not carry a decodable key length, so 128- vs 256-bit could not "
            "be confirmed; scored as Medium pending that confirmation.",
        )

    if is_cbc:
        if has_256:
            return ("Medium", MEDIUM, "AES-256-CBC is adequate but non-AEAD; prefer AES-GCM where available.")
        if has_128:
            return ("Weak", WEAK, "AES-128-CBC combines a shorter key with a non-AEAD mode.")
        return (
            "Weak",
            WEAK,
            "AES-CBC negotiated but key length could not be confirmed from the capture; "
            "scored conservatively as Weak since CBC alone (without a decoded 256-bit key) "
            "is the lower end of the accepted range.",
        )

    return ("Unknown", UNKNOWN, f"Unrecognized encryption transform '{value}'.")


def classify_integrity(value: Optional[str]) -> Tuple[str, Optional[int], str]:
    """
    Classify an integrity/PRF algorithm. AEAD ciphers (GCM/CCM/ChaCha20)
    provide integrity intrinsically and should be passed in as "AEAD".
    """
    s = _norm(value)
    if not s or s == "UNKNOWN":
        return ("Unknown", UNKNOWN, "Integrity/PRF algorithm not present in capture/metadata.")

    if s == "AEAD" or "AEAD" in s:
        return ("Strong", STRONG, "Integrity is built into the negotiated AEAD cipher.")
    if "SHA2" in s or "SHA-2" in s or "SHA256" in s or "SHA-256" in s or "SHA384" in s or "SHA512" in s:
        return ("Strong", STRONG, f"{value} is a modern SHA-2 family HMAC.")
    if "SHA1" in s or "SHA-1" in s:
        return ("Medium", MEDIUM, "HMAC-SHA1 is still permitted but SHA-2 is preferred going forward.")
    if "MD5" in s:
        return ("Weak", WEAK, "HMAC-MD5 relies on a broken hash function and should be retired.")
    if s == "NULL":
        return ("Weak", WEAK, "No integrity protection negotiated.")

    return ("Unknown", UNKNOWN, f"Unrecognized integrity/PRF algorithm '{value}'.")


def classify_dh_group(value: Any) -> Tuple[str, Optional[int], str]:
    """
    Classify a Diffie-Hellman group. Accepts either a bare group number
    (int or numeric string, as in data/labels.csv) or ike_parser's
    descriptive string (e.g. "Group 14 (2048-bit MODP)").
    """
    s = _norm(str(value)) if value is not None else ""
    if not s or s == "UNKNOWN":
        return ("Unknown", UNKNOWN, "DH group not present in capture/metadata.")

    # Pull the leading group number out of either representation.
    digits = ""
    for ch in s:
        if ch.isdigit():
            digits += ch
        elif digits:
            break
    group_num = int(digits) if digits else None

    strong_groups = {19, 20, 21, 31}
    good_modp = {14, 15, 16, 17, 18}
    medium_groups = {5}
    weak_groups = {1, 2}

    if group_num in strong_groups:
        return ("Strong", STRONG, f"DH group {group_num} is an elliptic-curve / Curve25519 group.")
    if group_num in good_modp:
        return ("Strong", STRONG, f"DH group {group_num} is MODP \u2265 2048-bit.")
    if group_num in medium_groups:
        return ("Medium", MEDIUM, f"DH group {group_num} (1536-bit MODP) is below the 2048-bit floor.")
    if group_num in weak_groups:
        return ("Weak", WEAK, f"DH group {group_num} is a legacy sub-1024-bit MODP group.")
    if group_num is not None:
        return ("Unknown", UNKNOWN, f"DH group {group_num} is not in the reference table.")

    return ("Unknown", UNKNOWN, f"Could not parse a DH group number from '{value}'.")


def classify_pfs(enabled: Any) -> Tuple[str, Optional[int], str]:
    """Classify Perfect Forward Secrecy status. Accepts bool, "true"/"false", or None."""
    if enabled is None:
        return ("Unknown", UNKNOWN, "PFS status not present in capture/metadata.")
    if isinstance(enabled, str):
        s = enabled.strip().lower()
        if s in ("true", "1", "yes", "on"):
            enabled = True
        elif s in ("false", "0", "no", "off"):
            enabled = False
        else:
            return ("Unknown", UNKNOWN, f"Unrecognized PFS value '{enabled}'.")
    if enabled:
        return ("Strong", STRONG, "PFS is enabled; a compromised long-term key cannot decrypt past sessions.")
    return ("Weak", WEAK, "PFS is disabled; session keys are derivable from the long-term key alone.")


def classify_ike_version(value: Optional[str]) -> Tuple[str, Optional[int], str]:
    """Classify negotiated IKE protocol version."""
    s = _norm(value)
    if not s or s == "UNKNOWN":
        return ("Unknown", UNKNOWN, "IKE version not present in capture/metadata.")
    if "IKEV2" in s.replace(" ", ""):
        return ("Strong", STRONG, "IKEv2 is the current, recommended protocol version.")
    if "IKEV1" in s.replace(" ", ""):
        return ("Weak", WEAK, "IKEv1 is legacy; it lacks IKEv2's simplified, hardened state machine.")
    return ("Unknown", UNKNOWN, f"Unrecognized IKE version '{value}'.")


def classify_key_lifetime(hours: Optional[float]) -> Tuple[str, Optional[int], str]:
    """Classify negotiated SA key lifetime, in hours."""
    if hours is None:
        return ("Unknown", UNKNOWN, "Key lifetime not present in capture/metadata.")
    try:
        h = float(hours)
    except (TypeError, ValueError):
        return ("Unknown", UNKNOWN, f"Could not parse key lifetime '{hours}'.")
    if h <= 8:
        return ("Strong", STRONG, f"{h:g}h key lifetime keeps re-keying frequent.")
    if h <= 24:
        return ("Medium", MEDIUM, f"{h:g}h key lifetime is within a day but longer than best practice.")
    return ("Weak", WEAK, f"{h:g}h key lifetime exceeds 24 hours, widening the exposure window if a key leaks.")


def classify_replay_protection(enabled: Optional[bool]) -> Tuple[str, Optional[int], str]:
    """Classify ESP anti-replay (sequence number checking) status."""
    if enabled is None:
        return ("Unknown", UNKNOWN, "Replay protection status not present in capture/metadata.")
    if enabled:
        return ("Strong", STRONG, "Anti-replay sequence checking is enabled.")
    return ("Weak", WEAK, "Anti-replay checking is disabled; captured ESP packets could be replayed.")


def classify_mode(value: Optional[str]) -> Tuple[str, Optional[int], str]:
    """Classify IPsec mode. Transport is scored Medium (context-dependent) per implementation.md §7."""
    s = _norm(value)
    if not s or s == "UNKNOWN":
        return ("Unknown", UNKNOWN, "IPsec mode not present in capture/metadata.")
    if "TUNNEL" in s:
        return ("Strong", STRONG, "Tunnel mode encrypts the full inner IP header, suited to site-to-site/remote access.")
    if "TRANSPORT" in s:
        return (
            "Medium",
            MEDIUM,
            "Transport mode only protects the payload; appropriate for host-to-host but exposes inner headers.",
        )
    return ("Unknown", UNKNOWN, f"Unrecognized mode '{value}'.")


# One entry per scoring-table parameter, in the order §7 lists them, so
# risk_engine.py can iterate a single stable list to build both the score
# and the threat matrix without duplicating parameter names in two places.
PARAMETER_CLASSIFIERS: Dict[str, Any] = {
    "Encryption": classify_encryption,
    "Integrity": classify_integrity,
    "DH Group": classify_dh_group,
    "PFS": classify_pfs,
    "IKE Version": classify_ike_version,
    "Key Lifetime": classify_key_lifetime,
    "Replay Protection": classify_replay_protection,
    "Mode": classify_mode,
}
