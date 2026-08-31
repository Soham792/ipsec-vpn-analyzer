"""
tests/test_pipeline_smoke.py

Smoke tests for the Phase 7 analysis pipeline.

These tests verify that:
1. analyze_pcap() returns the expected top-level structure.
2. The security score exists and is within [0, 100].
3. The risk level is valid.
4. Every bundled PCAP can be processed without crashing.

This is intentionally an integration/smoke test, not a detailed
correctness test for the individual security rules.
"""

import glob
import os

import pytest

from src.pipeline import analyze_pcap


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

PCAP_DIR = os.path.normpath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "data",
        "pcaps",
    )
)


# This matches the ACTUAL Phase 7 analyze_pcap() output.
EXPECTED_TOP_LEVEL_KEYS = {
    "ike_info",
    "traffic_prediction",
    "findings",
    "risk",
    "generated_at",
}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _first_real_pcap():
    """
    Return the first bundled PCAP.

    If no PCAPs exist, skip the test rather than failing because the
    dataset has not been installed.
    """
    candidates = sorted(
        glob.glob(
            os.path.join(
                PCAP_DIR,
                "*.pcap",
            )
        )
    )

    if not candidates:

        pytest.skip(
            f"No .pcap files found in {PCAP_DIR} — "
            "run the Phase 3 lab/data setup first."
        )

    return candidates[0]


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------

def test_analyze_pcap_returns_expected_shape():
    """
    Verify that analyze_pcap() returns the expected top-level keys.
    """

    pcap_path = _first_real_pcap()

    result = analyze_pcap(
        pcap_path
    )

    assert isinstance(
        result,
        dict,
    ), (
        "analyze_pcap() must return a dictionary"
    )

    missing = (
        EXPECTED_TOP_LEVEL_KEYS
        - set(result.keys())
    )

    assert not missing, (
        "analyze_pcap() result is missing keys: "
        f"{missing}"
    )


def test_analyze_pcap_score_in_range():
    """
    Verify that the Phase 6 security score exists and is 0–100.

    Actual pipeline location:
        result["risk"]["security_score"]
    """

    pcap_path = _first_real_pcap()

    result = analyze_pcap(
        pcap_path
    )

    risk = result.get(
        "risk",
        {},
    )

    score = risk.get(
        "security_score"
    )

    assert score is not None, (
        "No score found in "
        "result['risk']['security_score']"
    )

    score = float(
        score
    )

    assert 0 <= score <= 100, (
        f"Score {score} is out of range [0, 100]"
    )


def test_analyze_pcap_risk_level_is_valid():
    """
    Verify that the risk engine returns a recognized risk level.
    """

    pcap_path = _first_real_pcap()

    result = analyze_pcap(
        pcap_path
    )

    risk = result.get(
        "risk",
        {},
    )

    level = risk.get(
        "risk_level"
    )

    assert level in {
        "Critical",
        "High",
        "Medium",
        "Low",
    }, (
        f"Unexpected risk level: {level}"
    )


def test_analyze_pcap_traffic_prediction_shape():
    """
    Verify the actual Phase 7 traffic prediction structure.

    The current pipeline returns:

        result["traffic_prediction"] = {
            "label": ...,
            "confidence": ...
        }

    rather than a traffic_predictions list.
    """

    pcap_path = _first_real_pcap()

    result = analyze_pcap(
        pcap_path
    )

    prediction = result.get(
        "traffic_prediction"
    )

    assert isinstance(
        prediction,
        dict,
    ), (
        "Expected result['traffic_prediction'] "
        "to be a dictionary"
    )

    assert "label" in prediction, (
        "traffic_prediction is missing 'label'"
    )

    assert "confidence" in prediction, (
        "traffic_prediction is missing 'confidence'"
    )


def test_analyze_pcap_on_all_bundled_scenarios_does_not_crash():
    """
    Process every bundled PCAP.

    None should raise an exception.

    This deliberately includes edge cases such as S11, where the
    traffic classifier should return insufficient_data instead of
    producing a fake confident prediction.
    """

    all_pcaps = sorted(
        glob.glob(
            os.path.join(
                PCAP_DIR,
                "*.pcap",
            )
        )
    )

    if not all_pcaps:

        pytest.skip(
            f"No .pcap files found in {PCAP_DIR}"
        )

    failures = []

    for path in all_pcaps:

        try:

            result = analyze_pcap(
                path
            )

            assert isinstance(
                result,
                dict,
            )

            assert "risk" in result, (
                f"{os.path.basename(path)} "
                "does not contain a risk result"
            )

            assert "security_score" in result[
                "risk"
            ], (
                f"{os.path.basename(path)} "
                "does not contain risk.security_score"
            )

        except Exception as exc:

            failures.append(
                (
                    os.path.basename(path),
                    str(exc),
                )
            )

    assert not failures, (
        "analyze_pcap() raised on: "
        f"{failures}"
    )


def test_s11_zero_esp_packets_returns_insufficient_data():
    """
    Explicitly verify the known S11 edge case.

    S11 has zero ESP packets in the bundled dataset. The pipeline
    should therefore avoid a fake ML classification and return
    insufficient_data.
    """

    candidates = sorted(
        glob.glob(
            os.path.join(
                PCAP_DIR,
                "S11_*.pcap",
            )
        )
    )

    if not candidates:

        pytest.skip(
            "S11 PCAP not found in bundled dataset."
        )

    result = analyze_pcap(
        candidates[0]
    )

    prediction = result.get(
        "traffic_prediction",
        {},
    )

    assert prediction.get(
        "label"
    ) == "insufficient_data", (
        "S11 should return insufficient_data "
        "because it contains zero ESP packets."
    )