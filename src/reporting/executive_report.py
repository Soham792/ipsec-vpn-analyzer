"""
src/reporting/executive_report.py

Generates a 1-page, plain-English Executive Summary PDF from an
analyze_pcap() result dict.

The report is designed to work with the actual Phase 7 pipeline output,
while remaining tolerant of minor key-name differences.
"""

from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
)


def _get(d, *keys, default="N/A"):
    """
    Try several possible key names or nested key paths.

    Examples:
        _get(result, "score", ["risk", "security_score"])
        _get(result, ["traffic_prediction", "confidence"])

    Returns the first non-empty value found.
    """
    for key in keys:

        if isinstance(key, (list, tuple)):

            current = d
            found = True

            for part in key:

                if isinstance(current, dict) and part in current:
                    current = current[part]

                else:
                    found = False
                    break

            if found and current not in (None, ""):
                return current

        else:

            if (
                isinstance(d, dict)
                and key in d
                and d[key] not in (None, "")
            ):
                return d[key]

    return default


RISK_COLORS = {
    "Critical": colors.HexColor("#B00020"),
    "High": colors.HexColor("#E65100"),
    "Medium": colors.HexColor("#F9A825"),
    "Low": colors.HexColor("#2E7D32"),
}


def _risk_color(level):
    """Return the display color associated with a risk level."""
    return RISK_COLORS.get(
        str(level),
        colors.grey,
    )


def _confidence_percent(value):
    """
    Convert pipeline confidence into a percentage.

    The actual Phase 7 pipeline returns confidence as a decimal
    between 0 and 1, for example 0.9.

    Also accepts an already-converted percentage such as 90.
    """
    if not isinstance(value, (int, float)):
        return None

    if 0 <= value <= 1:
        return value * 100

    return float(value)


def generate_executive_report(
    result: dict,
    output_path: str,
    scenario_name: str = None,
) -> str:
    """
    Build a 1-page executive PDF summarizing an analyze_pcap() result.

    Parameters
    ----------
    result:
        Dictionary returned by src.pipeline.analyze_pcap().

    output_path:
        Destination path for the generated PDF.

    scenario_name:
        Optional scenario name displayed in the report.

    Returns
    -------
    str
        The output_path written.
    """

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleBig",
        parent=styles["Title"],
        fontSize=20,
        spaceAfter=4,
    )

    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.grey,
    )

    h2 = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        spaceBefore=14,
        spaceAfter=6,
    )

    body = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=10.5,
        leading=15,
    )

    footer_style = ParagraphStyle(
        "Footer",
        parent=styles["Normal"],
        fontSize=8.5,
        textColor=colors.grey,
    )

    # ------------------------------------------------------------------
    # Extract actual Phase 7 pipeline values
    # ------------------------------------------------------------------

    # Actual pipeline:
    # result["risk"]["security_score"]
    score = _get(
        result,
        "score",
        ["risk", "security_score"],
        ["risk", "score"],
        default="N/A",
    )

    # Actual pipeline:
    # result["risk"]["risk_level"]
    risk_level = _get(
        result,
        "risk_level",
        ["risk", "risk_level"],
        ["risk", "level"],
        default="Unknown",
    )

    # Actual pipeline:
    # result["traffic_prediction"]["confidence"]
    ai_conf = _get(
        result,
        "ai_confidence",
        ["traffic_prediction", "confidence"],
        ["risk", "ai_confidence"],
        default=None,
    )

    # Actual pipeline:
    # result["traffic_prediction"]["label"]
    traffic_label = _get(
        result,
        ["traffic_prediction", "label"],
        default="N/A",
    )

    generated_at = _get(
        result,
        "generated_at",
        default=datetime.now(
            timezone.utc
        ).isoformat(),
    )

    # IMPORTANT:
    # The threat matrix is deliberately taken from risk.threat_matrix.
    #
    # Do NOT fall back to result["findings"] here because findings
    # contains all assessed parameters, including Strong parameters.
    threat_matrix = _get(
        result,
        "threat_matrix",
        ["risk", "threat_matrix"],
        default=[],
    ) or []

    # ------------------------------------------------------------------
    # Normalize confidence
    # ------------------------------------------------------------------

    confidence_percent = _confidence_percent(
        ai_conf
    )

    # ------------------------------------------------------------------
    # Build PDF
    # ------------------------------------------------------------------

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
        leftMargin=0.7 * inch,
        rightMargin=0.7 * inch,
    )

    elements = []

    # ------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------

    elements.append(
        Paragraph(
            "IPsec VPN Security Assessment",
            title_style,
        )
    )

    subtitle = "Executive Summary"

    if scenario_name:
        subtitle += (
            f"  ·  Scenario: {scenario_name}"
        )

    subtitle += (
        f"  ·  Generated {generated_at}"
    )

    elements.append(
        Paragraph(
            subtitle,
            subtitle_style,
        )
    )

    elements.append(
        Spacer(
            1,
            10,
        )
    )

    elements.append(
        HRFlowable(
            width="100%",
            color=colors.HexColor("#DDDDDD"),
        )
    )

    elements.append(
        Spacer(
            1,
            14,
        )
    )

    # ------------------------------------------------------------------
    # Score / Risk / AI confidence
    # ------------------------------------------------------------------

    if isinstance(score, (int, float)):
        score_display = f"{score:.1f}/100"
    else:
        score_display = str(score)

    if confidence_percent is not None:
        confidence_display = (
            f"{confidence_percent:.1f}%"
        )
    else:
        confidence_display = "N/A"

    badge_table = Table(
        [
            [
                "Security Score",
                "Risk Level",
                "AI Confidence",
            ],
            [
                score_display,
                str(risk_level),
                confidence_display,
            ],
        ],
        colWidths=[
            2.1 * inch,
            2.1 * inch,
            2.1 * inch,
        ],
    )

    badge_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#F2F2F2"),
                ),
                (
                    "TEXTCOLOR",
                    (1, 1),
                    (1, 1),
                    _risk_color(risk_level),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "FONTNAME",
                    (0, 1),
                    (-1, 1),
                    "Helvetica-Bold",
                ),
                (
                    "FONTSIZE",
                    (0, 1),
                    (-1, 1),
                    14,
                ),
                (
                    "ALIGN",
                    (0, 0),
                    (-1, -1),
                    "CENTER",
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, 0),
                    6,
                ),
                (
                    "TOPPADDING",
                    (0, 1),
                    (-1, 1),
                    8,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 1),
                    (-1, 1),
                    10,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.5,
                    colors.HexColor("#DDDDDD"),
                ),
            ]
        )
    )

    elements.append(
        badge_table
    )

    elements.append(
        Spacer(
            1,
            16,
        )
    )

    # ------------------------------------------------------------------
    # Plain-English summary
    # ------------------------------------------------------------------

    elements.append(
        Paragraph(
            "What this means",
            h2,
        )
    )

    n_findings = len(
        threat_matrix
    )

    n_critical = sum(
        1
        for finding in threat_matrix
        if str(
            _get(
                finding,
                "severity",
                default="",
            )
        ).lower()
        == "critical"
    )

    if (
        str(risk_level) == "Low"
        and n_findings == 0
    ):

        summary = (
            "This VPN tunnel was configured using strong, "
            "currently-recommended cryptographic settings "
            "across every parameter we checked. No weaknesses "
            "were found."
        )

    else:

        summary = (
            f"This VPN tunnel scored {score_display} "
            f"and is rated <b>{risk_level}</b> risk. "
            f"We identified {n_findings} configuration "
            f"issue(s)"
            + (
                f", including {n_critical} rated Critical"
                if n_critical
                else ""
            )
            + ". The most important issues to fix are "
            "listed below."
        )

    elements.append(
        Paragraph(
            summary,
            body,
        )
    )

    elements.append(
        Spacer(
            1,
            10,
        )
    )

    # ------------------------------------------------------------------
    # Traffic prediction
    # ------------------------------------------------------------------

    elements.append(
        Paragraph(
            "Traffic Analysis",
            h2,
        )
    )

    if (
        traffic_label != "N/A"
        or confidence_percent is not None
    ):

        traffic_text = (
            f"The encrypted traffic was classified as "
            f"<b>{traffic_label}</b>"
        )

        if confidence_percent is not None:

            traffic_text += (
                f" with {confidence_percent:.1f}% "
                "model confidence."
            )

        else:

            traffic_text += "."

        elements.append(
            Paragraph(
                traffic_text,
                body,
            )
        )

    else:

        elements.append(
            Paragraph(
                "No traffic-type prediction was available.",
                body,
            )
        )

    elements.append(
        Spacer(
            1,
            8,
        )
    )

    # ------------------------------------------------------------------
    # Top issues
    # ------------------------------------------------------------------

    elements.append(
        Paragraph(
            "Top issues to address",
            h2,
        )
    )

    severity_order = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
    }

    top = sorted(
        threat_matrix,
        key=lambda finding: severity_order.get(
            str(
                _get(
                    finding,
                    "severity",
                    default="Low",
                )
            ),
            4,
        ),
    )[:3]

    if not top:

        elements.append(
            Paragraph(
                "None — every parameter met the "
                "strong-configuration bar.",
                body,
            )
        )

    else:

        for finding in top:

            parameter = _get(
                finding,
                "parameter",
                default="Unknown parameter",
            )

            description = _get(
                finding,
                "finding",
                "note",
                default="",
            )

            recommendation = _get(
                finding,
                "recommendation",
                default="",
            )

            severity = _get(
                finding,
                "severity",
                default="",
            )

            line = (
                f"<b>[{severity}] "
                f"{parameter}:</b> "
                f"{description}"
            )

            if recommendation:

                line += (
                    f" <i>Recommended fix: "
                    f"{recommendation}</i>"
                )

            elements.append(
                Paragraph(
                    line,
                    body,
                )
            )

            elements.append(
                Spacer(
                    1,
                    6,
                )
            )

    # ------------------------------------------------------------------
    # Footer
    # ------------------------------------------------------------------

    elements.append(
        Spacer(
            1,
            14,
        )
    )

    elements.append(
        HRFlowable(
            width="100%",
            color=colors.HexColor("#DDDDDD"),
        )
    )

    elements.append(
        Spacer(
            1,
            6,
        )
    )

    elements.append(
        Paragraph(
            "This is a summary for non-technical stakeholders. "
            "See the accompanying Technical Report for full "
            "parameter-by-parameter justification, the ML "
            "traffic-analysis output, and methodology notes.",
            footer_style,
        )
    )

    # ------------------------------------------------------------------
    # Generate PDF
    # ------------------------------------------------------------------

    doc.build(
        elements
    )

    return output_path


# --------------------------------------------------------------------------
# Manual test
# --------------------------------------------------------------------------

if __name__ == "__main__":

    fake_result = {
        "ike_info": {
            "version": "IKEv1",
            "mode": "tunnel",
            "encryption": "AES-128-CBC",
            "integrity": "HMAC-MD5",
            "dh_group": 1,
            "pfs": False,
        },
        "traffic_prediction": {
            "label": "web",
            "confidence": 0.865,
        },
        "findings": [
            {
                "parameter": "Encryption",
                "band": "Weak",
                "points": 0,
                "note": (
                    "AES-128-CBC combines a shorter key "
                    "with a non-AEAD mode."
                ),
            },
            {
                "parameter": "Integrity",
                "band": "Weak",
                "points": 0,
                "note": (
                    "HMAC-MD5 relies on a broken hash "
                    "function and should be retired."
                ),
            },
        ],
        "risk": {
            "security_score": 31.2,
            "risk_level": "Critical",
            "threat_matrix": [
                {
                    "parameter": "Integrity",
                    "finding": (
                        "HMAC-MD5 relies on a broken hash "
                        "function and should be retired."
                    ),
                    "severity": "Critical",
                    "recommendation": (
                        "Move to an AEAD cipher suite or "
                        "HMAC-SHA2-256/384/512."
                    ),
                },
                {
                    "parameter": "Encryption",
                    "finding": (
                        "AES-128-CBC combines a shorter key "
                        "with a non-AEAD mode."
                    ),
                    "severity": "High",
                    "recommendation": (
                        "Renegotiate using AES-256-GCM "
                        "or ChaCha20-Poly1305."
                    ),
                },
            ],
        },
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    output = "executive_report_test.pdf"

    generate_executive_report(
        fake_result,
        output,
        scenario_name="S07",
    )

    print(
        f"Wrote {output}"
    )