"""
src/reporting/technical_report.py

Generates the full Technical Report PDF from an analyze_pcap() result.

The report is designed around the actual Phase 7 pipeline output:

    result
    ├── pcap_path
    ├── ike_info
    │   ├── version
    │   ├── exchange_type
    │   ├── encryption
    │   ├── dh_group
    │   ├── pfs
    │   ├── mode
    │   ├── integrity
    │   ├── ip_version
    │   ├── key_lifetime_hours
    │   ├── replay_protection
    │   ├── ike_version
    │   └── _enrichment_notes
    ├── esp_packet_count
    ├── traffic_prediction
    │   ├── label
    │   └── confidence
    ├── findings
    ├── risk
    │   ├── security_score
    │   ├── risk_level
    │   ├── threat_matrix
    │   ├── scored_parameter_count
    │   ├── total_parameter_count
    │   ├── low_confidence
    │   └── coverage_note
    └── generated_at

The report deliberately does not invent an ML feature vector because the
current pipeline returns the prediction and confidence, but does not expose
the raw feature vector in the final result dictionary.
"""

from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle,
)
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    PageBreak,
)

from src.reporting.executive_report import _get, _risk_color


# --------------------------------------------------------------------------
# Severity colors
# --------------------------------------------------------------------------

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#B00020"),
    "High": colors.HexColor("#E65100"),
    "Medium": colors.HexColor("#F9A825"),
    "Low": colors.HexColor("#2E7D32"),
    "Info": colors.grey,
}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _confidence_percent(value):
    """
    Convert a confidence value to a percentage.

    The actual pipeline returns values between 0 and 1:

        0.90 -> 90.0%

    Already-converted percentages such as 90 are also accepted.
    """
    if not isinstance(value, (int, float)):
        return None

    if 0 <= value <= 1:
        return value * 100

    return float(value)


def _format_value(value):
    """Make common values easier to read in the PDF."""
    if isinstance(value, bool):
        return "Enabled" if value else "Disabled"

    if value is None:
        return "N/A"

    return str(value)


def _risk_hex(level):
    """Return a safe hex color string for a risk level."""
    color = _risk_color(level)

    try:
        return color.hexval()
    except AttributeError:
        return "#000000"


# --------------------------------------------------------------------------
# Main report generator
# --------------------------------------------------------------------------

def generate_technical_report(
    result: dict,
    output_path: str,
    scenario_name: str = None,
) -> str:
    """
    Generate the Technical Report PDF.

    Parameters
    ----------
    result:
        Dictionary returned by src.pipeline.analyze_pcap().

    output_path:
        Destination path for the PDF.

    scenario_name:
        Optional scenario identifier displayed in the report.

    Returns
    -------
    str
        The output path.
    """

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TechnicalTitle",
        parent=styles["Title"],
        fontSize=18,
        spaceAfter=4,
    )

    subtitle_style = ParagraphStyle(
        "TechnicalSubtitle",
        parent=styles["Normal"],
        fontSize=9.5,
        textColor=colors.grey,
    )

    h2 = ParagraphStyle(
        "TechnicalH2",
        parent=styles["Heading2"],
        spaceBefore=14,
        spaceAfter=6,
    )

    h3 = ParagraphStyle(
        "TechnicalH3",
        parent=styles["Heading3"],
        spaceBefore=10,
        spaceAfter=4,
    )

    body = ParagraphStyle(
        "TechnicalBody",
        parent=styles["Normal"],
        fontSize=9.5,
        leading=13.5,
    )

    small = ParagraphStyle(
        "TechnicalSmall",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=11,
    )

    mono = ParagraphStyle(
        "TechnicalMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.8,
        leading=10.5,
    )

    # ----------------------------------------------------------------------
    # Extract actual pipeline output
    # ----------------------------------------------------------------------

    ike_info = _get(
        result,
        "ike_info",
        default={},
    ) or {}

    findings = _get(
        result,
        "findings",
        default=[],
    ) or []

    # IMPORTANT:
    # Never fall back to `findings` here.
    #
    # findings = all assessed parameters
    # threat_matrix = only parameters below Strong
    threat_matrix = _get(
        result,
        "threat_matrix",
        ["risk", "threat_matrix"],
        default=[],
    ) or []

    score = _get(
        result,
        "score",
        ["risk", "security_score"],
        ["risk", "score"],
        default="N/A",
    )

    risk_level = _get(
        result,
        "risk_level",
        ["risk", "risk_level"],
        ["risk", "level"],
        default="Unknown",
    )

    traffic_prediction = _get(
        result,
        "traffic_prediction",
        default={},
    ) or {}

    if not isinstance(traffic_prediction, dict):
        traffic_prediction = {}

    traffic_label = _get(
        traffic_prediction,
        "label",
        "prediction",
        default="N/A",
    )

    traffic_confidence = _get(
        traffic_prediction,
        "confidence",
        default=None,
    )

    confidence_percent = _confidence_percent(
        traffic_confidence
    )

    esp_packet_count = _get(
        result,
        "esp_packet_count",
        default=0,
    )

    generated_at = _get(
        result,
        "generated_at",
        default=datetime.now(
            timezone.utc
        ).isoformat(),
    )

    # Actual pipeline stores enrichment notes inside ike_info.
    enrichment_notes = _get(
        ike_info,
        "_enrichment_notes",
        default=[],
    ) or []

    if not enrichment_notes:
        enrichment_notes = _get(
            result,
            "_enrichment_notes",
            default=[],
        ) or []

    scored_parameter_count = _get(
        result,
        ["risk", "scored_parameter_count"],
        default=len(findings),
    )

    total_parameter_count = _get(
        result,
        ["risk", "total_parameter_count"],
        default=8,
    )

    low_confidence = _get(
        result,
        ["risk", "low_confidence"],
        default=False,
    )

    coverage_note = _get(
        result,
        ["risk", "coverage_note"],
        default=None,
    )

    # ----------------------------------------------------------------------
    # Create PDF
    # ----------------------------------------------------------------------

    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
        leftMargin=0.7 * inch,
        rightMargin=0.7 * inch,
    )

    elements = []

    # ----------------------------------------------------------------------
    # Header
    # ----------------------------------------------------------------------

    elements.append(
        Paragraph(
            "IPsec VPN Security Assessment — Technical Report",
            title_style,
        )
    )

    subtitle = (
        f"Generated {generated_at}"
    )

    if scenario_name:
        subtitle = (
            f"Scenario: {scenario_name}  ·  "
            + subtitle
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
            8,
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
            12,
        )
    )

    # ----------------------------------------------------------------------
    # Overall assessment
    # ----------------------------------------------------------------------

    score_display = (
        f"{score:.1f}"
        if isinstance(score, (int, float))
        else str(score)
    )

    risk_color = _risk_hex(
        risk_level
    )

    elements.append(
        Paragraph(
            f"Overall Score: <b>{score_display}/100</b>  —  "
            f"Risk Level: "
            f"<b><font color='{risk_color}'>{risk_level}</font></b>",
            body,
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
            f"Security parameters assessed: "
            f"<b>{scored_parameter_count}</b> / "
            f"<b>{total_parameter_count}</b>.",
            small,
        )
    )

    elements.append(
        Spacer(
            1,
            12,
        )
    )

    # ----------------------------------------------------------------------
    # 1. Negotiated parameters
    # ----------------------------------------------------------------------

    elements.append(
        Paragraph(
            "1. Negotiated Parameters",
            h2,
        )
    )

    param_rows = [
        [
            "Parameter",
            "Value",
            "Band",
            "Justification",
        ]
    ]

    param_keys = [
        (
            "IKE Version",
            ["ike_version", "version"],
        ),
        (
            "Exchange Type",
            ["exchange_type"],
        ),
        (
            "Mode",
            ["mode"],
        ),
        (
            "Encryption",
            ["encryption"],
        ),
        (
            "Integrity",
            ["integrity"],
        ),
        (
            "DH Group",
            ["dh_group"],
        ),
        (
            "PFS",
            ["pfs"],
        ),
        (
            "IP Version",
            ["ip_version"],
        ),
        (
            "Key Lifetime",
            [
                "key_lifetime_hours",
                "key_lifetime",
                "lifetime",
            ],
        ),
        (
            "Replay Protection",
            ["replay_protection"],
        ),
    ]

    # Match findings to their assessed parameter.
    findings_by_param = {}

    for finding in findings:

        parameter = str(
            _get(
                finding,
                "parameter",
                default="",
            )
        ).strip().lower()

        if parameter:
            findings_by_param[
                parameter
            ] = finding

    for label, keys in param_keys:

        value = _get(
            ike_info,
            *keys,
            default="N/A",
        )

        # Key lifetime should be displayed with units.
        if label == "Key Lifetime" and value != "N/A":
            value_display = f"{value} hours"
        else:
            value_display = _format_value(
                value
            )

        match = findings_by_param.get(
            label.lower()
        )

        if match:

            band = _get(
                match,
                "band",
                default="Unknown",
            )

            note = _get(
                match,
                "note",
                "finding",
                default="No justification available.",
            )

        else:

            band = "Unknown"

            note = (
                "No assessment record was returned "
                "for this parameter."
            )

        param_rows.append(
            [
                label,
                value_display,
                str(band),
                Paragraph(
                    str(note),
                    mono,
                ),
            ]
        )

    param_table = Table(
        param_rows,
        colWidths=[
            1.25 * inch,
            1.25 * inch,
            0.85 * inch,
            3.15 * inch,
        ],
        repeatRows=1,
    )

    param_table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#F2F2F2"),
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    8.2,
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.HexColor("#DDDDDD"),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),
            ]
        )
    )

    elements.append(
        param_table
    )

    elements.append(
        Spacer(
            1,
            14,
        )
    )

    # ----------------------------------------------------------------------
    # 2. Threat matrix
    # ----------------------------------------------------------------------

    elements.append(
        Paragraph(
            "2. Threat Matrix (Severity-Sorted)",
            h2,
        )
    )

    if not threat_matrix:

        elements.append(
            Paragraph(
                "No entries — every assessed parameter "
                "scored Strong.",
                body,
            )
        )

    else:

        tm_rows = [
            [
                "Parameter",
                "Finding",
                "Severity",
                "Recommendation",
            ]
        ]

        severity_order = {
            "Critical": 0,
            "High": 1,
            "Medium": 2,
            "Low": 3,
        }

        sorted_threats = sorted(
            threat_matrix,
            key=lambda item: severity_order.get(
                str(
                    _get(
                        item,
                        "severity",
                        default="Low",
                    )
                ),
                4,
            ),
        )

        for finding in sorted_threats:

            tm_rows.append(
                [
                    str(
                        _get(
                            finding,
                            "parameter",
                            default="",
                        )
                    ),
                    Paragraph(
                        str(
                            _get(
                                finding,
                                "finding",
                                "note",
                                default="",
                            )
                        ),
                        mono,
                    ),
                    str(
                        _get(
                            finding,
                            "severity",
                            default="",
                        )
                    ),
                    Paragraph(
                        str(
                            _get(
                                finding,
                                "recommendation",
                                default="",
                            )
                        ),
                        mono,
                    ),
                ]
            )

        tm_table = Table(
            tm_rows,
            colWidths=[
                1.05 * inch,
                2.15 * inch,
                0.85 * inch,
                2.45 * inch,
            ],
            repeatRows=1,
        )

        style_commands = [
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#F2F2F2"),
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold",
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                8.2,
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.4,
                colors.HexColor("#DDDDDD"),
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP",
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                4,
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                4,
            ),
        ]

        for row_index, finding in enumerate(
            sorted_threats,
            start=1,
        ):

            severity = str(
                _get(
                    finding,
                    "severity",
                    default="",
                )
            )

            style_commands.append(
                (
                    "TEXTCOLOR",
                    (2, row_index),
                    (2, row_index),
                    SEVERITY_COLORS.get(
                        severity,
                        colors.black,
                    ),
                )
            )

            style_commands.append(
                (
                    "FONTNAME",
                    (2, row_index),
                    (2, row_index),
                    "Helvetica-Bold",
                )
            )

        tm_table.setStyle(
            TableStyle(
                style_commands
            )
        )

        elements.append(
            tm_table
        )

    elements.append(
        Spacer(
            1,
            14,
        )
    )

    # ----------------------------------------------------------------------
    # 3. ML traffic analysis
    # ----------------------------------------------------------------------

    elements.append(
        Paragraph(
            "3. Traffic-Type Prediction (ML)",
            h2,
        )
    )

    if traffic_label == "insufficient_data":

        elements.append(
            Paragraph(
                "Prediction status: "
                "<b>insufficient_data</b>.",
                body,
            )
        )

        elements.append(
            Spacer(
                1,
                4,
            )
        )

        elements.append(
            Paragraph(
                "The pipeline intentionally avoids producing a "
                "confident traffic classification when insufficient "
                "ESP traffic is available.",
                body,
            )
        )

    else:

        confidence_text = (
            f"{confidence_percent:.1f}%"
            if confidence_percent is not None
            else "N/A"
        )

        elements.append(
            Paragraph(
                f"Predicted traffic type: "
                f"<b>{traffic_label}</b>",
                body,
            )
        )

        elements.append(
            Paragraph(
                f"Model confidence: "
                f"<b>{confidence_text}</b>",
                body,
            )
        )

        elements.append(
            Paragraph(
                f"ESP packet count: "
                f"<b>{esp_packet_count}</b>",
                body,
            )
        )

    elements.append(
        Spacer(
            1,
            8,
        )
    )

    # The actual pipeline currently doesn't expose raw ML features.
    elements.append(
        Paragraph(
            "ML feature-vector disclosure",
            h3,
        )
    )

    elements.append(
        Paragraph(
            "The current Phase 7 pipeline returns the final traffic "
            "prediction label and model confidence, but does not expose "
            "the raw feature vector in the final analyze_pcap() result. "
            "Therefore, this report does not fabricate or reconstruct a "
            "feature vector. The prediction is generated by the existing "
            "ESP traffic feature-extraction and Random Forest classification "
            "pipeline.",
            body,
        )
    )

    if low_confidence:

        elements.append(
            Spacer(
                1,
                6,
            )
        )

        elements.append(
            Paragraph(
                "Pipeline warning: the risk engine marked this result "
                "as low-confidence.",
                body,
            )
        )

    if coverage_note:

        elements.append(
            Spacer(
                1,
                6,
            )
        )

        elements.append(
            Paragraph(
                f"Coverage note: {coverage_note}",
                body,
            )
        )

    elements.append(
        Spacer(
            1,
            14,
        )
    )

    # ----------------------------------------------------------------------
    # 4. Methodology
    # ----------------------------------------------------------------------

    elements.append(
        PageBreak()
    )

    elements.append(
        Paragraph(
            "4. Methodology & Honest Disclosure",
            h2,
        )
    )

    elements.append(
        Paragraph(
            "The IPsec tunnel, IKE negotiation, and ESP traffic analyzed "
            "by this project are based on a real strongSwan lab deployment "
            "across Linux nodes. The bundled PCAP scenarios represent "
            "captured VPN traffic rather than manually fabricated packet "
            "records.",
            body,
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
            "The project uses bundled scenario metadata and lab "
            "configuration files to enrich fields that are not reliably "
            "decoded by the current IKE parser. Such enrichment is recorded "
            "in field-level provenance notes rather than being presented "
            "as direct wire-level parsing.",
            body,
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
            "Traffic classification is performed on encrypted ESP-flow "
            "metadata such as packet size, timing, and direction. The "
            "application does not claim to decrypt ESP payload contents. "
            "The classifier therefore predicts traffic type from observable "
            "encrypted-flow characteristics.",
            body,
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
            "The bundled scenarios include standard traffic generated "
            "using ordinary network tools as well as scripted traffic "
            "patterns intended to reproduce characteristic packet-size "
            "and timing behavior for application categories such as "
            "VoIP, video, and chat. These limitations should be considered "
            "when interpreting the classifier's generalization to arbitrary "
            "real-world applications.",
            body,
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
            "Security scoring is performed by the Phase 6 rule engine. "
            "Each assessed parameter receives a Strong, Medium, Weak, or "
            "Unknown classification and contributes to the aggregate "
            "0–100 security score. The threat matrix contains only "
            "parameters that fall below the Strong band.",
            body,
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
            "Cryptographic recommendations are based on established "
            "security guidance and the project's documented references, "
            "including NIST SP 800-77 Rev. 1 and RFC 8247.",
            body,
        )
    )

    # ----------------------------------------------------------------------
    # 5. Field-level enrichment provenance
    # ----------------------------------------------------------------------

    if enrichment_notes:

        elements.append(
            Spacer(
                1,
                12,
            )
        )

        elements.append(
            Paragraph(
                "5. Field-Level Data Provenance",
                h2,
            )
        )

        elements.append(
            Paragraph(
                "The following notes were produced by the pipeline to "
                "distinguish information decoded from the capture from "
                "information enriched from the project's known scenario "
                "configuration or documented defaults.",
                body,
            )
        )

        elements.append(
            Spacer(
                1,
                6,
            )
        )

        for note in enrichment_notes:

            elements.append(
                Paragraph(
                    f"• {note}",
                    mono,
                )
            )

            elements.append(
                Spacer(
                    1,
                    3,
                )
            )

    # ----------------------------------------------------------------------
    # 6. Reproducibility information
    # ----------------------------------------------------------------------

    elements.append(
        Spacer(
            1,
            12,
        )
    )

    elements.append(
        Paragraph(
            "6. Reproducibility Information",
            h2,
        )
    )

    pcap_path = _get(
        result,
        "pcap_path",
        default="N/A",
    )

    elements.append(
        Paragraph(
            f"Analyzed PCAP: <b>{pcap_path}</b>",
            small,
        )
    )

    elements.append(
        Spacer(
            1,
            4,
        )
    )

    elements.append(
        Paragraph(
            f"ESP packets observed: "
            f"<b>{esp_packet_count}</b>",
            small,
        )
    )

    elements.append(
        Spacer(
            1,
            4,
        )
    )

    elements.append(
        Paragraph(
            f"Security parameters scored: "
            f"<b>{scored_parameter_count}/{total_parameter_count}</b>",
            small,
        )
    )

    # ----------------------------------------------------------------------
    # Generate PDF
    # ----------------------------------------------------------------------

    doc.build(
        elements
    )

    return output_path


# --------------------------------------------------------------------------
# Manual test
# --------------------------------------------------------------------------

if __name__ == "__main__":

    fake_result = {
        "pcap_path": "data/pcaps/S07_example.pcap",

        "ike_info": {
            "version": "IKEv1",
            "exchange_type": "IKE_SA_INIT, Main Mode",
            "encryption": "AES-128-CBC",
            "dh_group": 1,
            "pfs": False,
            "mode": "tunnel",
            "integrity": "HMAC-MD5",
            "ip_version": "IPv4",
            "key_lifetime_hours": 24.0,
            "replay_protection": True,
            "ike_version": "IKEv1",
            "_enrichment_notes": [
                "Encryption backfilled from the known lab configuration.",
                "DH group backfilled from the known lab configuration.",
            ],
        },

        "esp_packet_count": 1464,

        "traffic_prediction": {
            "label": "web",
            "confidence": 0.865,
        },

        "findings": [
            {
                "parameter": "Encryption",
                "value": "AES-128-CBC",
                "band": "Weak",
                "points": 0,
                "note": (
                    "AES-128-CBC combines a shorter key "
                    "with a non-AEAD mode."
                ),
            },
            {
                "parameter": "Integrity",
                "value": "HMAC-MD5",
                "band": "Weak",
                "points": 0,
                "note": (
                    "HMAC-MD5 relies on a broken hash "
                    "function and should be retired."
                ),
            },
            {
                "parameter": "DH Group",
                "value": 1,
                "band": "Weak",
                "points": 0,
                "note": (
                    "DH group 1 is a legacy sub-1024-bit "
                    "MODP group."
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
                {
                    "parameter": "DH Group",
                    "finding": (
                        "DH group 1 is a legacy sub-1024-bit "
                        "MODP group."
                    ),
                    "severity": "High",
                    "recommendation": (
                        "Raise the Diffie-Hellman group to "
                        "≥14 or an ECC group."
                    ),
                },
            ],

            "scored_parameter_count": 8,
            "total_parameter_count": 8,
            "low_confidence": False,
            "coverage_note": None,
        },

        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }

    output = "technical_report_test.pdf"

    generate_technical_report(
        fake_result,
        output,
        scenario_name="S07",
    )

    print(
        f"Wrote {output}"
    )