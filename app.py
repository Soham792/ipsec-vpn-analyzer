"""
IPsec VPN Analyzer — Streamlit Dashboard (Phase 8)

Dashboard for the Phase 6/7 IPsec VPN analysis pipeline.

Uses the real analyze_pcap() output currently implemented in:
    src/pipeline.py
"""

import glob
import os
import sys
from datetime import datetime, timezone

import pandas as pd
import plotly.graph_objects as go
import streamlit as st


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

st.set_page_config(
    page_title="IPsec VPN Analyzer",
    page_icon="🔐",
    layout="wide",
)

PCAP_DIR = "data/pcaps"
LABELS_CSV = "data/labels.csv"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def get_first(data, keys, default="N/A"):
    """Return the first non-empty value found for the supplied keys."""
    if not isinstance(data, dict):
        return default

    for key in keys:
        if key in data and data[key] not in (None, ""):
            return data[key]

    return default


def status_icon(value):
    """Return a simple status icon for common security values."""
    if isinstance(value, bool):
        return "🟢" if value else "🔴"

    normalized = str(value).strip().lower()

    if normalized in {
        "strong",
        "enabled",
        "ikev2",
        "tunnel",
        "low",
        "true",
    }:
        return "🟢"

    if normalized in {
        "medium",
        "1536-bit",
    }:
        return "🟡"

    if normalized in {
        "weak",
        "disabled",
        "ikev1",
        "critical",
        "high",
        "false",
    }:
        return "🔴"

    return "⚪"


def format_value(value):
    """Make boolean values more readable in the dashboard."""
    if isinstance(value, bool):
        return "Enabled" if value else "Disabled"

    return str(value)


@st.cache_resource(show_spinner=False)
def load_pipeline():
    """Load the Phase 7 pipeline lazily."""
    try:
        from src.pipeline import analyze_pcap
    except ImportError as exc:
        st.error(
            "Could not import `analyze_pcap` from `src/pipeline.py`.\n\n"
            "Make sure Phase 6/7 is present in this checkout.\n\n"
            f"Import error: {exc}"
        )
        st.stop()

    return analyze_pcap


def list_bundled_scenarios():
    """
    Load bundled scenarios from labels.csv.

    Falls back to the PCAP directory if labels.csv is unavailable.
    """
    if os.path.exists(LABELS_CSV):
        try:
            df = pd.read_csv(LABELS_CSV)

            if "pcap_path" in df.columns:
                return df

        except Exception:
            pass

    paths = sorted(glob.glob(os.path.join(PCAP_DIR, "*.pcap")))

    return pd.DataFrame(
        {
            "scenario_id": [
                os.path.basename(path).split("_")[0]
                for path in paths
            ],
            "pcap_path": paths,
        }
    )


def build_traffic_chart(result):
    """
    Build a Plotly chart from traffic information actually exposed
    by the Phase 7 pipeline.

    If raw packet_sizes are available, display their distribution.

    Otherwise, display a useful summary chart using the available
    ESP packet count and prediction confidence.
    """
    packet_sizes = result.get("packet_sizes")

    if isinstance(packet_sizes, list) and packet_sizes:
        fig = go.Figure(
            data=[
                go.Histogram(
                    x=packet_sizes,
                    nbinsx=30,
                )
            ]
        )

        fig.update_layout(
            title="ESP Packet Size Distribution",
            xaxis_title="Packet Size (bytes)",
            yaxis_title="Packet Count",
            height=350,
            margin=dict(l=10, r=10, t=50, b=10),
        )

        return fig

    traffic_prediction = result.get("traffic_prediction", {})

    if not isinstance(traffic_prediction, dict):
        traffic_prediction = {}

    label = traffic_prediction.get("label", "Unknown")
    confidence = traffic_prediction.get("confidence", 0.0)

    if not isinstance(confidence, (int, float)):
        confidence = 0.0

    if confidence <= 1:
        confidence_percent = confidence * 100
    else:
        confidence_percent = confidence

    esp_count = result.get("esp_packet_count", 0)

    if not isinstance(esp_count, (int, float)):
        esp_count = 0

    fig = go.Figure(
        data=[
            go.Bar(
                x=[
                    "ESP Packets",
                    "AI Confidence (%)",
                ],
                y=[
                    esp_count,
                    confidence_percent,
            ],
                text=[
                    f"{int(esp_count)}",
                    f"{confidence_percent:.1f}%",
                ],
                textposition="auto",
            )
        ]
    )

    fig.update_layout(
        title=f"Traffic Analysis — Predicted: {label}",
        yaxis_title="Value",
        height=350,
        margin=dict(l=10, r=10, t=50, b=10),
    )

    return fig


def build_threat_dataframe(threat_matrix):
    """Convert the pipeline threat matrix into a sorted DataFrame."""
    rows = []

    if not isinstance(threat_matrix, list):
        return pd.DataFrame()

    for entry in threat_matrix:
        if not isinstance(entry, dict):
            continue

        rows.append(
            {
                "Parameter": get_first(
                    entry,
                    ["parameter"],
                ),
                "Finding": get_first(
                    entry,
                    ["finding", "note"],
                ),
                "Severity": get_first(
                    entry,
                    ["severity"],
                ),
                "Recommendation": get_first(
                    entry,
                    ["recommendation"],
                ),
            }
        )

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)

    severity_order = {
        "Critical": 0,
        "High": 1,
        "Medium": 2,
        "Low": 3,
    }

    df["_sort"] = (
        df["Severity"]
        .map(severity_order)
        .fillna(9)
    )

    df = (
        df.sort_values("_sort")
        .drop(columns="_sort")
        .reset_index(drop=True)
    )

    return df


# --------------------------------------------------------------------------
# Sidebar
# --------------------------------------------------------------------------

st.sidebar.title("🔐 IPsec VPN Analyzer")
st.sidebar.caption("AI-Powered Security Assessment Framework")

scenarios_df = list_bundled_scenarios()

source_mode = st.sidebar.radio(
    "PCAP source",
    [
        "Bundled scenario",
        "Upload a .pcap",
    ],
)

pcap_path = None
selected_scenario = None


if source_mode == "Bundled scenario":

    if scenarios_df.empty:

        st.sidebar.warning(
            f"No scenarios found in {LABELS_CSV} "
            f"or {PCAP_DIR}/"
        )

    else:

        if "scenario_id" in scenarios_df.columns:
            label_col = "scenario_id"
        else:
            label_col = scenarios_df.columns[0]

        choices = scenarios_df[label_col].tolist()

        selected_scenario = st.sidebar.selectbox(
            "Scenario",
            choices,
        )

        matching_rows = scenarios_df[
            scenarios_df[label_col] == selected_scenario
        ]

        if not matching_rows.empty:

            row = matching_rows.iloc[0]

            pcap_path = row.get(
                "pcap_path",
                None,
            )

            if pcap_path and not os.path.isabs(pcap_path):
                pcap_path = os.path.normpath(pcap_path)

            with st.sidebar.expander(
                "Ground truth (labels.csv)"
            ):
                st.write(row.to_dict())


else:

    uploaded = st.sidebar.file_uploader(
        "Upload a .pcap file",
        type=["pcap", "pcapng"],
    )

    if uploaded is not None:

        upload_dir = os.path.join(
            PCAP_DIR,
            "_uploaded",
        )

        os.makedirs(
            upload_dir,
            exist_ok=True,
        )

        pcap_path = os.path.join(
            upload_dir,
            uploaded.name,
        )

        with open(
            pcap_path,
            "wb",
        ) as file:
            file.write(
                uploaded.getbuffer()
            )


analyze_clicked = st.sidebar.button(
    "Analyze",
    type="primary",
    use_container_width=True,
)

st.sidebar.divider()

st.sidebar.caption(
    "Traffic-type prediction is based on encrypted-flow "
    "metadata such as packet size and timing, not decrypted payload."
)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

st.title("IPsec VPN Protocol Analyzer")

st.markdown(
    """
    Analyze an IPsec VPN packet capture to assess its security posture,
    identify configuration weaknesses, and predict encrypted traffic type.
    """
)


if not analyze_clicked or not pcap_path:

    st.info(
        "Pick a scenario (or upload a PCAP) in the sidebar, "
        "then click **Analyze**."
    )

    st.stop()


if not os.path.exists(pcap_path):

    st.error(
        f"PCAP not found on disk: `{pcap_path}`"
    )

    st.stop()


analyze_pcap = load_pipeline()


# --------------------------------------------------------------------------
# Run pipeline
# --------------------------------------------------------------------------

with st.spinner(
    "Parsing PCAP, running classifier, "
    "and scoring security posture..."
):

    try:

        result = analyze_pcap(
            pcap_path
        )

    except Exception as exc:

        st.error(
            f"analyze_pcap() raised an exception: {exc}"
        )

        st.exception(exc)

        st.stop()


if not isinstance(result, dict):

    st.error(
        "The pipeline did not return a dictionary."
    )

    st.stop()


# --------------------------------------------------------------------------
# Extract real Phase 7 output
# --------------------------------------------------------------------------

ike_info = result.get(
    "ike_info",
    {},
)

risk = result.get(
    "risk",
    {},
)

traffic_prediction = result.get(
    "traffic_prediction",
    {},
)

if not isinstance(traffic_prediction, dict):
    traffic_prediction = {}


threat_matrix = get_first(
    risk,
    ["threat_matrix"],
    [],
)

# if not threat_matrix:
#     threat_matrix = result.get(
#         "findings",
#         [],
#     )


# Phase 7 stores enrichment notes inside ike_info.
enrichment_notes = ike_info.get(
    "_enrichment_notes",
    [],
)

if not enrichment_notes:
    enrichment_notes = result.get(
        "_enrichment_notes",
        [],
    )


# --------------------------------------------------------------------------
# Header cards
# --------------------------------------------------------------------------

score = get_first(
    risk,
    [
        "security_score",
        "overall_score",
        "score",
    ],
    None,
)

risk_level = get_first(
    risk,
    [
        "risk_level",
        "level",
    ],
    "Unknown",
)

ai_conf = traffic_prediction.get(
    "confidence",
    None,
)

traffic_label = traffic_prediction.get(
    "label",
    "N/A",
)


c1, c2, c3 = st.columns(3)


with c1:

    if isinstance(
        score,
        (int, float),
    ):

        st.metric(
            "Security Score",
            f"{score:.1f}/100",
        )

    else:

        st.metric(
            "Security Score",
            "N/A",
        )


with c2:

    st.metric(
        "Risk Level",
        f"{status_icon(risk_level)} {risk_level}",
    )


with c3:

    if isinstance(
        ai_conf,
        (int, float),
    ):

        confidence_percent = (
            ai_conf * 100
            if ai_conf <= 1
            else ai_conf
        )

        st.metric(
            "AI Confidence",
            f"{confidence_percent:.1f}%",
        )

    else:

        st.metric(
            "AI Confidence",
            "N/A",
        )


# --------------------------------------------------------------------------
# Data provenance
# --------------------------------------------------------------------------

if enrichment_notes:

    with st.expander(
        "⚠️ Data provenance notes "
        "(what was backfilled vs. wire-parsed)"
    ):

        for note in enrichment_notes:

            st.write(
                f"- {note}"
            )


st.divider()


# --------------------------------------------------------------------------
# Protocol Identification
# --------------------------------------------------------------------------

st.subheader(
    "Protocol Identification"
)


protocol_fields = [
    (
        "IKE Version",
        get_first(
            ike_info,
            [
                "ike_version",
                "version",
            ],
        ),
    ),
    (
        "Exchange Type",
        get_first(
            ike_info,
            [
                "exchange_type",
            ],
        ),
    ),
    (
        "Mode",
        get_first(
            ike_info,
            [
                "mode",
            ],
        ),
    ),
    (
        "Encryption",
        get_first(
            ike_info,
            [
                "encryption",
            ],
        ),
    ),
    (
        "Integrity",
        get_first(
            ike_info,
            [
                "integrity",
            ],
        ),
    ),
    (
        "DH Group",
        get_first(
            ike_info,
            [
                "dh_group",
            ],
        ),
    ),
    (
        "PFS",
        get_first(
            ike_info,
            [
                "pfs",
            ],
        ),
    ),
    (
        "Key Lifetime",
        get_first(
            ike_info,
            [
                "key_lifetime_hours",
                "key_lifetime",
                "lifetime",
            ],
        ),
    ),
    (
        "Replay Protection",
        get_first(
            ike_info,
            [
                "replay_protection",
            ],
        ),
    ),
    (
        "IP Version",
        get_first(
            ike_info,
            [
                "ip_version",
            ],
        ),
    ),
]


cols = st.columns(3)


for index, (
    label,
    value,
) in enumerate(protocol_fields):

    with cols[index % 3]:

        st.markdown(
            f"{status_icon(value)} "
            f"**{label}:** "
            f"{format_value(value)}"
        )


st.divider()


# --------------------------------------------------------------------------
# Traffic Analysis
# --------------------------------------------------------------------------

st.subheader(
    "Traffic Analysis"
)


traffic_col1, traffic_col2 = st.columns(
    [1, 2]
)


with traffic_col1:

    st.markdown(
        f"**Predicted type:** "
        f"`{traffic_label}`"
    )

    if traffic_label == "insufficient_data":

        st.warning(
            "Insufficient ESP traffic was available "
            "for a reliable traffic-type prediction."
        )

    if isinstance(
        ai_conf,
        (int, float),
    ):

        confidence_percent = (
            ai_conf * 100
            if ai_conf <= 1
            else ai_conf
        )

        st.progress(
            min(
                confidence_percent / 100,
                1.0,
            ),
            text=(
                f"{confidence_percent:.1f}% confidence"
            ),
        )

    esp_count = result.get(
        "esp_packet_count",
        0,
    )

    st.metric(
        "ESP Packets",
        esp_count,
    )


with traffic_col2:

    chart = build_traffic_chart(
        result
    )

    st.plotly_chart(
        chart,
        use_container_width=True,
    )


st.divider()


# --------------------------------------------------------------------------
# Threat Matrix
# --------------------------------------------------------------------------

st.subheader(
    "Threat Matrix"
)


threat_df = build_threat_dataframe(
    threat_matrix
)


if not threat_df.empty:

    st.dataframe(
        threat_df,
        use_container_width=True,
        hide_index=True,
    )

else:

    st.success(
        "✅ No findings — every assessed parameter "
        "scored Strong."
    )


st.divider()


# --------------------------------------------------------------------------
# Reports — Phase 9 placeholders
# --------------------------------------------------------------------------

st.subheader(
    "Reports"
)


report_col1, report_col2 = st.columns(2)


try:

    from src.reporting.executive_report import (
        generate_executive_report,
    )

    from src.reporting.technical_report import (
        generate_technical_report,
    )

    reports_available = True

except ImportError:

    reports_available = False


with report_col1:

    if reports_available:

        if st.button(
            "Generate Executive Summary PDF",
            use_container_width=True,
        ):

            report_path = (
                generate_executive_report(
                    result
                )
            )

            with open(
                report_path,
                "rb",
            ) as file:

                st.download_button(
                    "Download Executive Summary",
                    file,
                    file_name=os.path.basename(
                        report_path
                    ),
                    mime="application/pdf",
                    use_container_width=True,
                )

    else:

        st.button(
            "Generate Executive Summary PDF",
            disabled=True,
            use_container_width=True,
            help=(
                "Build "
                "src/reporting/executive_report.py "
                "in Phase 9 to enable this."
            ),
        )


with report_col2:

    if reports_available:

        if st.button(
            "Generate Technical Report PDF",
            use_container_width=True,
        ):

            report_path = (
                generate_technical_report(
                    result
                )
            )

            with open(
                report_path,
                "rb",
            ) as file:

                st.download_button(
                    "Download Technical Report",
                    file,
                    file_name=os.path.basename(
                        report_path
                    ),
                    mime="application/pdf",
                    use_container_width=True,
                )

    else:

        st.button(
            "Generate Technical Report PDF",
            disabled=True,
            use_container_width=True,
            help=(
                "Build "
                "src/reporting/technical_report.py "
                "in Phase 9 to enable this."
            ),
        )


# --------------------------------------------------------------------------
# Metadata / Debug
# --------------------------------------------------------------------------

generated_at = get_first(
    result,
    [
        "generated_at",
    ],
    datetime.now(
        timezone.utc
    ).isoformat(),
)


st.caption(
    f"Generated at: {generated_at}"
)


with st.expander(
    "🔧 Raw pipeline output "
    "(debug)"
):

    st.json(
        result
    )