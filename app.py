"""
IPsec VPN Analyzer — Streamlit Dashboard

Phase 8:
    Streamlit dashboard for the IPsec VPN analyzer.

Phase 9:
    Integrated Executive and Technical PDF report generation.

The dashboard is built against the actual Phase 7 analyze_pcap()
output rather than the original idealized implementation.md shape.
"""

import glob
import os
import sys
from datetime import datetime, timezone

import pandas as pd
import plotly.graph_objects as go
import streamlit as st


# --------------------------------------------------------------------------
# Python path
# --------------------------------------------------------------------------

sys.path.insert(
    0,
    os.path.dirname(
        os.path.abspath(__file__)
    ),
)


# --------------------------------------------------------------------------
# Streamlit configuration
# --------------------------------------------------------------------------

st.set_page_config(
    page_title="IPsec VPN Analyzer",
    page_icon="🔐",
    layout="wide",
)


# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------

PCAP_DIR = "data/pcaps"
LABELS_CSV = "data/labels.csv"
REPORT_DIR = "reports"


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def get_first(d, keys, default="N/A"):
    """
    Look up the first available key from a list of candidate names.

    Supports direct dictionary keys.
    """

    if not isinstance(d, dict):
        return default

    for key in keys:

        if (
            key in d
            and d[key] not in (None, "")
        ):
            return d[key]

    return default


def status_icon(value):
    """Return a simple status icon for common security values."""

    if value in (
        "Strong",
        "Enabled",
        "IKEv2",
        "Tunnel",
        "Low",
        True,
    ):
        return "🟢"

    if value in (
        "Medium",
        "1536-bit",
    ):
        return "🟡"

    if value in (
        "Weak",
        "Disabled",
        "IKEv1",
        "Critical",
        "High",
        False,
    ):
        return "🔴"

    return "⚪"


def confidence_percent(value):
    """
    Convert a model confidence value to a percentage.

    Actual pipeline values are normally decimals:

        0.90 -> 90.0%

    Already-converted percentages are also accepted.
    """

    if not isinstance(
        value,
        (int, float),
    ):
        return None

    if 0 <= value <= 1:
        return value * 100

    return float(value)


# --------------------------------------------------------------------------
# Pipeline loader
# --------------------------------------------------------------------------

@st.cache_resource(
    show_spinner=False
)
def load_pipeline():
    """
    Import analyze_pcap lazily.
    """

    try:

        from src.pipeline import analyze_pcap

    except ImportError as exc:

        st.error(
            "Could not import `analyze_pcap` from "
            "`src/pipeline.py`.\n\n"
            "Make sure the Phase 6/7 pipeline is present "
            "in this checkout.\n\n"
            f"Import error: {exc}"
        )

        st.stop()

    return analyze_pcap


# --------------------------------------------------------------------------
# Scenario loading
# --------------------------------------------------------------------------

def list_bundled_scenarios():
    """
    Load bundled scenarios from labels.csv.

    Falls back to scanning data/pcaps if labels.csv cannot be read.
    """

    if os.path.exists(
        LABELS_CSV
    ):

        try:

            dataframe = pd.read_csv(
                LABELS_CSV
            )

            if "pcap_path" in dataframe.columns:
                return dataframe

        except Exception:
            pass

    paths = sorted(
        glob.glob(
            os.path.join(
                PCAP_DIR,
                "*.pcap",
            )
        )
    )

    return pd.DataFrame(
        {
            "scenario_id": [
                os.path.basename(path)
                for path in paths
            ],
            "pcap_path": paths,
        }
    )


# --------------------------------------------------------------------------
# Sidebar
# --------------------------------------------------------------------------

st.sidebar.title(
    "🔐 IPsec VPN Analyzer"
)

st.sidebar.caption(
    "AI-Powered Security Assessment Framework"
)

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
            f"No scenarios found in "
            f"{LABELS_CSV} or {PCAP_DIR}/"
        )

    else:

        if "scenario_id" in scenarios_df.columns:
            label_col = "scenario_id"
        else:
            label_col = scenarios_df.columns[0]

        choice = st.sidebar.selectbox(
            "Scenario",
            scenarios_df[
                label_col
            ].tolist(),
        )

        selected_scenario = str(
            choice
        )

        row = scenarios_df[
            scenarios_df[
                label_col
            ] == choice
        ].iloc[0]

        pcap_path = row.get(
            "pcap_path",
            os.path.join(
                PCAP_DIR,
                f"{choice}.pcap",
            ),
        )

        with st.sidebar.expander(
            "Ground truth (labels.csv)"
        ):

            st.write(
                row.to_dict()
            )


else:

    uploaded = st.sidebar.file_uploader(
        "Upload a .pcap file",
        type=[
            "pcap",
            "pcapng",
        ],
    )

    if uploaded is not None:

        os.makedirs(
            os.path.join(
                PCAP_DIR,
                "_uploaded",
            ),
            exist_ok=True,
        )

        pcap_path = os.path.join(
            PCAP_DIR,
            "_uploaded",
            uploaded.name,
        )

        selected_scenario = (
            os.path.splitext(
                uploaded.name
            )[0]
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
    "Traffic-type prediction is based on "
    "encrypted-flow metadata "
    "(packet size/timing), not decrypted payload."
)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

st.title(
    "IPsec VPN Protocol Analyzer"
)


# --------------------------------------------------------------------------
# Persist analysis results across Streamlit reruns
# --------------------------------------------------------------------------

if "analysis_result" not in st.session_state:
    st.session_state.analysis_result = None

if "analysis_pcap_path" not in st.session_state:
    st.session_state.analysis_pcap_path = None

if "analysis_scenario" not in st.session_state:
    st.session_state.analysis_scenario = None


# --------------------------------------------------------------------------
# Run analysis only when Analyze is clicked
# --------------------------------------------------------------------------

if analyze_clicked:

    if not pcap_path:

        st.info(
            "Pick a scenario (or upload a pcap) "
            "in the sidebar, then click **Analyze**."
        )

        st.stop()

    if not os.path.exists(
        pcap_path
    ):

        st.error(
            f"PCAP not found on disk: `{pcap_path}`"
        )

        st.stop()

    analyze_pcap = load_pipeline()

    with st.spinner(
        "Parsing pcap, running classifier, "
        "scoring security posture..."
    ):

        try:

            result = analyze_pcap(
                pcap_path
            )

        except Exception as exc:

            st.error(
                f"analyze_pcap() raised an exception: {exc}"
            )

            st.exception(
                exc
            )

            st.stop()

    if not isinstance(
        result,
        dict,
    ):

        st.error(
            "The pipeline did not return a dictionary."
        )

        st.stop()

    # Store result in Streamlit session state.
    # This is essential because every Streamlit button click
    # causes the script to rerun.
    st.session_state.analysis_result = result
    st.session_state.analysis_pcap_path = pcap_path
    st.session_state.analysis_scenario = selected_scenario


# --------------------------------------------------------------------------
# Recover previous analysis after a Streamlit rerun
# --------------------------------------------------------------------------

result = st.session_state.analysis_result


if result is None:

    st.info(
        "Pick a scenario (or upload a pcap) "
        "in the sidebar, then click **Analyze**."
    )

    st.stop()


if st.session_state.analysis_scenario:

    selected_scenario = (
        st.session_state.analysis_scenario
    )


if st.session_state.analysis_pcap_path:

    pcap_path = (
        st.session_state.analysis_pcap_path
    )


# --------------------------------------------------------------------------
# Extract actual Phase 7 output
# --------------------------------------------------------------------------

ike_info = result.get(
    "ike_info",
    {},
) or {}

risk = result.get(
    "risk",
    {},
) or {}

traffic_prediction = result.get(
    "traffic_prediction",
    {},
) or {}

threat_matrix = risk.get(
    "threat_matrix",
    [],
) or []

enrichment_notes = ike_info.get(
    "_enrichment_notes",
    [],
) or []


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


ai_conf = get_first(
    traffic_prediction,
    [
        "confidence",
    ],
    None,
)


ai_conf_percent = confidence_percent(
    ai_conf
)


c1, c2, c3 = st.columns(
    3
)


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
        f"{status_icon(risk_level)} "
        f"{risk_level}",
    )


with c3:

    if ai_conf_percent is not None:

        st.metric(
            "AI Confidence",
            f"{ai_conf_percent:.1f}%",
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
# Protocol identification
# --------------------------------------------------------------------------

st.subheader(
    "Protocol Identification"
)


key_lifetime = get_first(
    ike_info,
    [
        "key_lifetime_hours",
        "key_lifetime",
        "lifetime",
    ],
    "N/A",
)


if key_lifetime != "N/A":

    key_lifetime_display = (
        f"{key_lifetime} hours"
    )

else:

    key_lifetime_display = "N/A"


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
        key_lifetime_display,
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


cols = st.columns(
    3
)


for index, (
    label,
    value,
) in enumerate(
    protocol_fields
):

    with cols[
        index % 3
    ]:

        st.markdown(
            f"{status_icon(value)} "
            f"**{label}:** {value}"
        )


st.divider()


# --------------------------------------------------------------------------
# Traffic analysis
# --------------------------------------------------------------------------

st.subheader(
    "Traffic Analysis"
)


tcol1, tcol2 = st.columns(
    [1, 2]
)


with tcol1:

    traffic_label = get_first(
        traffic_prediction,
        [
            "label",
            "prediction",
            "traffic_type",
        ],
        "N/A",
    )

    if traffic_prediction:

        st.markdown(
            f"**Predicted type:** "
            f"`{traffic_label}`"
        )

        if ai_conf_percent is not None:

            st.progress(
                min(
                    ai_conf_percent / 100,
                    1.0,
                ),
                text=(
                    f"{ai_conf_percent:.1f}% "
                    "confidence"
                ),
            )

        esp_packet_count = result.get(
            "esp_packet_count",
            0,
        )

        st.metric(
            "ESP Packets",
            str(
                esp_packet_count
            ),
        )

        if traffic_label == "insufficient_data":

            st.warning(
                "Insufficient ESP traffic was available "
                "for a reliable traffic classification."
            )

    else:

        st.warning(
            "No traffic prediction returned."
        )


with tcol2:

    packet_sizes = result.get(
        "packet_sizes"
    )

    if (
        isinstance(
            packet_sizes,
            list,
        )
        and packet_sizes
    ):

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
            xaxis_title="Packet size (bytes)",
            yaxis_title="Count",
            height=300,
            margin=dict(
                l=10,
                r=10,
                t=40,
                b=10,
            ),
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
        )

    else:

        st.caption(
            "No per-packet size series is exposed "
            "by the current pipeline output. "
            "The traffic prediction shown here is "
            "based on the existing ESP-flow feature "
            "extraction and classifier."
        )


st.divider()


# --------------------------------------------------------------------------
# Threat matrix
# --------------------------------------------------------------------------

st.subheader(
    "Threat Matrix"
)


if threat_matrix:

    rows = []

    for entry in threat_matrix:

        if isinstance(
            entry,
            dict,
        ):

            rows.append(
                {
                    "Parameter": get_first(
                        entry,
                        [
                            "parameter",
                        ],
                    ),
                    "Finding": get_first(
                        entry,
                        [
                            "finding",
                            "note",
                        ],
                    ),
                    "Severity": get_first(
                        entry,
                        [
                            "severity",
                        ],
                    ),
                    "Recommendation": get_first(
                        entry,
                        [
                            "recommendation",
                        ],
                    ),
                }
            )


    if rows:

        dataframe = pd.DataFrame(
            rows
        )

        severity_order = {
            "Critical": 0,
            "High": 1,
            "Medium": 2,
            "Low": 3,
        }

        dataframe[
            "_sort"
        ] = dataframe[
            "Severity"
        ].map(
            severity_order
        ).fillna(
            9
        )

        dataframe = (
            dataframe
            .sort_values(
                "_sort"
            )
            .drop(
                columns="_sort"
            )
        )

        st.dataframe(
            dataframe,
            use_container_width=True,
            hide_index=True,
        )

    else:

        st.success(
            "No structured threat-matrix entries."
        )

else:

    st.success(
        "✅ No findings — every parameter "
        "scored Strong."
    )


st.divider()


# --------------------------------------------------------------------------
# Reports — Phase 9
# --------------------------------------------------------------------------

st.subheader(
    "Reports"
)


rcol1, rcol2 = st.columns(
    2
)


try:

    from src.reporting.executive_report import (
        generate_executive_report,
    )

    from src.reporting.technical_report import (
        generate_technical_report,
    )

    reports_available = True

except ImportError as exc:

    reports_available = False
    report_import_error = exc


os.makedirs(
    REPORT_DIR,
    exist_ok=True,
)


if not selected_scenario:

    selected_scenario = os.path.splitext(
        os.path.basename(
            pcap_path
        )
    )[0]


# --------------------------------------------------------------------------
# Executive report
# --------------------------------------------------------------------------

with rcol1:

    if reports_available:

        if st.button(
            "Generate Executive Summary PDF",
            use_container_width=True,
        ):

            executive_path = os.path.join(
                REPORT_DIR,
                f"{selected_scenario}_executive.pdf",
            )

            try:

                generate_executive_report(
                    result,
                    executive_path,
                    scenario_name=selected_scenario,
                )

                with open(
                    executive_path,
                    "rb",
                ) as pdf_file:

                    pdf_bytes = pdf_file.read()

                st.success(
                    "Executive report generated successfully."
                )

                st.download_button(
                    "⬇️ Download Executive Summary",
                    data=pdf_bytes,
                    file_name=os.path.basename(
                        executive_path
                    ),
                    mime="application/pdf",
                    use_container_width=True,
                )

            except Exception as exc:

                st.error(
                    "Could not generate the executive report."
                )

                st.exception(
                    exc
                )

    else:

        st.button(
            "Generate Executive Summary PDF",
            disabled=True,
            use_container_width=True,
        )

        st.error(
            f"Reporting modules could not be imported: "
            f"{report_import_error}"
        )


# --------------------------------------------------------------------------
# Technical report
# --------------------------------------------------------------------------

with rcol2:

    if reports_available:

        if st.button(
            "Generate Technical Report PDF",
            use_container_width=True,
        ):

            technical_path = os.path.join(
                REPORT_DIR,
                f"{selected_scenario}_technical.pdf",
            )

            try:

                generate_technical_report(
                    result,
                    technical_path,
                    scenario_name=selected_scenario,
                )

                with open(
                    technical_path,
                    "rb",
                ) as pdf_file:

                    pdf_bytes = pdf_file.read()

                st.success(
                    "Technical report generated successfully."
                )

                st.download_button(
                    "⬇️ Download Technical Report",
                    data=pdf_bytes,
                    file_name=os.path.basename(
                        technical_path
                    ),
                    mime="application/pdf",
                    use_container_width=True,
                )

            except Exception as exc:

                st.error(
                    "Could not generate the technical report."
                )

                st.exception(
                    exc
                )


# --------------------------------------------------------------------------
# Generated timestamp
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


# --------------------------------------------------------------------------
# Raw pipeline output
# --------------------------------------------------------------------------

with st.expander(
    "🔧 Raw pipeline output "
    "(debug)"
):

    st.json(
        result
    )