import json
import os
import tempfile

import pandas as pd
import streamlit as st

from core.reporting import generate_html_report
from core.service import analyze_architecture


st.set_page_config(
    page_title="ThreatModel AI",
    page_icon="🧠",
    layout="wide",
)


st.markdown(
    """
    <style>
    .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    .tm-title {
        font-size: 2.7rem;
        font-weight: 800;
        margin-bottom: 0;
    }

    .tm-subtitle {
        color: #94a3b8;
        font-size: 1.05rem;
        margin-bottom: 1.5rem;
    }

    .tm-note {
        background: #172554;
        padding: 14px 18px;
        border-radius: 10px;
        margin-bottom: 20px;
    }

    .risk-card {
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 14px;
        margin-bottom: 12px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


st.markdown(
    '<div class="tm-title">🧠 ThreatModel AI</div>',
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="tm-subtitle">
    Architecture Threat Modeling, STRIDE Analysis,
    Risk Prioritization & Security Controls
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="tm-note">
    ThreatModel AI performs deterministic architecture analysis.
    Projected residual risk assumes recommended controls are
    implemented effectively and does not represent validated
    production control effectiveness.
    </div>
    """,
    unsafe_allow_html=True,
)


st.sidebar.header("Assessment Input")

input_mode = st.sidebar.radio(
    "Choose input source",
    [
        "Cloud Banking Demo",
        "Upload Architecture",
    ],
)


temp_path = None

try:
    if input_mode == "Cloud Banking Demo":
        input_file = (
            "data/banking_architecture.yaml"
        )

        st.sidebar.success(
            "Using built-in Cloud Banking architecture."
        )

    else:
        uploaded_file = st.sidebar.file_uploader(
            "Upload Architecture YAML",
            type=["yaml", "yml"],
        )

        if uploaded_file is None:
            st.info(
                "Upload an architecture YAML file "
                "to begin threat modeling."
            )
            st.stop()

        suffix = os.path.splitext(
            uploaded_file.name
        )[1]

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=suffix,
        ) as temp_file:
            temp_file.write(
                uploaded_file.getvalue()
            )
            temp_path = temp_file.name

        input_file = temp_path


    report = analyze_architecture(
        input_file
    )

    summary = report["summary"]
    architecture = report["architecture"]
    boundaries = report["boundaries"]
    threats = report["threats"]

    if input_mode == "Upload Architecture":
        report["summary"]["input_file"] = (
            uploaded_file.name
        )

    else:
        report["summary"]["input_file"] = (
            "banking_architecture.yaml"
        )


    st.header(
        summary["architecture"]
    )

    st.caption(
        "Security Architecture Threat Model"
    )


    metric_cols = st.columns(6)

    metric_cols[0].metric(
        "Components",
        summary["components"],
    )

    metric_cols[1].metric(
        "Data Flows",
        summary["data_flows"],
    )

    metric_cols[2].metric(
        "Trust Boundaries",
        summary["trust_boundaries"],
    )

    metric_cols[3].metric(
        "Threats",
        summary["threats"],
    )

    metric_cols[4].metric(
        "Highest Risk",
        f"{summary['highest_risk']}/25",
    )

    metric_cols[5].metric(
        "P1 Threats",
        summary["priorities"]["P1"],
    )


    st.divider()

    st.subheader(
        "Architecture Overview"
    )

    component_rows = []

    for component in architecture[
        "components"
    ]:
        component_rows.append(
            {
                "Component": component["name"],
                "Type": component["type"],
                "Trust Zone": component[
                    "trust_zone"
                ],
                "Internet Exposed": component[
                    "internet_exposed"
                ],
                "Sensitive Data": component[
                    "stores_sensitive_data"
                ],
            }
        )

    components_df = pd.DataFrame(
        component_rows
    )

    st.dataframe(
        components_df,
        use_container_width=True,
        hide_index=True,
    )


    st.subheader(
        "Data Flow Overview"
    )

    flow_rows = []

    for flow in architecture[
        "data_flows"
    ]:
        flow_rows.append(
            {
                "Flow": flow["id"],
                "Source": flow["source"],
                "Destination": flow[
                    "destination"
                ],
                "Protocol": flow["protocol"],
                "Encrypted": flow[
                    "encrypted"
                ],
                "Authenticated": flow[
                    "authentication"
                ],
                "Sensitive Data": flow[
                    "sensitive_data"
                ],
            }
        )

    flows_df = pd.DataFrame(
        flow_rows
    )

    st.dataframe(
        flows_df,
        use_container_width=True,
        hide_index=True,
    )


    st.divider()

    st.subheader(
        "Trust Boundary Analysis"
    )

    boundaries_df = pd.DataFrame(
        boundaries
    )

    if not boundaries_df.empty:
        boundaries_df = boundaries_df.rename(
            columns={
                "flow_id": "Flow",
                "source": "Source",
                "destination": "Destination",
                "source_zone": "Source Zone",
                "destination_zone":
                    "Destination Zone",
                "encrypted": "Encrypted",
                "authentication":
                    "Authenticated",
                "sensitive_data":
                    "Sensitive Data",
            }
        )

        st.dataframe(
            boundaries_df,
            use_container_width=True,
            hide_index=True,
        )

    else:
        st.info(
            "No trust boundary crossings detected."
        )


    st.divider()

    st.subheader(
        "STRIDE Threat Distribution"
    )

    if threats:
        category_counts = (
            pd.DataFrame(threats)[
                "category"
            ]
            .value_counts()
            .rename_axis("Threat Category")
            .reset_index(name="Count")
        )

        st.bar_chart(
            category_counts,
            x="Threat Category",
            y="Count",
        )


    st.subheader(
        "Risk Prioritization"
    )

    priority_data = pd.DataFrame(
        {
            "Priority": [
                "P1",
                "P2",
                "P3",
                "P4",
                "P5",
            ],
            "Count": [
                summary["priorities"]["P1"],
                summary["priorities"]["P2"],
                summary["priorities"]["P3"],
                summary["priorities"]["P4"],
                summary["priorities"]["P5"],
            ],
        }
    )

    st.bar_chart(
        priority_data,
        x="Priority",
        y="Count",
    )


    st.divider()

    st.subheader(
        "Top Threats"
    )

    for index, threat in enumerate(
        threats,
        start=1,
    ):
        title = (
            f"{index}. "
            f"{threat['category']} "
            f"— {threat['target']} "
            f"[{threat['priority']} | "
            f"{threat['severity']}]"
        )

        with st.expander(
            title,
            expanded=(
                threat["priority"] == "P1"
            ),
        ):
            threat_cols = st.columns(4)

            threat_cols[0].metric(
                "Likelihood",
                threat["likelihood"],
            )

            threat_cols[1].metric(
                "Impact",
                threat["impact"],
            )

            threat_cols[2].metric(
                "Inherent Risk",
                f"{threat['inherent_risk']}/25",
            )

            threat_cols[3].metric(
                "Projected Residual",
                f"{threat['residual_risk']}/25",
            )

            st.write(
                threat["description"]
            )

            st.markdown(
                "**Recommended Controls**"
            )

            for control in threat[
                "recommended_controls"
            ]:
                st.write(
                    f"- **{control['id']} — "
                    f"{control['name']}**: "
                    f"{control['description']}"
                )

            st.caption(
                "Projected residual severity: "
                f"{threat['residual_severity']}"
            )


    st.divider()

    st.subheader(
        "Threat Register"
    )

    threat_rows = []

    for threat in threats:
        threat_rows.append(
            {
                "Threat": threat[
                    "category"
                ],
                "Target": threat["target"],
                "Priority": threat[
                    "priority"
                ],
                "Severity": threat[
                    "severity"
                ],
                "Likelihood": threat[
                    "likelihood"
                ],
                "Impact": threat["impact"],
                "Inherent Risk": threat[
                    "inherent_risk"
                ],
                "Residual Risk": threat[
                    "residual_risk"
                ],
                "Residual Severity":
                    threat[
                        "residual_severity"
                    ],
            }
        )

    threat_df = pd.DataFrame(
        threat_rows
    )

    priority_filter = st.multiselect(
        "Filter by Priority",
        options=[
            "P1",
            "P2",
            "P3",
            "P4",
            "P5",
        ],
        default=[
            "P1",
            "P2",
            "P3",
            "P4",
            "P5",
        ],
    )

    severity_filter = st.multiselect(
        "Filter by Severity",
        options=[
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
        ],
        default=[
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
        ],
    )

    filtered_df = threat_df[
        threat_df[
            "Priority"
        ].isin(priority_filter)
        & threat_df[
            "Severity"
        ].isin(severity_filter)
    ]

    st.dataframe(
        filtered_df,
        use_container_width=True,
        hide_index=True,
    )


    st.divider()

    st.subheader(
        "Assessment Reports"
    )

    report_json = json.dumps(
        report,
        indent=2,
    )

    html_report = generate_html_report(
        report
    )

    download_cols = st.columns(2)

    download_cols[0].download_button(
        label="Download JSON Report",
        data=report_json,
        file_name=(
            "threatmodel-security-report.json"
        ),
        mime="application/json",
        use_container_width=True,
    )

    download_cols[1].download_button(
        label="Download HTML Report",
        data=html_report,
        file_name=(
            "threatmodel-security-report.html"
        ),
        mime="text/html",
        use_container_width=True,
    )


    st.divider()

    st.caption(
        "ThreatModel AI — Architecture Threat Modeling "
        "and Risk Analysis. Synthetic demonstration "
        "data is used in the built-in banking scenario."
    )


finally:
    if temp_path and os.path.exists(
        temp_path
    ):
        os.remove(temp_path)