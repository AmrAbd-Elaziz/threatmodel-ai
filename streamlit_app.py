# ============================================================
# 1. IMPORTS
# ============================================================

import json
import os
import tempfile

import pandas as pd
import streamlit as st
from graphviz import Digraph

from core.reporting import generate_html_report
from core.service import analyze_architecture


# ============================================================
# 2. PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="ThreatModel AI",
    page_icon="🧠",
    layout="wide",
)


# ============================================================
# 3. UI STYLING
# ============================================================

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


# ============================================================
# 4. APPLICATION HEADER
# ============================================================

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


# ============================================================
# 5. SIDEBAR & INPUT SELECTION
# ============================================================

st.sidebar.header("Assessment Input")

input_mode = st.sidebar.radio(
    "Choose input source",
    [
        "Cloud Banking Demo",
        "Upload Architecture",
    ],
)


# ============================================================
# 6. INPUT PROCESSING & SECURITY ANALYSIS
# ============================================================

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


    # ========================================================
    # 7. ASSESSMENT SUMMARY
    # ========================================================

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


    # ========================================================
    # 8. ARCHITECTURE OVERVIEW
    # ========================================================

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


    # ========================================================
    # 9. ARCHITECTURE & ATTACK PATH VISUALIZATION
    # ========================================================

    st.subheader(
        "Architecture & Attack Paths"
    )

    st.caption(
        "Components are grouped conceptually by trust zone. "
        "Edges represent configured application data flows."
    )

    graph = Digraph(
        "threatmodel_architecture"
    )

    graph.attr(
        rankdir="LR",
        bgcolor="transparent",
        pad="0.4",
        nodesep="0.6",
        ranksep="0.8",
    )

    graph.attr(
        "node",
        shape="box",
        style="rounded,filled",
        fillcolor="#1e293b",
        color="#475569",
        fontcolor="white",
        fontname="Arial",
        margin="0.18",
    )

    graph.attr(
        "edge",
        color="#64748b",
        fontcolor="#94a3b8",
        fontname="Arial",
        arrowsize="0.8",
    )

    for component in architecture[
        "components"
    ]:
        component_label = (
            f"{component['name']}\n"
            f"{component['type']}\n"
            f"Zone: {component['trust_zone']}"
        )

        graph.node(
            component["id"],
            component_label,
        )

    for flow in architecture[
        "data_flows"
    ]:
        flow_label = flow["protocol"]

        if flow["sensitive_data"]:
            flow_label += "\nSensitive Data"

        graph.edge(
            flow["source"],
            flow["destination"],
            label=flow_label,
        )

    st.graphviz_chart(
        graph,
        use_container_width=True,
    )


    # ========================================================
    # 10. DATA FLOW OVERVIEW
    # ========================================================

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


    # ========================================================
    # 11. TRUST BOUNDARY ANALYSIS
    # ========================================================

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


    # ========================================================
    # 12. STRIDE THREAT DISTRIBUTION
    # ========================================================

    st.subheader(
        "STRIDE Threat Distribution"
    )

    if threats:
        category_counts = (
            pd.DataFrame(threats)[
                "category"
            ]
            .value_counts()
            .rename_axis(
                "Threat Category"
            )
            .reset_index(
                name="Count"
            )
        )

        st.bar_chart(
            category_counts,
            x="Threat Category",
            y="Count",
        )


    # ========================================================
    # 13. RISK PRIORITIZATION
    # ========================================================

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


    # ========================================================
    # 14. VISUAL 5x5 RISK MATRIX
    # ========================================================

    st.subheader("5×5 Threat Risk Matrix")

    st.caption(
        "Threats are positioned by likelihood × impact. "
        "Colors represent inherent risk severity and the "
        "number in each cell shows identified threats."
    )

    matrix_counts = {}

    for threat in threats:
        position = (
            threat["likelihood"],
            threat["impact"],
        )

        matrix_counts[position] = (
            matrix_counts.get(position, 0) + 1
        )

    def matrix_color(score):
        if score >= 20:
            return "#7f1d1d"

        if score >= 15:
            return "#b91c1c"

        if score >= 10:
            return "#c2410c"

        if score >= 5:
            return "#a16207"

        return "#166534"

    html = """
    <div style="
        display:grid;
        grid-template-columns:70px repeat(5, 1fr);
        gap:5px;
        width:100%;
        margin-top:20px;
    ">
    """

    html += """
    <div></div>
    """

    for impact in range(1, 6):
        html += f"""
        <div style="
            text-align:center;
            font-weight:700;
            padding:8px;
        ">
            Impact {impact}
        </div>
        """

    for likelihood in range(5, 0, -1):

        html += f"""
        <div style="
            display:flex;
            align-items:center;
            justify-content:center;
            font-weight:700;
        ">
            L{likelihood}
        </div>
        """

        for impact in range(1, 6):
            score = likelihood * impact

            count = matrix_counts.get(
                (likelihood, impact),
                0,
            )

            background = matrix_color(
                score
            )

            html += f"""
            <div style="
                background:{background};
                border:1px solid #475569;
                border-radius:8px;
                min-height:80px;
                display:flex;
                flex-direction:column;
                align-items:center;
                justify-content:center;
            ">
                <div style="
                    font-size:13px;
                    opacity:0.8;
                ">
                    {score}/25
                </div>

                <div style="
                    font-size:28px;
                    font-weight:800;
                ">
                    {count}
                </div>

                <div style="
                    font-size:11px;
                    opacity:0.75;
                ">
                    threat{"s" if count != 1 else ""}
                </div>
            </div>
            """

    html += "</div>"

    html += """
    <div style="
        text-align:center;
        margin-top:12px;
        font-weight:600;
    ">
        Impact →
    </div>
    """

    st.markdown(
        html,
        unsafe_allow_html=True,
    )

    st.markdown("#### Highest-Risk Positions")

    sorted_positions = sorted(
        matrix_counts.items(),
        key=lambda item:
            item[0][0] * item[0][1],
        reverse=True,
    )

    for (
        likelihood,
        impact,
    ), count in sorted_positions:

        score = likelihood * impact

        matching_threats = [
            threat
            for threat in threats
            if threat["likelihood"] == likelihood
            and threat["impact"] == impact
        ]

        with st.expander(
            f"L{likelihood} × I{impact} "
            f"= {score}/25 "
            f"— {count} threat"
            f"{'s' if count != 1 else ''}",
            expanded=(score >= 20),
        ):
            for threat in matching_threats:
                st.markdown(
                    f"**{threat['category']} → "
                    f"{threat['target']}**  \n"
                    f"{threat['priority']} · "
                    f"{threat['severity']} · "
                    f"Projected residual: "
                    f"{threat['residual_risk']}/25"
                )

    st.divider()

    # ========================================================
    # 15. TOP THREATS & ATTACK SCENARIOS
    # ========================================================

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


    # ========================================================
    # 16. THREAT REGISTER & FILTERING
    # ========================================================

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
                "Target": threat[
                    "target"
                ],
                "Priority": threat[
                    "priority"
                ],
                "Severity": threat[
                    "severity"
                ],
                "Likelihood": threat[
                    "likelihood"
                ],
                "Impact": threat[
                    "impact"
                ],
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


    # ========================================================
    # 17. REPORT GENERATION & DOWNLOADS
    # ========================================================

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


    # ========================================================
    # 18. FOOTER
    # ========================================================

    st.caption(
        "ThreatModel AI — Architecture Threat Modeling "
        "and Risk Analysis. Synthetic demonstration "
        "data is used in the built-in banking scenario."
    )


# ============================================================
# 19. TEMPORARY FILE CLEANUP
# ============================================================

finally:
    if temp_path and os.path.exists(
        temp_path
    ):
        os.remove(temp_path)