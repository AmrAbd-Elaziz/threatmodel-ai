# ============================================================
# 1. IMPORTS
# ============================================================

import json
import os
import tempfile

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from graphviz import Digraph

from core.reporting import generate_html_report
from core.service import analyze_architecture
from core.assessment_history import create_assessment_snapshot, compare_assessments
from core.finding_reconciliation import reconcile_findings, reconciliation_summary


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
    # 9.1 HIGHEST-RISK ATTACK PATH
    # ========================================================

    attack_paths = report.get(
        "attack_paths",
        [],
    )

    if attack_paths:
        highest_path = max(
            attack_paths,
            key=lambda item:
                item.get(
                    "path_risk",
                    0,
                ),
        )

        st.markdown(
            "### 🚨 Highest-Risk Attack Path"
        )

        st.caption(
            "Architecture-level attack path analysis "
            "showing exposure, trust-boundary "
            "crossings, associated threats, declared "
            "controls, and estimated residual risk."
        )

        path_cols = st.columns(4)

        path_cols[0].metric(
            "Entry Point",
            highest_path[
                "entry_point"
            ],
        )

        path_cols[1].metric(
            "Critical Asset",
            highest_path[
                "critical_asset"
            ],
        )

        path_cols[2].metric(
            "Inherent Path Risk",
            (
                f"{highest_path[
                    'path_risk'
                ]}/25"
            ),
        )

        path_cols[3].metric(
            "Priority",
            highest_path.get(
                "path_priority",
                highest_path.get(
                    "priority",
                    "N/A",
                ),
            ),
        )

        st.markdown(
            "**Attack Path**"
        )

        path_display = "  →  ".join(
            highest_path["nodes"]
        )

        component_map = {
            component["id"]: component
            for component in architecture[
                "components"
            ]
        }

        path_graph = Digraph(
            "highest_risk_attack_path"
        )

        path_graph.attr(
            rankdir="LR",
            bgcolor="transparent",
            pad="0.35",
            nodesep="0.55",
            ranksep="0.75",
        )

        path_graph.attr(
            "node",
            shape="box",
            style="rounded,filled",
            fontcolor="white",
            fontname="Arial",
            penwidth="2",
            margin="0.22",
        )

        path_graph.attr(
            "edge",
            color="#f59e0b",
            fontcolor="#cbd5e1",
            fontname="Arial",
            penwidth="2",
            arrowsize="0.9",
        )

        for index, node_id in enumerate(
            highest_path["nodes"]
        ):
            component = component_map.get(
                node_id,
                {},
            )

            name = component.get(
                "name",
                node_id,
            )

            zone = component.get(
                "trust_zone",
                "unknown",
            )

            criticality = component.get(
                "criticality",
                "medium",
            ).upper()

            classification = component.get(
                "data_classification",
                "internal",
            ).upper()

            if index == 0:
                role = "ENTRY POINT"
                fillcolor = "#7f1d1d"
                bordercolor = "#ef4444"

            elif index == (
                len(
                    highest_path["nodes"]
                ) - 1
            ):
                role = "CRITICAL ASSET"
                fillcolor = "#581c87"
                bordercolor = "#c084fc"

            else:
                role = "ATTACK PATH"
                fillcolor = "#1e3a5f"
                bordercolor = "#38bdf8"

            node_label = (
                f"{role}\n"
                f"{name}\n"
                f"Zone: {zone}\n"
                f"Criticality: {criticality}\n"
                f"Data: {classification}"
            )

            path_graph.node(
                node_id,
                node_label,
                fillcolor=fillcolor,
                color=bordercolor,
            )

        for source, destination in zip(
            highest_path["nodes"],
            highest_path["nodes"][1:],
        ):
            source_component = (
                component_map.get(
                    source,
                    {},
                )
            )

            destination_component = (
                component_map.get(
                    destination,
                    {},
                )
            )

            matching_flow = next(
                (
                    flow
                    for flow in architecture[
                        "data_flows"
                    ]
                    if flow["source"] == source
                    and flow[
                        "destination"
                    ] == destination
                ),
                None,
            )

            edge_labels = []

            if matching_flow:
                edge_labels.append(
                    matching_flow[
                        "protocol"
                    ]
                )

                if matching_flow.get(
                    "sensitive_data"
                ):
                    edge_labels.append(
                        "Sensitive Data"
                    )

            if (
                source_component.get(
                    "trust_zone"
                )
                != destination_component.get(
                    "trust_zone"
                )
            ):
                edge_labels.append(
                    "Trust Boundary"
                )

            path_graph.edge(
                source,
                destination,
                label="\n".join(
                    edge_labels
                ),
            )

        st.graphviz_chart(
            path_graph,
            use_container_width=True,
        )

        st.caption(
            "Path: "
            + path_display
        )

        detail_cols = st.columns(4)

        detail_cols[0].metric(
            "Trust Boundaries",
            highest_path[
                "boundary_crossings"
            ],
        )

        detail_cols[1].metric(
            "Threats Along Path",
            highest_path[
                "threat_count"
            ],
        )

        control_summary = (
            highest_path.get(
                "control_summary",
                {},
            )
        )

        detail_cols[2].metric(
            "Control Coverage",
            (
                f"{control_summary.get(
                    'coverage_percentage',
                    0,
                )}%"
            ),
        )

        detail_cols[3].metric(
            "Estimated Residual Risk",
            (
                f"{highest_path.get(
                    'residual_path_risk',
                    highest_path[
                        'path_risk'
                    ],
                )}/25"
            ),
        )

        residual_severity = (
            highest_path.get(
                "residual_path_severity",
                "N/A",
            )
        )

        residual_priority = (
            highest_path.get(
                "residual_path_priority",
                "N/A",
            )
        )

        st.info(
            "Estimated residual risk based on "
            "declared existing controls: "
            f"{highest_path.get(
                'residual_path_risk',
                highest_path['path_risk'],
            )}/25 "
            f"({residual_severity}, "
            f"{residual_priority})."
        )

        control_gaps = (
            highest_path.get(
                "control_gaps",
                [],
            )
        )

        st.markdown(
            "#### Control Gaps"
        )

        if control_gaps:
            gap_rows = []

            for gap in control_gaps:
                gap_rows.append(
                    {
                        "Control": (
                            gap["id"]
                        ),
                        "Control Name": (
                            gap["name"]
                        ),
                        "Status": (
                            gap["status"]
                        ),
                        "Effectiveness": (
                            gap[
                                "effectiveness"
                            ]
                        ),
                        "Component": (
                            gap.get(
                                "component_id"
                            )
                            or highest_path[
                                "critical_asset"
                            ]
                        ),
                    }
                )

            st.dataframe(
                pd.DataFrame(
                    gap_rows
                ),
                use_container_width=True,
                hide_index=True,
            )

        else:
            st.success(
                "No declared control gaps "
                "were identified for this "
                "attack path."
            )

        with st.expander(
            "Why is this path high risk?"
        ):
            risk_drivers = (
                highest_path.get(
                    "risk_drivers",
                    [],
                )
            )

            if risk_drivers:
                for driver in risk_drivers:
                    st.markdown(
                        f"- {driver}"
                    )
            else:
                st.write(
                    highest_path.get(
                        "analysis_basis",
                        "Architecture-driven "
                        "risk analysis.",
                    )
                )

            st.caption(
                "This represents a plausible "
                "architecture attack path, not "
                "a confirmed exploit chain."
            )

    else:
        st.info(
            "No architecture attack paths "
            "were identified."
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

    matrix_html = """
    <style>
        html,
        body {
            margin: 0;
            padding: 0;
            background: transparent;
            color: #f8fafc;
            font-family:
                Inter,
                system-ui,
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                sans-serif;
        }
    </style>
    """ + html

    components.html(
        matrix_html,
        height=575,
        scrolling=False,
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
    # 17. CONTINUOUS ASSESSMENT & REMEDIATION TREND
    # ========================================================

    st.subheader(
        "Continuous Assessment & Remediation"
    )

    baseline_file = (
        "data/banking_architecture.yaml"
    )

    remediated_file = (
        "data/"
        "banking_architecture_remediated.yaml"
    )

    if (
        os.path.exists(baseline_file)
        and os.path.exists(remediated_file)
    ):
        baseline_report = (
            analyze_architecture(
                baseline_file
            )
        )

        remediated_report = (
            analyze_architecture(
                remediated_file
            )
        )

        baseline_snapshot = (
            create_assessment_snapshot(
                baseline_report,
                "A-001",
            )
        )

        remediated_snapshot = (
            create_assessment_snapshot(
                remediated_report,
                "A-002",
            )
        )

        assessment_comparison = (
            compare_assessments(
                baseline_snapshot,
                remediated_snapshot,
            )
        )

        finding_reconciliation = (
            reconcile_findings(
                baseline_report[
                    "findings"
                ],
                remediated_report[
                    "findings"
                ],
            )
        )

        finding_summary = (
            reconciliation_summary(
                finding_reconciliation
            )
        )

        trend_cols = st.columns(4)

        trend_cols[0].metric(
            "Baseline Coverage",
            (
                f"{baseline_snapshot[
                    'average_control_coverage'
                ]}%"
            ),
        )

        trend_cols[1].metric(
            "Current Coverage",
            (
                f"{remediated_snapshot[
                    'average_control_coverage'
                ]}%"
            ),
            delta=(
                f"{assessment_comparison[
                    'coverage_change'
                ]:+}%"
            ),
        )

        trend_cols[2].metric(
            "Baseline Residual Risk",
            (
                f"{baseline_snapshot[
                    'highest_residual_risk'
                ]}/25"
            ),
        )

        trend_cols[3].metric(
            "Current Residual Risk",
            (
                f"{remediated_snapshot[
                    'highest_residual_risk'
                ]}/25"
            ),
            delta=(
                assessment_comparison[
                    "risk_change"
                ]
            ),
            delta_color="inverse",
        )

        st.caption(
            "Assessment trend: "
            f"{assessment_comparison['trend']}. "
            "Residual risk is estimated from "
            "declared control implementation "
            "and effectiveness."
        )

        assessment_df = pd.DataFrame(
            [
                {
                    "Assessment": "A-001",
                    "Stage": "Baseline",
                    "Control Coverage (%)": (
                        baseline_snapshot[
                            "average_control_coverage"
                        ]
                    ),
                    "Residual Risk": (
                        baseline_snapshot[
                            "highest_residual_risk"
                        ]
                    ),
                    "Findings": (
                        baseline_snapshot[
                            "finding_count"
                        ]
                    ),
                },
                {
                    "Assessment": "A-002",
                    "Stage": "After Remediation",
                    "Control Coverage (%)": (
                        remediated_snapshot[
                            "average_control_coverage"
                        ]
                    ),
                    "Residual Risk": (
                        remediated_snapshot[
                            "highest_residual_risk"
                        ]
                    ),
                    "Findings": (
                        remediated_snapshot[
                            "finding_count"
                        ]
                    ),
                },
            ]
        )

        st.dataframe(
            assessment_df,
            use_container_width=True,
            hide_index=True,
        )

        # ====================================================
        # SECURITY FINDINGS & REMEDIATION
        # ====================================================

        st.markdown(
            "### Security Findings & Remediation"
        )

        st.caption(
            "Current security findings after remediation, "
            "including ownership, SLA status, priority, "
            "and estimated residual risk."
        )

        current_findings = (
            remediated_report.get(
                "findings",
                [],
            )
        )

        open_findings = [
            finding
            for finding in current_findings
            if finding.get(
                "status"
            ) in {
                "Open",
                "In Progress",
            }
        ]

        overdue_findings = [
            finding
            for finding in current_findings
            if finding.get(
                "sla_status"
            ) == "Overdue"
        ]

        p1_findings = [
            finding
            for finding in current_findings
            if finding.get(
                "priority"
            ) == "P1"
        ]

        finding_metric_cols = (
            st.columns(4)
        )

        finding_metric_cols[0].metric(
            "Open Findings",
            len(open_findings),
        )

        finding_metric_cols[1].metric(
            "Resolved",
            finding_summary[
                "Resolved"
            ],
        )

        finding_metric_cols[2].metric(
            "Overdue",
            len(overdue_findings),
        )

        finding_metric_cols[3].metric(
            "Current P1",
            len(p1_findings),
        )

        if current_findings:
            finding_rows = []

            for finding in current_findings:
                finding_rows.append(
                    {
                        "Finding": (
                            finding["id"]
                        ),
                        "Asset": (
                            finding.get(
                                "asset",
                                "N/A",
                            )
                        ),
                        "Control": (
                            finding.get(
                                "control_id",
                                "N/A",
                            )
                        ),
                        "Control Name": (
                            finding.get(
                                "control_name",
                                "N/A",
                            )
                        ),
                        "Priority": (
                            finding.get(
                                "priority",
                                "N/A",
                            )
                        ),
                        "Status": (
                            finding.get(
                                "status",
                                "N/A",
                            )
                        ),
                        "Owner": (
                            finding.get(
                                "owner",
                                "Unassigned",
                            )
                        ),
                        "SLA": (
                            finding.get(
                                "sla_status",
                                "N/A",
                            )
                        ),
                        "Due Date": (
                            finding.get(
                                "due_date",
                                "N/A",
                            )
                        ),
                        "Residual Risk": (
                            finding.get(
                                "estimated_residual_risk",
                                "N/A",
                            )
                        ),
                    }
                )

            findings_df = pd.DataFrame(
                finding_rows
            )

            st.dataframe(
                findings_df,
                use_container_width=True,
                hide_index=True,
            )

            st.markdown(
                "#### Remediation Actions"
            )

            for finding in current_findings:
                title = (
                    f"{finding['id']} · "
                    f"{finding.get(
                        'control_name',
                        'Control Gap',
                    )} · "
                    f"{finding.get(
                        'priority',
                        'N/A',
                    )}"
                )

                with st.expander(
                    title
                ):
                    remediation_cols = (
                        st.columns(3)
                    )

                    remediation_cols[
                        0
                    ].metric(
                        "Owner",
                        finding.get(
                            "owner",
                            "Unassigned",
                        ),
                    )

                    remediation_cols[
                        1
                    ].metric(
                        "SLA Status",
                        finding.get(
                            "sla_status",
                            "N/A",
                        ),
                    )

                    remediation_cols[
                        2
                    ].metric(
                        "Due Date",
                        finding.get(
                            "due_date",
                            "N/A",
                        ),
                    )

                    st.markdown(
                        "**Recommended Remediation**"
                    )

                    st.write(
                        finding.get(
                            "remediation",
                            "No remediation "
                            "guidance available.",
                        )
                    )

                    st.caption(
                        "Estimated residual "
                        "path risk: "
                        f"{finding.get(
                            'estimated_residual_risk',
                            'N/A',
                        )}/25"
                    )

        else:
            st.success(
                "No current open security "
                "findings remain after "
                "remediation."
            )

        st.markdown(
            "#### Finding Lifecycle"
        )

        finding_cols = st.columns(4)

        finding_cols[0].metric(
            "Resolved",
            finding_summary[
                "Resolved"
            ],
        )

        finding_cols[1].metric(
            "Still Open",
            finding_summary[
                "Still Open"
            ],
        )

        finding_cols[2].metric(
            "New",
            finding_summary[
                "New"
            ],
        )

        finding_cols[3].metric(
            "Reopened",
            finding_summary[
                "Reopened"
            ],
        )

        reconciliation_rows = []

        for item in finding_reconciliation:
            reconciliation_rows.append(
                {
                    "Finding": (
                        item["finding_id"]
                    ),
                    "Control": (
                        item["control_id"]
                    ),
                    "Control Name": (
                        item[
                            "control_name"
                        ]
                    ),
                    "Asset": (
                        item["asset"]
                    ),
                    "Lifecycle": (
                        item["state"]
                    ),
                }
            )

        if reconciliation_rows:
            st.dataframe(
                pd.DataFrame(
                    reconciliation_rows
                ),
                use_container_width=True,
                hide_index=True,
            )

    else:
        st.info(
            "Continuous assessment data "
            "will appear after both baseline "
            "and remediated architecture "
            "files are available."
        )

    st.divider()


    # ========================================================
    # 18. REPORT GENERATION & DOWNLOADS
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
    # 19. FOOTER
    # ========================================================

    st.caption(
        "ThreatModel AI — Architecture Threat Modeling "
        "and Risk Analysis. Synthetic demonstration "
        "data is used in the built-in banking scenario."
    )


# ============================================================
# 20. TEMPORARY FILE CLEANUP
# ============================================================

finally:
    if temp_path and os.path.exists(
        temp_path
    ):
        os.remove(temp_path)
