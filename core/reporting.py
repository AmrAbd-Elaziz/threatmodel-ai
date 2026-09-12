from html import escape


def _safe(value):
    return escape(str(value))


def generate_html_report(report):
    summary = report["summary"]
    boundaries = report["boundaries"]
    threats = report["threats"]
    attack_paths = report.get(
        "attack_paths",
        [],
    )
    findings = report.get(
        "findings",
        [],
    )

    priorities = summary["priorities"]

    threat_rows = ""

    for threat in threats:
        controls = ", ".join(
            control["name"]
            for control in threat[
                "recommended_controls"
            ]
        )

        threat_rows += f"""
        <tr>
            <td>{_safe(threat["category"])}</td>
            <td>{_safe(threat["target"])}</td>
            <td>{_safe(threat["priority"])}</td>
            <td>{_safe(threat["severity"])}</td>
            <td>{threat["inherent_risk"]}/25</td>
            <td>{threat["residual_risk"]}/25</td>
            <td>{_safe(threat["residual_severity"])}</td>
            <td>{_safe(controls)}</td>
        </tr>
        """

    boundary_rows = ""

    for boundary in boundaries:
        boundary_rows += f"""
        <tr>
            <td>{_safe(boundary["flow_id"])}</td>
            <td>{_safe(boundary["source_zone"])}</td>
            <td>{_safe(boundary["destination_zone"])}</td>
            <td>{_safe(boundary["sensitive_data"])}</td>
            <td>{_safe(boundary["encrypted"])}</td>
            <td>{_safe(boundary["authentication"])}</td>
        </tr>
        """

    attack_path_rows = ""

    for path in attack_paths:
        node_path = " → ".join(
            path["nodes"]
        )

        coverage = (
            path.get(
                "control_summary",
                {},
            ).get(
                "coverage_percentage",
                0,
            )
        )

        attack_path_rows += f"""
        <tr>
            <td>{_safe(path["id"])}</td>
            <td>{_safe(node_path)}</td>
            <td>{path["boundary_crossings"]}</td>
            <td>{path["threat_count"]}</td>
            <td>{path["path_risk"]}/25</td>
            <td>{_safe(path["path_severity"])}</td>
            <td>{coverage}%</td>
            <td>{path["residual_path_risk"]}/25</td>
            <td>{_safe(path["residual_path_priority"])}</td>
        </tr>
        """

    control_gap_rows = ""

    for path in attack_paths:
        for gap in path.get(
            "control_gaps",
            [],
        ):
            control_gap_rows += f"""
            <tr>
                <td>{_safe(gap["id"])}</td>
                <td>{_safe(gap["name"])}</td>
                <td>{_safe(gap["status"])}</td>
                <td>{_safe(gap["effectiveness"])}</td>
                <td>{_safe(gap.get("component_id") or "Global")}</td>
                <td>{gap.get("effective_score", 0)}</td>
            </tr>
            """

    finding_rows = ""

    for finding in findings:
        finding_rows += f"""
        <tr>
            <td>{_safe(finding["id"])}</td>
            <td>{_safe(finding["control_id"])}</td>
            <td>{_safe(finding["control_name"])}</td>
            <td>{_safe(finding["asset"])}</td>
            <td>{_safe(finding["owner"])}</td>
            <td>{_safe(finding["status"])}</td>
            <td>{_safe(finding["priority"])}</td>
            <td>{_safe(finding["sla_status"])}</td>
            <td>{_safe(finding["due_date"])}</td>
            <td>{finding["estimated_residual_risk"]}/25</td>
        </tr>
        """

    highest_path = (
        max(
            attack_paths,
            key=lambda item:
                item.get(
                    "path_risk",
                    0,
                ),
        )
        if attack_paths
        else None
    )

    highest_path_risk = (
        highest_path[
            "path_risk"
        ]
        if highest_path
        else 0
    )

    highest_residual = max(
        (
            path.get(
                "residual_path_risk",
                0,
            )
            for path in attack_paths
        ),
        default=0,
    )

    control_coverage = round(
        sum(
            path.get(
                "control_summary",
                {},
            ).get(
                "coverage_percentage",
                0,
            )
            for path in attack_paths
        ) / len(attack_paths),
        1,
    ) if attack_paths else 0

    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>
<title>
ThreatModel AI Security Assessment · V2
</title>

<style>
:root {{
    --bg: #07090d;
    --panel: #0d1218;
    --panel2: #10161e;
    --border: #222b36;
    --text: #f8fafc;
    --muted: #8b98aa;
    --red: #ef4444;
    --green: #22c55e;
    --orange: #f59e0b;
    --blue: #3b82f6;
}}

* {{
    box-sizing: border-box;
}}

body {{
    font-family:
        Inter,
        Arial,
        sans-serif;

    background:
        radial-gradient(
            circle at 85% 0%,
            rgba(239,68,68,.08),
            transparent 25%
        ),
        var(--bg);

    color: var(--text);

    margin: 0;
    padding: 40px;
}}

.container {{
    max-width: 1450px;
    margin: auto;
}}

.header {{
    border: 1px solid var(--border);
    border-radius: 16px;

    background:
        linear-gradient(
            135deg,
            #10151c,
            #090d12
        );

    padding: 25px 28px;
    margin-bottom: 20px;
}}

.eyebrow {{
    color: var(--red);

    font-size: 11px;
    font-weight: 800;

    letter-spacing: .16em;
    text-transform: uppercase;
}}

h1 {{
    margin: 8px 0 5px;
    font-size: 34px;
}}

h1 span {{
    color: var(--red);
}}

.subtitle {{
    color: var(--muted);
    font-size: 14px;
}}

.note {{
    margin: 18px 0;

    padding: 14px 17px;

    border-left: 3px solid var(--red);
    border-radius: 8px;

    background:
        rgba(239,68,68,.05);

    color: #aab5c3;
}}

.grid {{
    display: grid;
    grid-template-columns:
        repeat(6, 1fr);

    gap: 12px;

    margin: 20px 0;
}}

.card {{
    padding: 16px;

    border: 1px solid var(--border);
    border-radius: 12px;

    background: var(--panel);
}}

.card .label {{
    color: var(--muted);
    font-size: 11px;
}}

.card .value {{
    margin-top: 7px;

    font-size: 27px;
    font-weight: 800;
}}

.red {{
    color: var(--red);
}}

.green {{
    color: var(--green);
}}

.section {{
    margin-top: 35px;

    border: 1px solid var(--border);
    border-radius: 14px;

    background: var(--panel);

    padding: 20px;
}}

.section h2 {{
    margin: 3px 0 15px;
    font-size: 21px;
}}

table {{
    width: 100%;

    border-collapse: collapse;

    margin-top: 12px;
}}

th {{
    color: #69778a;

    text-transform: uppercase;
    letter-spacing: .08em;

    font-size: 10px;
}}

td {{
    color: #aab5c3;
    font-size: 11px;
}}

th,
td {{
    padding: 11px;

    text-align: left;

    border-bottom:
        1px solid #1b232d;
}}

.priority {{
    display: inline-block;

    padding: 4px 7px;

    border-radius: 5px;

    background:
        rgba(239,68,68,.1);

    color: var(--red);

    font-weight: 700;
}}

.method {{
    color: var(--muted);
    line-height: 1.7;
}}

.footer {{
    margin-top: 35px;

    color: #566274;

    font-size: 11px;
    text-align: center;
}}

@media print {{
    body {{
        background: white;
        color: #111827;
        padding: 20px;
    }}

    .section,
    .card,
    .header {{
        break-inside: avoid;
    }}
}}
</style>
</head>

<body>
<div class="container">

<div class="header">
    <div class="eyebrow">
        Security Engineering Assessment
    </div>

    <h1>
        ThreatModel
        <span>AI</span>
        V2
    </h1>

    <div class="subtitle">
        {_safe(summary["architecture"])}
        · Architecture Threat Modeling
        · Attack Path Analysis
        · Control Assessment
        · Remediation Findings
    </div>
</div>

<div class="note">
Residual risk and control coverage are
estimated from declared architecture and
control implementation state. They do not
represent validated production
effectiveness or confirmed exploitability.
</div>

<div class="grid">

<div class="card">
<div class="label">Components</div>
<div class="value">
{summary["components"]}
</div>
</div>

<div class="card">
<div class="label">Data Flows</div>
<div class="value">
{summary["data_flows"]}
</div>
</div>

<div class="card">
<div class="label">Threats</div>
<div class="value">
{summary["threats"]}
</div>
</div>

<div class="card">
<div class="label">Highest Threat Risk</div>
<div class="value red">
{summary["highest_risk"]}/25
</div>
</div>

<div class="card">
<div class="label">Highest Path Risk</div>
<div class="value red">
{highest_path_risk}/25
</div>
</div>

<div class="card">
<div class="label">Residual Path Risk</div>
<div class="value green">
{highest_residual}/25
</div>
</div>

</div>

<div class="section">

<div class="eyebrow">
Executive Security Posture
</div>

<h2>
Executive Summary
</h2>

<div class="grid">

<div class="card">
<div class="label">
Trust Boundaries
</div>
<div class="value">
{summary["trust_boundaries"]}
</div>
</div>

<div class="card">
<div class="label">
Attack Paths
</div>
<div class="value">
{summary.get("attack_paths", 0)}
</div>
</div>

<div class="card">
<div class="label">
Control Coverage
</div>
<div class="value">
{control_coverage}%
</div>
</div>

<div class="card">
<div class="label">
Security Findings
</div>
<div class="value">
{len(findings)}
</div>
</div>

<div class="card">
<div class="label">
P1 Threats
</div>
<div class="value">
{priorities["P1"]}
</div>
</div>

<div class="card">
<div class="label">
P2 Threats
</div>
<div class="value">
{priorities["P2"]}
</div>
</div>

</div>

</div>

<div class="section">

<div class="eyebrow">
Architecture Risk
</div>

<h2>
Trust Boundary Analysis
</h2>

<table>
<thead>
<tr>
<th>Flow</th>
<th>Source Zone</th>
<th>Destination Zone</th>
<th>Sensitive Data</th>
<th>Encrypted</th>
<th>Authenticated</th>
</tr>
</thead>

<tbody>
{boundary_rows}
</tbody>
</table>

</div>

<div class="section">

<div class="eyebrow">
STRIDE
</div>

<h2>
Threat & Risk Analysis
</h2>

<table>
<thead>
<tr>
<th>Threat</th>
<th>Target</th>
<th>Priority</th>
<th>Severity</th>
<th>Inherent</th>
<th>Projected Residual</th>
<th>Residual Severity</th>
<th>Recommended Controls</th>
</tr>
</thead>

<tbody>
{threat_rows}
</tbody>
</table>

</div>

<div class="section">

<div class="eyebrow">
Attack Surface
</div>

<h2>
Attack Path Analysis
</h2>

<table>
<thead>
<tr>
<th>ID</th>
<th>Attack Path</th>
<th>Boundaries</th>
<th>Threats</th>
<th>Inherent Risk</th>
<th>Severity</th>
<th>Coverage</th>
<th>Residual Risk</th>
<th>Residual Priority</th>
</tr>
</thead>

<tbody>
{attack_path_rows}
</tbody>
</table>

</div>

<div class="section">

<div class="eyebrow">
Defense Posture
</div>

<h2>
Control Gaps
</h2>

<table>
<thead>
<tr>
<th>ID</th>
<th>Control</th>
<th>Status</th>
<th>Effectiveness</th>
<th>Asset</th>
<th>Effective Score</th>
</tr>
</thead>

<tbody>
{control_gap_rows}
</tbody>
</table>

</div>

<div class="section">

<div class="eyebrow">
Remediation Workflow
</div>

<h2>
Security Findings
</h2>

<table>
<thead>
<tr>
<th>Finding</th>
<th>Control ID</th>
<th>Control</th>
<th>Asset</th>
<th>Owner</th>
<th>Status</th>
<th>Priority</th>
<th>SLA</th>
<th>Due Date</th>
<th>Residual Risk</th>
</tr>
</thead>

<tbody>
{finding_rows}
</tbody>
</table>

</div>

<div class="section">

<div class="eyebrow">
Methodology
</div>

<h2>
Assessment Method
</h2>

<div class="method">

<p>
ThreatModel AI evaluates architecture
components, data flows, trust boundaries,
internet exposure, asset criticality and
data classification.
</p>

<p>
STRIDE-aligned threat scenarios are scored
using likelihood and impact. Architecture
context is then used to discover plausible
attack paths from exposed entry points to
critical assets.
</p>

<p>
Declared security controls are evaluated
against required controls to estimate
coverage, identify control gaps and
calculate estimated residual path risk.
Control gaps are converted into trackable
security findings with ownership, SLA and
remediation guidance.
</p>

<p>
Attack paths represent plausible
architecture-level security scenarios and
do not represent confirmed exploit chains.
</p>

</div>
</div>

<div class="footer">
ThreatModel AI · Security Engineering Platform V2
</div>

</div>
</body>
</html>
"""
