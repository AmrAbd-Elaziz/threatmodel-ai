from html import escape


def generate_html_report(report):
    summary = report["summary"]
    boundaries = report["boundaries"]
    threats = report["threats"]

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
            <td>{escape(threat["category"])}</td>
            <td>{escape(threat["target"])}</td>
            <td>{escape(threat["priority"])}</td>
            <td>{escape(threat["severity"])}</td>
            <td>{threat["inherent_risk"]}/25</td>
            <td>{threat["residual_risk"]}/25</td>
            <td>{escape(threat["residual_severity"])}</td>
            <td>{escape(controls)}</td>
        </tr>
        """

    boundary_rows = ""

    for boundary in boundaries:
        boundary_rows += f"""
        <tr>
            <td>{escape(boundary["flow_id"])}</td>
            <td>{escape(boundary["source_zone"])}</td>
            <td>{escape(boundary["destination_zone"])}</td>
            <td>{escape(str(boundary["sensitive_data"]))}</td>
            <td>{escape(str(boundary["encrypted"]))}</td>
            <td>{escape(str(boundary["authentication"]))}</td>
        </tr>
        """

    priorities = summary["priorities"]

    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ThreatModel AI Security Assessment</title>

<style>
body {{
    font-family: Arial, sans-serif;
    background: #0f172a;
    color: #e5e7eb;
    margin: 0;
    padding: 40px;
}}

.container {{
    max-width: 1200px;
    margin: auto;
}}

h1, h2 {{
    color: #f8fafc;
}}

.subtitle {{
    color: #94a3b8;
    margin-bottom: 32px;
}}

.grid {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 14px;
    margin: 25px 0;
}}

.card {{
    background: #1e293b;
    padding: 18px;
    border-radius: 10px;
}}

.card .value {{
    font-size: 28px;
    font-weight: bold;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 20px;
    background: #111827;
}}

th, td {{
    padding: 12px;
    border-bottom: 1px solid #334155;
    text-align: left;
    vertical-align: top;
}}

th {{
    background: #1e293b;
}}

.note {{
    background: #172554;
    padding: 14px;
    border-radius: 8px;
    margin: 20px 0;
}}

.section {{
    margin-top: 45px;
}}
</style>
</head>

<body>
<div class="container">

<h1>ThreatModel AI Security Assessment</h1>

<div class="subtitle">
Architecture Threat Modeling & Risk Analysis
</div>

<div class="note">
Residual risk values shown in this report are projected
estimates assuming the recommended security controls are
implemented effectively. They do not represent validated
production control effectiveness.
</div>

<h2>Executive Summary</h2>

<div class="grid">

<div class="card">
<div>Components</div>
<div class="value">{summary["components"]}</div>
</div>

<div class="card">
<div>Data Flows</div>
<div class="value">{summary["data_flows"]}</div>
</div>

<div class="card">
<div>Trust Boundaries</div>
<div class="value">{summary["trust_boundaries"]}</div>
</div>

<div class="card">
<div>Threats</div>
<div class="value">{summary["threats"]}</div>
</div>

<div class="card">
<div>Highest Risk</div>
<div class="value">{summary["highest_risk"]}/25</div>
</div>

</div>

<div class="section">
<h2>Risk Prioritization</h2>

<p>
P1: {priorities["P1"]} |
P2: {priorities["P2"]} |
P3: {priorities["P3"]} |
P4: {priorities["P4"]} |
P5: {priorities["P5"]}
</p>
</div>

<div class="section">
<h2>Architecture Scope</h2>

<p>
<strong>{escape(summary["architecture"])}</strong>
</p>

<p>
This assessment analyzes architectural components,
data flows, trust boundaries, STRIDE-aligned threats,
inherent risk, recommended controls, and projected
residual risk.
</p>
</div>

<div class="section">
<h2>Trust Boundary Analysis</h2>

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
<h2>Threat & Risk Analysis</h2>

<table>
<thead>
<tr>
<th>Threat</th>
<th>Target</th>
<th>Priority</th>
<th>Severity</th>
<th>Inherent Risk</th>
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
<h2>Assessment Methodology</h2>

<p>
ThreatModel AI evaluates architecture data flows across
trust boundaries and generates context-aware,
STRIDE-aligned threat scenarios.
</p>

<p>
Threats are prioritized using likelihood and impact,
then mapped to security controls designed to reduce
risk exposure.
</p>

</div>

</div>
</body>
</html>
"""