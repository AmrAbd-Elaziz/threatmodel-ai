# ThreatModel AI

### Enterprise Security Architecture & Continuous Threat Modeling Platform

ThreatModel AI is an architecture-driven security engineering platform for identifying threats, analyzing attack paths, evaluating security controls, prioritizing risk, tracking remediation findings, and measuring security posture across repeated assessments.

Rather than treating threat modeling as a static STRIDE checklist, the platform builds a security model from system components, data flows, trust zones, sensitive assets, and declared controls — then uses that context to identify plausible architecture attack paths and measure how remediation changes residual risk.

> **Current implementation:** deterministic security analysis engine with an AI-ready architecture.  
> The project does not use an external LLM to make risk decisions.

---

## Why This Project Exists

Traditional threat models often become static documents that are difficult to maintain as architectures and security controls change.

ThreatModel AI explores a more continuous workflow:

```text
Architecture
     ↓
Security Context
     ↓
STRIDE Threat Analysis
     ↓
Attack Path Discovery
     ↓
Inherent Risk
     ↓
Existing Control Assessment
     ↓
Control Gaps
     ↓
Estimated Residual Risk
     ↓
Security Findings
     ↓
Owner + SLA + Remediation
     ↓
Reassessment
     ↓
Security Posture Trend
```

The goal is to connect **security architecture review, threat modeling, control validation, and remediation tracking** in one explainable workflow.

---

## Core Capabilities

### Architecture-Driven Threat Modeling

Models security context including:

- Components and services
- Data flows
- Trust zones
- Internet exposure
- Sensitive-data flows
- Asset criticality
- Data classification
- Existing security controls

The engine applies STRIDE-oriented threat analysis using architecture context rather than generating generic threat lists.

### Attack Path Analysis

ThreatModel AI discovers plausible paths from exposed entry points toward critical assets.

Example from the built-in synthetic banking architecture:

```text
API Gateway
     ↓
Banking API
     ↓
Customer Database
```

The path crosses multiple trust boundaries and reaches a critical asset containing restricted data.

The current model scores this architecture path at:

```text
Inherent Path Risk: 23/25 — CRITICAL — P1
```

Attack paths represent **architecture-level security scenarios**, not confirmed exploit chains.

### Control-Aware Residual Risk

Recommended controls are compared with declared existing controls.

Control states include:

```text
Implemented
Partial
Missing
```

Control effectiveness is also considered when calculating coverage.

Example baseline:

```text
Inherent Path Risk       23/25
Control Coverage         47.9%
Estimated Residual Risk  12/25
Residual Priority        P3
```

Residual risk is an **estimate based on declared control implementation and effectiveness**, not a validated production measurement.

### Security Findings & Remediation

Control gaps become trackable security findings containing:

- Stable finding fingerprint
- Affected asset
- Required control
- Priority
- Finding status
- Assigned owner
- SLA
- Due date
- Remediation guidance
- Estimated residual risk

Example:

```text
Finding       Control                        Owner
---------------------------------------------------------------
GAP-...       Input Validation               Application Team
GAP-...       Availability Protection        Platform Engineering Team
```

Finding identities remain stable across assessments, allowing the platform to distinguish:

```text
New
Still Open
Resolved
Reopened
```

### Continuous Reassessment

ThreatModel AI can compare security posture before and after remediation.

Built-in demonstration:

| Metric | A-001 Baseline | A-002 After Remediation |
|---|---:|---:|
| Control Coverage | 47.9% | 75.0% |
| Highest Residual Risk | 12/25 | 6/25 |
| Open Findings | 4 | 2 |
| Security Trend | — | Improved |

Remediation of Least Privilege and Authorization Enforcement results in:

```text
Risk Change:      -6
Coverage Change:  +27.1%

Resolved:         2
Still Open:       2
New:              0
Reopened:         0
```

This creates an auditable security engineering story:

```text
Identify → Prioritize → Remediate → Reassess → Measure
```

---

## Security Dashboard

The Streamlit dashboard provides:

- Architecture overview
- Architecture graph
- Trust-boundary visualization
- Highest-risk attack path
- Attack-path risk drivers
- Control coverage
- Control-gap analysis
- STRIDE threat distribution
- Priority distribution
- Interactive 5×5 risk matrix
- Threat register and filtering
- Security findings
- Finding ownership and SLA
- Remediation guidance
- Continuous assessment comparison
- Finding lifecycle reconciliation
- JSON and HTML assessment reports

---

## Built-In Banking Scenario

The repository includes a completely synthetic cloud banking architecture for demonstrating the analysis workflow.

### Architecture

```text
Mobile Banking Client
        ↓
    API Gateway
      ↙     ↘
Auth Service  Banking API
                  ↓
          Customer Database
                  ↓
       Third-Party Payment Provider
```

Example trust zones:

```text
Internet
DMZ
Application
Data
External
```

The Customer Database is modeled as a:

```text
Criticality:        CRITICAL
Data Classification: RESTRICTED
```

No real employer, customer, production configuration, or confidential infrastructure data is included.

---

## V2 Security Analysis Flow

```text
YAML Architecture
       │
       ▼
┌──────────────────────┐
│ Architecture Parser  │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ Trust Boundary Model │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ STRIDE Threat Engine │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ Attack Path Engine   │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ Path Risk Scoring    │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ Control Assessment   │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ Finding Generation   │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ Reassessment Engine  │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ Assessment History   │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│ SQLite Persistence   │
└──────────────────────┘
```

---

## Project Structure

```text
threatmodel-ai/
│
├── core/
│   ├── attack_paths.py
│   ├── attack_path_risk.py
│   ├── control_assessment.py
│   ├── findings.py
│   ├── finding_lifecycle.py
│   ├── finding_reconciliation.py
│   ├── reassessment.py
│   ├── assessment_history.py
│   ├── assessment_workflow.py
│   ├── storage.py
│   ├── threats.py
│   ├── risk.py
│   ├── controls.py
│   ├── boundaries.py
│   ├── reporting.py
│   ├── parser.py
│   ├── models.py
│   └── service.py
│
├── data/
│   ├── banking_architecture.yaml
│   └── banking_architecture_remediated.yaml
│
├── tests/
│   └── ...
│
├── streamlit_app.py
├── requirements.txt
└── README.md
```

---

## Run Locally

Clone the repository:

```bash
git clone https://github.com/AmrAbd-Elaziz/threatmodel-ai.git
cd threatmodel-ai
```

Create a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the dashboard:

```bash
streamlit run streamlit_app.py
```

Then open the local Streamlit URL displayed in the terminal.

---

## Run the Test Suite

```bash
pytest -q
```

Current V2 test suite:

```text
83 passed
```

Tests cover the core security workflow including:

- Architecture parsing
- Threat analysis
- Risk scoring
- Trust-boundary analysis
- Attack-path discovery
- Attack-path risk scoring
- Control assessment
- Finding generation
- Stable finding identities
- Finding lifecycle
- Finding reconciliation
- Reassessment
- Assessment history
- SQLite persistence
- End-to-end assessment workflow

---

## Risk Model

Threat risk uses a 5×5 likelihood and impact model:

```text
Risk = Likelihood × Impact
```

Maximum inherent threat risk:

```text
5 × 5 = 25
```

Attack-path scoring additionally considers architecture context such as:

- Threat exposure
- Internet-accessible entry points
- Asset criticality
- Data classification
- Trust-boundary crossings
- Authentication weaknesses
- Encryption weaknesses
- Authorization weaknesses
- Sensitive-data flows

This produces a normalized path risk up to `25`.

---

## Engineering Principles

ThreatModel AI follows several security engineering principles:

**Deterministic before generative**  
Core risk decisions are explainable and reproducible.

**Architecture context matters**  
Risk is evaluated using assets, flows, exposure, trust boundaries, and data sensitivity.

**Controls change risk**  
Existing control implementation and effectiveness affect estimated residual risk.

**Findings need ownership**  
Security issues are connected to owners, SLA targets, and remediation guidance.

**Security is continuous**  
A threat model should support reassessment rather than remain a static document.

---

## Current Scope

V2 focuses on the core security-engineering workflow.

Future architecture can support additional enterprise capabilities such as:

- OpenAPI architecture discovery
- Terraform analysis
- Kubernetes manifest analysis
- Draw.io architecture imports
- Multiple architecture versions
- Project and workspace isolation
- RBAC
- Audit trails
- External issue-tracker integrations
- AI-assisted architecture review and threat explanation

These capabilities are not represented as implemented features in the current version.

---

## Disclaimer

ThreatModel AI is a security engineering and educational project.

Risk scores, attack paths, control coverage, and residual-risk estimates are generated from the architecture and control information supplied to the platform.

They should support — not replace — manual security architecture review, penetration testing, vulnerability validation, and professional risk assessment.

The built-in banking architecture is synthetic and contains no real production or customer information.

---

## Author

**Amr Abdelaziz**  
Cybersecurity Engineer — Security Engineering · Vulnerability Management · Application & Infrastructure Security

