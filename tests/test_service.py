from core.service import analyze_architecture


def test_analyze_architecture():
    report = analyze_architecture(
        "data/banking_architecture.yaml"
    )

    summary = report["summary"]

    assert summary["components"] == 6
    assert summary["data_flows"] == 5
    assert summary["trust_boundaries"] == 5
    assert summary["threats"] == 9


def test_highest_risk():
    report = analyze_architecture(
        "data/banking_architecture.yaml"
    )

    assert report["summary"][
        "highest_risk"
    ] == 25


def test_priority_summary():
    report = analyze_architecture(
        "data/banking_architecture.yaml"
    )

    priorities = report["summary"][
        "priorities"
    ]

    assert priorities["P1"] == 1
    assert priorities["P2"] == 4
    assert priorities["P3"] == 4


def test_report_sections_exist():
    report = analyze_architecture(
        "data/banking_architecture.yaml"
    )

    assert "architecture" in report
    assert "boundaries" in report
    assert "threats" in report

def test_service_includes_attack_paths():
    report = analyze_architecture(
        "data/banking_architecture.yaml"
    )

    assert "attack_paths" in report
    assert report["attack_paths"]

    assert (
        report["summary"]["attack_paths"]
        == len(report["attack_paths"])
    )

    assert (
        report["summary"][
            "highest_attack_path_risk"
        ]
        > 0
    )
    
def test_service_returns_scored_attack_paths():
    report = analyze_architecture(
        "data/banking_architecture.yaml"
    )

    assert report["attack_paths"]

    path = report["attack_paths"][0]

    assert "path_risk" in path
    assert "path_severity" in path
    assert "path_priority" in path
    assert "risk_drivers" in path
    assert "risk_factors" in path

    assert (
        report["summary"][
            "highest_attack_path_risk"
        ]
        == path["path_risk"]
    )

def test_service_returns_findings():
    report = analyze_architecture(
        "data/banking_architecture.yaml"
    )

    assert "findings" in report
    assert report["findings"]


def test_service_findings_have_workflow_metadata():
    report = analyze_architecture(
        "data/banking_architecture.yaml"
    )

    finding = report["findings"][0]

    required_fields = {
        "id",
        "control_id",
        "status",
        "owner",
        "priority",
        "sla_days",
        "due_date",
        "sla_status",
        "days_remaining",
        "remediation",
    }

    assert required_fields.issubset(
        finding.keys()
    )
