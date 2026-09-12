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