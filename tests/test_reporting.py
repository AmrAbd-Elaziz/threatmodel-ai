from core.reporting import generate_html_report
from core.service import analyze_architecture


def test_generate_html_report():
    report = analyze_architecture(
        "data/banking_architecture.yaml"
    )

    html = generate_html_report(report)

    assert "ThreatModel AI Security Assessment" in html
    assert "Executive Summary" in html
    assert "Trust Boundary Analysis" in html
    assert "Threat & Risk Analysis" in html
    assert "Projected Residual" in html