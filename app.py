from pathlib import Path

from core.reporting import generate_html_report
from core.service import analyze_architecture


def main():
    input_file = "data/banking_architecture.yaml"

    report = analyze_architecture(
        input_file
    )

    summary = report["summary"]

    print(
        f"\nArchitecture: {summary['architecture']}"
    )
    print(
        f"Components: {summary['components']}"
    )
    print(
        f"Data Flows: {summary['data_flows']}"
    )
    print(
        f"Trust Boundaries: "
        f"{summary['trust_boundaries']}"
    )
    print(
        f"Threats: {summary['threats']}"
    )
    print(
        f"Highest Risk: "
        f"{summary['highest_risk']}/25"
    )

    print("\nRisk Priorities:")

    for priority, count in (
        summary["priorities"].items()
    ):
        print(
            f"  {priority}: {count}"
        )

    print("\nThreats:")

    for threat in report["threats"]:
        print("=" * 70)
        print(
            f"{threat['category']} "
            f"| {threat['priority']} "
            f"| {threat['severity']}"
        )
        print(
            f"Target: {threat['target']}"
        )
        print(
            f"Inherent Risk: "
            f"{threat['inherent_risk']}/25"
        )
        print(
            f"Projected Residual Risk: "
            f"{threat['residual_risk']}/25 "
            f"({threat['residual_severity']})"
        )
        print(
            f"Threat: {threat['description']}"
        )

        print("Recommended Controls:")

        for control in threat[
            "recommended_controls"
        ]:
            print(
                f"  - {control['id']}: "
                f"{control['name']}"
            )

    reports_dir = Path("reports")
    reports_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_file = (
        reports_dir
        / "banking-threat-model-report.html"
    )

    html = generate_html_report(
        report
    )

    output_file.write_text(
        html,
        encoding="utf-8",
    )

    print(
        f"\nHTML report generated: "
        f"{output_file}"
    )


if __name__ == "__main__":
    main()