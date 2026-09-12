from datetime import datetime, timezone


def create_assessment_snapshot(
    report,
    assessment_id,
    assessment_time=None,
):
    if assessment_time is None:
        assessment_time = datetime.now(
            timezone.utc
        )

    attack_paths = report.get(
        "attack_paths",
        [],
    )

    findings = report.get(
        "findings",
        [],
    )

    residual_risks = [
        path.get(
            "residual_path_risk",
            0,
        )
        for path in attack_paths
    ]

    coverages = [
        path.get(
            "control_summary",
            {},
        ).get(
            "coverage_percentage",
            0,
        )
        for path in attack_paths
    ]

    highest_residual_risk = max(
        residual_risks,
        default=0,
    )

    average_coverage = (
        round(
            sum(coverages)
            / len(coverages),
            1,
        )
        if coverages
        else 0.0
    )

    open_findings = sum(
        1
        for finding in findings
        if finding.get("status")
        == "Open"
    )

    return {
        "assessment_id": assessment_id,
        "timestamp": (
            assessment_time.isoformat()
        ),
        "architecture": (
            report.get(
                "summary",
                {},
            ).get(
                "architecture"
            )
        ),
        "attack_path_count": len(
            attack_paths
        ),
        "highest_residual_risk": (
            highest_residual_risk
        ),
        "average_control_coverage": (
            average_coverage
        ),
        "finding_count": len(
            findings
        ),
        "open_findings": (
            open_findings
        ),
    }


def compare_assessments(
    previous,
    current,
):
    risk_change = (
        current[
            "highest_residual_risk"
        ]
        -
        previous[
            "highest_residual_risk"
        ]
    )

    coverage_change = round(
        current[
            "average_control_coverage"
        ]
        -
        previous[
            "average_control_coverage"
        ],
        1,
    )

    if risk_change < 0:
        trend = "Improved"
    elif risk_change > 0:
        trend = "Regressed"
    else:
        trend = "Unchanged"

    return {
        "previous_assessment": (
            previous["assessment_id"]
        ),
        "current_assessment": (
            current["assessment_id"]
        ),
        "trend": trend,
        "risk_change": risk_change,
        "coverage_change": (
            coverage_change
        ),
        "previous_risk": (
            previous[
                "highest_residual_risk"
            ]
        ),
        "current_risk": (
            current[
                "highest_residual_risk"
            ]
        ),
        "previous_coverage": (
            previous[
                "average_control_coverage"
            ]
        ),
        "current_coverage": (
            current[
                "average_control_coverage"
            ]
        ),
    }
