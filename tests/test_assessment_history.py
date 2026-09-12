from datetime import datetime, timezone

from core.assessment_history import (
    create_assessment_snapshot,
    compare_assessments,
)


def _report(
    risk,
    coverage,
    finding_count,
):
    return {
        "summary": {
            "architecture":
                "Cloud Banking Application"
        },
        "attack_paths": [
            {
                "residual_path_risk":
                    risk,
                "control_summary": {
                    "coverage_percentage":
                        coverage,
                },
            }
        ],
        "findings": [
            {
                "status": "Open"
            }
            for _ in range(
                finding_count
            )
        ],
    }


def test_snapshot_is_created():
    report = _report(
        12,
        47.9,
        4,
    )

    snapshot = (
        create_assessment_snapshot(
            report,
            "A-001",
            datetime(
                2026,
                9,
                12,
                tzinfo=timezone.utc,
            ),
        )
    )

    assert (
        snapshot[
            "assessment_id"
        ]
        == "A-001"
    )

    assert (
        snapshot[
            "highest_residual_risk"
        ]
        == 12
    )


def test_snapshot_tracks_coverage():
    report = _report(
        12,
        47.9,
        4,
    )

    snapshot = (
        create_assessment_snapshot(
            report,
            "A-001",
        )
    )

    assert (
        snapshot[
            "average_control_coverage"
        ]
        == 47.9
    )


def test_snapshot_tracks_findings():
    report = _report(
        12,
        47.9,
        4,
    )

    snapshot = (
        create_assessment_snapshot(
            report,
            "A-001",
        )
    )

    assert (
        snapshot[
            "open_findings"
        ]
        == 4
    )


def test_comparison_detects_improvement():
    previous = (
        create_assessment_snapshot(
            _report(
                12,
                47.9,
                4,
            ),
            "A-001",
        )
    )

    current = (
        create_assessment_snapshot(
            _report(
                6,
                75.0,
                2,
            ),
            "A-002",
        )
    )

    comparison = (
        compare_assessments(
            previous,
            current,
        )
    )

    assert (
        comparison["trend"]
        == "Improved"
    )

    assert (
        comparison["risk_change"]
        == -6
    )

    assert (
        comparison[
            "coverage_change"
        ]
        == 27.1
    )
