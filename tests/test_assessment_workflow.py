from datetime import (
    datetime,
    timezone,
)

from core.assessment_workflow import (
    get_assessment_findings,
    get_assessment_history,
    run_assessment,
)
from core.storage import (
    ThreatModelStorage,
)


INPUT_FILE = (
    "data/banking_architecture.yaml"
)


def _run(tmp_path):
    storage = ThreatModelStorage(
        tmp_path
        / "threatmodel.db"
    )

    result = run_assessment(
        INPUT_FILE,
        "A-001",
        storage,
        assessment_time=datetime(
            2026,
            9,
            12,
            12,
            0,
            tzinfo=timezone.utc,
        ),
    )

    return storage, result


def test_workflow_runs_assessment(
    tmp_path,
):
    _, result = _run(
        tmp_path
    )

    assert (
        result["assessment"][
            "assessment_id"
        ]
        == "A-001"
    )

    assert result["report"][
        "attack_paths"
    ]


def test_workflow_persists_assessment(
    tmp_path,
):
    storage, _ = _run(
        tmp_path
    )

    history = (
        get_assessment_history(
            storage
        )
    )

    assert len(history) == 1

    assert (
        history[0][
            "assessment_id"
        ]
        == "A-001"
    )


def test_workflow_persists_findings(
    tmp_path,
):
    storage, result = _run(
        tmp_path
    )

    findings = (
        get_assessment_findings(
            storage,
            "A-001",
        )
    )

    assert findings

    assert len(findings) == len(
        result["report"]["findings"]
    )


def test_workflow_snapshot_matches_report(
    tmp_path,
):
    _, result = _run(
        tmp_path
    )

    snapshot = result[
        "assessment"
    ]

    report = result["report"]

    highest = max(
        path[
            "residual_path_risk"
        ]
        for path in report[
            "attack_paths"
        ]
    )

    assert (
        snapshot[
            "highest_residual_risk"
        ]
        == highest
    )


def test_workflow_preserves_control_coverage(
    tmp_path,
):
    _, result = _run(
        tmp_path
    )

    assert (
        result["assessment"][
            "average_control_coverage"
        ]
        == 47.9
    )
