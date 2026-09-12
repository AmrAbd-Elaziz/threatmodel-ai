from core.assessment_history import (
    create_assessment_snapshot,
)
from core.service import analyze_architecture


def run_assessment(
    input_file,
    assessment_id,
    storage,
    assessment_time=None,
):
    report = analyze_architecture(
        input_file
    )

    snapshot = create_assessment_snapshot(
        report,
        assessment_id,
        assessment_time=assessment_time,
    )

    storage.save_assessment(
        snapshot
    )

    storage.save_findings(
        report.get(
            "findings",
            [],
        ),
        assessment_id,
    )

    return {
        "assessment": snapshot,
        "report": report,
    }


def get_assessment_history(
    storage,
):
    return storage.list_assessments()


def get_assessment_findings(
    storage,
    assessment_id,
):
    return storage.list_findings(
        assessment_id
    )
