from datetime import datetime, timezone

import pytest

from core.finding_lifecycle import (
    update_finding_status,
)


BASE_FINDING = {
    "id": "GAP-001",
    "status": "Open",
    "control_id": "TM-C010",
}


CHANGE_TIME = datetime(
    2026,
    9,
    12,
    12,
    0,
    tzinfo=timezone.utc,
)


def test_open_to_in_progress():
    updated = update_finding_status(
        BASE_FINDING,
        "In Progress",
        assessment_id="A-002",
        changed_at=CHANGE_TIME,
    )

    assert (
        updated["status"]
        == "In Progress"
    )


def test_finding_can_be_resolved():
    updated = update_finding_status(
        BASE_FINDING,
        "Resolved",
        notes=(
            "Least privilege "
            "implemented."
        ),
        assessment_id="A-002",
        changed_at=CHANGE_TIME,
    )

    assert (
        updated["status"]
        == "Resolved"
    )

    assert (
        updated[
            "resolved_in_assessment"
        ]
        == "A-002"
    )

    assert updated["resolved_at"]


def test_risk_can_be_accepted():
    updated = update_finding_status(
        BASE_FINDING,
        "Accepted Risk",
        notes=(
            "Business owner "
            "accepted residual risk."
        ),
        assessment_id="A-002",
        changed_at=CHANGE_TIME,
    )

    assert (
        updated["status"]
        == "Accepted Risk"
    )

    assert (
        updated[
            "accepted_in_assessment"
        ]
        == "A-002"
    )


def test_status_history_is_recorded():
    updated = update_finding_status(
        BASE_FINDING,
        "In Progress",
        assessment_id="A-002",
        changed_at=CHANGE_TIME,
    )

    history = updated[
        "status_history"
    ]

    assert len(history) == 1
    assert history[0]["from"] == "Open"
    assert (
        history[0]["to"]
        == "In Progress"
    )


def test_resolved_finding_can_be_reopened():
    resolved = update_finding_status(
        BASE_FINDING,
        "Resolved",
        assessment_id="A-002",
        changed_at=CHANGE_TIME,
    )

    reopened = update_finding_status(
        resolved,
        "Open",
        notes=(
            "Control failed "
            "revalidation."
        ),
        assessment_id="A-003",
        changed_at=CHANGE_TIME,
    )

    assert reopened["status"] == "Open"
    assert reopened["resolved_at"] is None


def test_invalid_status_is_rejected():
    with pytest.raises(ValueError):
        update_finding_status(
            BASE_FINDING,
            "Closed Forever",
        )


def test_invalid_transition_is_rejected():
    resolved = update_finding_status(
        BASE_FINDING,
        "Resolved",
        assessment_id="A-002",
        changed_at=CHANGE_TIME,
    )

    with pytest.raises(ValueError):
        update_finding_status(
            resolved,
            "In Progress",
        )
