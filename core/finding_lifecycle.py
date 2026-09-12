from copy import deepcopy
from datetime import datetime, timezone


VALID_STATUSES = {
    "Open",
    "In Progress",
    "Resolved",
    "Accepted Risk",
}

VALID_TRANSITIONS = {
    "Open": {
        "In Progress",
        "Resolved",
        "Accepted Risk",
    },
    "In Progress": {
        "Open",
        "Resolved",
        "Accepted Risk",
    },
    "Resolved": {
        "Open",
    },
    "Accepted Risk": {
        "Open",
    },
}


def update_finding_status(
    finding,
    new_status,
    notes="",
    assessment_id=None,
    changed_at=None,
):
    if new_status not in VALID_STATUSES:
        raise ValueError(
            f"Invalid finding status: "
            f"{new_status}"
        )

    current_status = finding.get(
        "status",
        "Open",
    )

    if new_status == current_status:
        return deepcopy(finding)

    allowed = VALID_TRANSITIONS.get(
        current_status,
        set(),
    )

    if new_status not in allowed:
        raise ValueError(
            f"Invalid transition: "
            f"{current_status} -> "
            f"{new_status}"
        )

    if changed_at is None:
        changed_at = datetime.now(
            timezone.utc
        )

    updated = deepcopy(finding)

    history = list(
        updated.get(
            "status_history",
            [],
        )
    )

    history.append(
        {
            "from": current_status,
            "to": new_status,
            "changed_at": (
                changed_at.isoformat()
            ),
            "assessment_id": (
                assessment_id
            ),
            "notes": notes,
        }
    )

    updated["status"] = new_status
    updated["status_history"] = history
    updated["updated_at"] = (
        changed_at.isoformat()
    )

    if new_status == "Resolved":
        updated["resolved_at"] = (
            changed_at.isoformat()
        )
        updated[
            "resolved_in_assessment"
        ] = assessment_id
        updated["resolution_notes"] = (
            notes
        )

    elif new_status == "Accepted Risk":
        updated["accepted_at"] = (
            changed_at.isoformat()
        )
        updated[
            "accepted_in_assessment"
        ] = assessment_id
        updated[
            "risk_acceptance_notes"
        ] = notes

    elif new_status == "Open":
        updated["resolved_at"] = None
        updated[
            "resolved_in_assessment"
        ] = None
        updated["resolution_notes"] = ""

        updated["accepted_at"] = None
        updated[
            "accepted_in_assessment"
        ] = None
        updated[
            "risk_acceptance_notes"
        ] = ""

    return updated
