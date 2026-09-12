def reconcile_findings(
    previous_findings,
    current_findings,
):
    previous_by_id = {
        finding["id"]: finding
        for finding in previous_findings
    }

    current_by_id = {
        finding["id"]: finding
        for finding in current_findings
    }

    results = []

    all_ids = sorted(
        set(previous_by_id)
        | set(current_by_id)
    )

    for finding_id in all_ids:
        previous = previous_by_id.get(
            finding_id
        )

        current = current_by_id.get(
            finding_id
        )

        if previous is None:
            state = "New"
            finding = current

        elif current is None:
            state = "Resolved"
            finding = previous

        else:
            previous_status = previous.get(
                "status",
                "Open",
            )

            if previous_status in {
                "Resolved",
                "Accepted Risk",
            }:
                state = "Reopened"
            else:
                state = "Still Open"

            finding = current

        results.append(
            {
                "finding_id": finding_id,
                "state": state,
                "control_id": finding.get(
                    "control_id"
                ),
                "control_name": finding.get(
                    "control_name"
                ),
                "asset": finding.get(
                    "asset"
                ),
                "previous_status": (
                    previous.get("status")
                    if previous
                    else None
                ),
                "current_status": (
                    current.get("status")
                    if current
                    else None
                ),
            }
        )

    return results


def reconciliation_summary(
    reconciliation,
):
    summary = {
        "New": 0,
        "Still Open": 0,
        "Resolved": 0,
        "Reopened": 0,
    }

    for item in reconciliation:
        summary[item["state"]] += 1

    return summary
