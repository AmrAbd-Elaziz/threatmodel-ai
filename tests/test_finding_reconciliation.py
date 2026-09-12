from core.finding_reconciliation import (
    reconcile_findings,
    reconciliation_summary,
)


def _finding(
    finding_id,
    status="Open",
):
    return {
        "id": finding_id,
        "status": status,
        "control_id": "TM-C010",
        "control_name": "Least Privilege",
        "asset": "banking-api",
    }


def test_existing_finding_stays_open():
    previous = [
        _finding("GAP-AAAA1111")
    ]

    current = [
        _finding("GAP-AAAA1111")
    ]

    result = reconcile_findings(
        previous,
        current,
    )

    assert (
        result[0]["state"]
        == "Still Open"
    )


def test_missing_current_finding_is_resolved():
    previous = [
        _finding("GAP-AAAA1111")
    ]

    result = reconcile_findings(
        previous,
        [],
    )

    assert (
        result[0]["state"]
        == "Resolved"
    )


def test_new_finding_is_detected():
    current = [
        _finding("GAP-BBBB2222")
    ]

    result = reconcile_findings(
        [],
        current,
    )

    assert (
        result[0]["state"]
        == "New"
    )


def test_resolved_finding_can_reopen():
    previous = [
        _finding(
            "GAP-AAAA1111",
            "Resolved",
        )
    ]

    current = [
        _finding("GAP-AAAA1111")
    ]

    result = reconcile_findings(
        previous,
        current,
    )

    assert (
        result[0]["state"]
        == "Reopened"
    )


def test_summary_counts_states():
    previous = [
        _finding("GAP-AAAA1111"),
        _finding("GAP-BBBB2222"),
    ]

    current = [
        _finding("GAP-AAAA1111"),
        _finding("GAP-CCCC3333"),
    ]

    result = reconcile_findings(
        previous,
        current,
    )

    summary = reconciliation_summary(
        result
    )

    assert summary["Still Open"] == 1
    assert summary["Resolved"] == 1
    assert summary["New"] == 1
    assert summary["Reopened"] == 0
