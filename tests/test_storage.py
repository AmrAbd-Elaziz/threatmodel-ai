from core.storage import ThreatModelStorage


def test_storage_creates_database(
    tmp_path,
):
    db_path = (
        tmp_path
        / "threatmodel.db"
    )

    ThreatModelStorage(
        db_path
    )

    assert db_path.exists()


def test_save_and_list_assessment(
    tmp_path,
):
    storage = ThreatModelStorage(
        tmp_path
        / "threatmodel.db"
    )

    snapshot = {
        "assessment_id": "A-001",
        "timestamp": (
            "2026-09-12T12:00:00+00:00"
        ),
        "architecture": (
            "Cloud Banking Application"
        ),
        "attack_path_count": 1,
        "highest_residual_risk": 12,
        "average_control_coverage": 47.9,
        "finding_count": 4,
        "open_findings": 4,
    }

    storage.save_assessment(
        snapshot
    )

    assessments = (
        storage.list_assessments()
    )

    assert len(assessments) == 1
    assert (
        assessments[0][
            "assessment_id"
        ]
        == "A-001"
    )


def test_save_and_list_findings(
    tmp_path,
):
    storage = ThreatModelStorage(
        tmp_path
        / "threatmodel.db"
    )

    findings = [
        {
            "id": "GAP-001",
            "attack_path_id": "AP-001",
            "control_id": "TM-C010",
            "control_name": (
                "Least Privilege"
            ),
            "asset": "banking-api",
            "status": "Open",
            "owner": (
                "IAM / Application Team"
            ),
            "priority": "P3",
            "sla_days": 30,
            "due_date": "2026-10-12",
            "sla_status": "Within SLA",
            "days_remaining": 30,
            "inherent_path_risk": 23,
            "estimated_residual_risk": 12,
            "remediation": (
                "Implement least privilege."
            ),
        }
    ]

    storage.save_findings(
        findings,
        "A-001",
    )

    saved = storage.list_findings(
        "A-001"
    )

    assert len(saved) == 1
    assert (
        saved[0]["control_id"]
        == "TM-C010"
    )


def test_save_finding_event(
    tmp_path,
):
    storage = ThreatModelStorage(
        tmp_path
        / "threatmodel.db"
    )

    event = {
        "from": "Open",
        "to": "Resolved",
        "changed_at": (
            "2026-09-12T12:00:00+00:00"
        ),
        "assessment_id": "A-002",
        "notes": (
            "Control implemented."
        ),
    }

    storage.save_finding_event(
        "GAP-001",
        event,
    )

    events = (
        storage.list_finding_events(
            "GAP-001"
        )
    )

    assert len(events) == 1
    assert (
        events[0]["to_status"]
        == "Resolved"
    )


def test_same_finding_id_is_preserved_across_assessments(
    tmp_path,
):
    storage = ThreatModelStorage(
        tmp_path / "history.db"
    )

    finding_a1 = {
        "id": "GAP-STABLE01",
        "attack_path_id": "AP-001",
        "control_id": "TM-C010",
        "control_name": "Least Privilege",
        "asset": "banking-api",
        "status": "Open",
        "owner": "IAM / Application Team",
        "priority": "P3",
        "sla_days": 30,
        "due_date": "2026-10-01",
        "sla_status": "Within SLA",
        "days_remaining": 30,
        "inherent_path_risk": 23,
        "estimated_residual_risk": 12,
        "remediation": "Implement least privilege.",
    }

    finding_a2 = {
        **finding_a1,
        "status": "In Progress",
        "estimated_residual_risk": 6,
    }

    storage.save_findings(
        [finding_a1],
        "A-001",
    )

    storage.save_findings(
        [finding_a2],
        "A-002",
    )

    with storage._connect() as connection:
        rows = connection.execute(
            """
            SELECT
                assessment_id,
                id,
                status,
                estimated_residual_risk
            FROM findings
            WHERE id = ?
            ORDER BY assessment_id
            """,
            (
                "GAP-STABLE01",
            ),
        ).fetchall()

    assert len(rows) == 2

    assert rows[0]["assessment_id"] == "A-001"
    assert rows[0]["status"] == "Open"
    assert (
        rows[0][
            "estimated_residual_risk"
        ]
        == 12
    )

    assert rows[1]["assessment_id"] == "A-002"
    assert (
        rows[1]["status"]
        == "In Progress"
    )
    assert (
        rows[1][
            "estimated_residual_risk"
        ]
        == 6
    )
