import json
import sqlite3
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS assessments (
    assessment_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    architecture TEXT,
    attack_path_count INTEGER NOT NULL,
    highest_residual_risk INTEGER NOT NULL,
    average_control_coverage REAL NOT NULL,
    finding_count INTEGER NOT NULL,
    open_findings INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT NOT NULL,
    assessment_id TEXT NOT NULL,
    attack_path_id TEXT,
    control_id TEXT,
    control_name TEXT,
    asset TEXT,
    status TEXT NOT NULL,
    owner TEXT,
    priority TEXT,
    sla_days INTEGER,
    due_date TEXT,
    sla_status TEXT,
    days_remaining INTEGER,
    inherent_path_risk INTEGER,
    estimated_residual_risk INTEGER,
    remediation TEXT,
    raw_json TEXT NOT NULL,
    PRIMARY KEY (
        assessment_id,
        id
    )
);

CREATE TABLE IF NOT EXISTS finding_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT NOT NULL,
    from_status TEXT,
    to_status TEXT NOT NULL,
    changed_at TEXT NOT NULL,
    assessment_id TEXT,
    notes TEXT
);
"""


class ThreatModelStorage:
    def __init__(
        self,
        db_path="data/threatmodel.db",
    ):
        self.db_path = Path(db_path)

        self.db_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(
            self.db_path
        )

        connection.row_factory = (
            sqlite3.Row
        )

        return connection

    def _initialize(self):
        with self._connect() as connection:
            connection.executescript(
                SCHEMA
            )

            self._migrate_findings_schema(
                connection
            )

    def _migrate_findings_schema(
        self,
        connection,
    ):
        columns = connection.execute(
            """
            PRAGMA table_info(findings)
            """
        ).fetchall()

        primary_key_columns = [
            row["name"]
            for row in sorted(
                (
                    row
                    for row in columns
                    if row["pk"]
                ),
                key=lambda row: row["pk"],
            )
        ]

        if primary_key_columns != [
            "id"
        ]:
            return

        connection.execute(
            """
            ALTER TABLE findings
            RENAME TO findings_legacy
            """
        )

        connection.execute(
            """
            CREATE TABLE findings (
                id TEXT NOT NULL,
                assessment_id TEXT NOT NULL,
                attack_path_id TEXT,
                control_id TEXT,
                control_name TEXT,
                asset TEXT,
                status TEXT NOT NULL,
                owner TEXT,
                priority TEXT,
                sla_days INTEGER,
                due_date TEXT,
                sla_status TEXT,
                days_remaining INTEGER,
                inherent_path_risk INTEGER,
                estimated_residual_risk INTEGER,
                remediation TEXT,
                raw_json TEXT NOT NULL,
                PRIMARY KEY (
                    assessment_id,
                    id
                )
            )
            """
        )

        connection.execute(
            """
            INSERT INTO findings (
                id,
                assessment_id,
                attack_path_id,
                control_id,
                control_name,
                asset,
                status,
                owner,
                priority,
                sla_days,
                due_date,
                sla_status,
                days_remaining,
                inherent_path_risk,
                estimated_residual_risk,
                remediation,
                raw_json
            )
            SELECT
                id,
                assessment_id,
                attack_path_id,
                control_id,
                control_name,
                asset,
                status,
                owner,
                priority,
                sla_days,
                due_date,
                sla_status,
                days_remaining,
                inherent_path_risk,
                estimated_residual_risk,
                remediation,
                raw_json
            FROM findings_legacy
            """
        )

        connection.execute(
            """
            DROP TABLE findings_legacy
            """
        )

    def save_assessment(
        self,
        snapshot,
    ):
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO assessments (
                    assessment_id,
                    timestamp,
                    architecture,
                    attack_path_count,
                    highest_residual_risk,
                    average_control_coverage,
                    finding_count,
                    open_findings
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot[
                        "assessment_id"
                    ],
                    snapshot[
                        "timestamp"
                    ],
                    snapshot[
                        "architecture"
                    ],
                    snapshot[
                        "attack_path_count"
                    ],
                    snapshot[
                        "highest_residual_risk"
                    ],
                    snapshot[
                        "average_control_coverage"
                    ],
                    snapshot[
                        "finding_count"
                    ],
                    snapshot[
                        "open_findings"
                    ],
                ),
            )

    def save_findings(
        self,
        findings,
        assessment_id,
    ):
        with self._connect() as connection:
            for finding in findings:
                connection.execute(
                    """
                    INSERT INTO findings (
                        id,
                        assessment_id,
                        attack_path_id,
                        control_id,
                        control_name,
                        asset,
                        status,
                        owner,
                        priority,
                        sla_days,
                        due_date,
                        sla_status,
                        days_remaining,
                        inherent_path_risk,
                        estimated_residual_risk,
                        remediation,
                        raw_json
                    )
                    VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    ON CONFLICT(
                        assessment_id,
                        id
                    )
                    DO UPDATE SET
                        attack_path_id = excluded.attack_path_id,
                        control_id = excluded.control_id,
                        control_name = excluded.control_name,
                        asset = excluded.asset,
                        status = excluded.status,
                        owner = excluded.owner,
                        priority = excluded.priority,
                        sla_days = excluded.sla_days,
                        due_date = excluded.due_date,
                        sla_status = excluded.sla_status,
                        days_remaining = excluded.days_remaining,
                        inherent_path_risk = excluded.inherent_path_risk,
                        estimated_residual_risk = excluded.estimated_residual_risk,
                        remediation = excluded.remediation,
                        raw_json = excluded.raw_json
                    """,
                    (
                        finding["id"],
                        assessment_id,
                        finding.get(
                            "attack_path_id"
                        ),
                        finding.get(
                            "control_id"
                        ),
                        finding.get(
                            "control_name"
                        ),
                        finding.get(
                            "asset"
                        ),
                        finding.get(
                            "status"
                        ),
                        finding.get(
                            "owner"
                        ),
                        finding.get(
                            "priority"
                        ),
                        finding.get(
                            "sla_days"
                        ),
                        finding.get(
                            "due_date"
                        ),
                        finding.get(
                            "sla_status"
                        ),
                        finding.get(
                            "days_remaining"
                        ),
                        finding.get(
                            "inherent_path_risk"
                        ),
                        finding.get(
                            "estimated_residual_risk"
                        ),
                        finding.get(
                            "remediation"
                        ),
                        json.dumps(
                            finding
                        ),
                    ),
                )

    def save_finding_event(
        self,
        finding_id,
        event,
    ):
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO finding_events (
                    finding_id,
                    from_status,
                    to_status,
                    changed_at,
                    assessment_id,
                    notes
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id,
                    event.get(
                        "from"
                    ),
                    event[
                        "to"
                    ],
                    event[
                        "changed_at"
                    ],
                    event.get(
                        "assessment_id"
                    ),
                    event.get(
                        "notes",
                        "",
                    ),
                ),
            )

    def list_assessments(self):
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM assessments
                ORDER BY timestamp
                """
            ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    def list_findings(
        self,
        assessment_id=None,
    ):
        with self._connect() as connection:

            if assessment_id:
                rows = connection.execute(
                    """
                    SELECT *
                    FROM findings
                    WHERE assessment_id = ?
                    ORDER BY id
                    """,
                    (
                        assessment_id,
                    ),
                ).fetchall()

            else:
                rows = connection.execute(
                    """
                    SELECT *
                    FROM findings
                    ORDER BY id
                    """
                ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    def list_finding_events(
        self,
        finding_id,
    ):
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT *
                FROM finding_events
                WHERE finding_id = ?
                ORDER BY id
                """,
                (
                    finding_id,
                ),
            ).fetchall()

        return [
            dict(row)
            for row in rows
        ]
