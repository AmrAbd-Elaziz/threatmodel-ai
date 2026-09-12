from datetime import date

from core.findings import generate_findings


def _gap(
    control_id,
    name,
    status,
    effective_score,
    control_effectiveness,
    component_id="critical-api",
):
    return {
        "id": control_id,
        "name": name,
        "status": status,
        "effective_score": effective_score,
        "control_effectiveness": (
            control_effectiveness
        ),
        "component_id": component_id,
    }


def _path(
    path_id,
    residual_risk,
    gaps,
):
    return {
        "id": path_id,
        "critical_asset": "critical-api",
        "path_risk": 25,
        "residual_path_risk": residual_risk,
        "residual_path_priority": "P1",
        "control_gaps": gaps,
    }


def test_duplicate_control_asset_is_one_finding():
    shared_gap = _gap(
        "TM-C001",
        "Strong Authentication",
        "missing",
        0.0,
        0.40,
    )

    findings = generate_findings(
        [
            _path(
                "AP-001",
                25,
                [shared_gap],
            ),
            _path(
                "AP-002",
                23,
                [shared_gap],
            ),
        ],
        assessment_date=date(
            2026,
            9,
            12,
        ),
    )

    assert len(findings) == 1

    assert findings[0][
        "attack_path_ids"
    ] == [
        "AP-001",
        "AP-002",
    ]


def test_finding_id_does_not_depend_on_path_id():
    gap = _gap(
        "TM-C010",
        "Least Privilege",
        "missing",
        0.0,
        0.35,
    )

    first = generate_findings(
        [
            _path(
                "AP-OLD",
                20,
                [gap],
            )
        ]
    )

    second = generate_findings(
        [
            _path(
                "AP-NEW",
                20,
                [gap],
            )
        ]
    )

    assert first[0]["id"] == second[0]["id"]


def test_findings_receive_independent_priorities():
    findings = generate_findings(
        [
            _path(
                "AP-001",
                25,
                [
                    _gap(
                        "TM-C001",
                        "Strong Authentication",
                        "missing",
                        0.0,
                        0.40,
                    ),
                    _gap(
                        "TM-C004",
                        "Input Validation",
                        "partial",
                        0.50,
                        0.25,
                    ),
                ],
            )
        ]
    )

    priorities = {
        finding["control_id"]:
            finding["priority"]
        for finding in findings
    }

    assert priorities["TM-C001"] == "P1"
    assert priorities["TM-C004"] == "P2"


def test_higher_gap_score_wins_when_merging():
    gap = _gap(
        "TM-C006",
        "Encryption",
        "missing",
        0.0,
        0.40,
    )

    findings = generate_findings(
        [
            _path(
                "AP-LOW",
                10,
                [gap],
            ),
            _path(
                "AP-HIGH",
                25,
                [gap],
            ),
        ]
    )

    assert len(findings) == 1
    assert (
        findings[0]["attack_path_id"]
        == "AP-HIGH"
    )
    assert (
        findings[0][
            "estimated_residual_risk"
        ]
        == 25
    )
