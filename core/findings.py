import hashlib
from datetime import date, timedelta


SLA_DAYS = {
    "P1": 7,
    "P2": 14,
    "P3": 30,
    "P4": 60,
    "P5": 90,
}


OWNER_MAPPING = {
    "TM-C001": "Security Engineering Team",
    "TM-C002": "Platform Engineering Team",
    "TM-C003": "Application Security Team",
    "TM-C004": "Application Team",
    "TM-C005": "Security Operations Team",
    "TM-C006": "Security Engineering Team",
    "TM-C007": "IAM / Application Team",
    "TM-C008": "Platform Engineering Team",
    "TM-C009": "Platform Engineering Team",
    "TM-C010": "IAM / Application Team",
    "TM-C011": "IAM / Application Team",
}


CONTROL_EFFECTIVENESS_FALLBACK = {
    "TM-C001": 0.40,
    "TM-C002": 0.25,
    "TM-C003": 0.35,
    "TM-C004": 0.25,
    "TM-C005": 0.40,
    "TM-C006": 0.40,
    "TM-C007": 0.30,
    "TM-C008": 0.30,
    "TM-C009": 0.30,
    "TM-C010": 0.35,
    "TM-C011": 0.35,
}


PRIORITY_ORDER = {
    "P1": 1,
    "P2": 2,
    "P3": 3,
    "P4": 4,
    "P5": 5,
}


def _priority_from_score(score):
    if score >= 20:
        return "P1"

    if score >= 15:
        return "P2"

    if score >= 10:
        return "P3"

    if score >= 5:
        return "P4"

    return "P5"


def _finding_priority(
    residual_path_risk,
    control_status,
    effective_score,
    control_effectiveness,
):
    """
    Calculate a finding-specific remediation score.

    The score combines:
    - 55% of the residual attack-path risk;
    - the expected risk-reduction value of the control;
    - the remaining control gap;
    - an escalation bonus for a completely missing control.

    This prevents every gap on one attack path from blindly
    inheriting the same residual_path_priority.
    """

    residual_path_risk = max(
        0.0,
        min(
            float(residual_path_risk),
            25.0,
        ),
    )

    effective_score = max(
        0.0,
        min(
            float(effective_score),
            1.0,
        ),
    )

    control_effectiveness = max(
        0.0,
        min(
            float(control_effectiveness),
            1.0,
        ),
    )

    remaining_gap = 1.0 - effective_score

    missing_bonus = (
        2.5
        if control_status == "missing"
        else 0.0
    )

    score = round(
        (
            residual_path_risk * 0.55
            + control_effectiveness
            * 10
            * remaining_gap
            + missing_bonus
        ),
        1,
    )

    score = max(
        0.0,
        min(score, 25.0),
    )

    return (
        _priority_from_score(score),
        score,
    )


def _finding_id(
    control_id,
    asset,
):
    """
    Stable remediation identity.

    The same control gap on the same asset remains one finding,
    even when several attack paths reach that asset.
    """

    fingerprint = (
        f"{control_id}|{asset}"
    )

    digest = hashlib.sha256(
        fingerprint.encode("utf-8")
    ).hexdigest()[:8].upper()

    return f"GAP-{digest}"


def generate_findings(
    attack_paths,
    assessment_date=None,
):
    if assessment_date is None:
        assessment_date = date.today()

    findings_by_action = {}

    for path in attack_paths:
        residual_path_risk = path.get(
            "residual_path_risk",
            0,
        )

        for gap in path.get(
            "control_gaps",
            [],
        ):
            affected_asset = (
                gap.get("component_id")
                or path["critical_asset"]
            )

            control_id = gap["id"]

            control_effectiveness = float(
                gap.get(
                    "control_effectiveness",
                    CONTROL_EFFECTIVENESS_FALLBACK.get(
                        control_id,
                        0.25,
                    ),
                )
            )

            priority, finding_score = (
                _finding_priority(
                    residual_path_risk=(
                        residual_path_risk
                    ),
                    control_status=gap.get(
                        "status",
                        "missing",
                    ),
                    effective_score=float(
                        gap.get(
                            "effective_score",
                            0.0,
                        )
                    ),
                    control_effectiveness=(
                        control_effectiveness
                    ),
                )
            )

            action_key = (
                control_id,
                affected_asset,
            )

            existing = findings_by_action.get(
                action_key
            )

            if existing is None:
                finding_id = _finding_id(
                    control_id,
                    affected_asset,
                )

                findings_by_action[
                    action_key
                ] = {
                    "id": finding_id,
                    "attack_path_id": path["id"],
                    "attack_path_ids": [
                        path["id"]
                    ],
                    "control_id": control_id,
                    "control_name": gap["name"],
                    "asset": affected_asset,
                    "status": "Open",
                    "control_status": gap.get(
                        "status",
                        "missing",
                    ),
                    "control_effectiveness": (
                        control_effectiveness
                    ),
                    "effective_score": float(
                        gap.get(
                            "effective_score",
                            0.0,
                        )
                    ),
                    "owner": OWNER_MAPPING.get(
                        control_id,
                        "Security Engineering Team",
                    ),
                    "priority": priority,
                    "finding_risk_score": (
                        finding_score
                    ),
                    "assessment_date": (
                        assessment_date.isoformat()
                    ),
                    "inherent_path_risk": (
                        path.get(
                            "path_risk",
                            0,
                        )
                    ),
                    "estimated_residual_risk": (
                        residual_path_risk
                    ),
                }

                continue

            if path["id"] not in (
                existing["attack_path_ids"]
            ):
                existing[
                    "attack_path_ids"
                ].append(path["id"])

            existing["inherent_path_risk"] = max(
                existing["inherent_path_risk"],
                path.get(
                    "path_risk",
                    0,
                ),
            )

            existing[
                "estimated_residual_risk"
            ] = max(
                existing[
                    "estimated_residual_risk"
                ],
                residual_path_risk,
            )

            if (
                finding_score
                > existing["finding_risk_score"]
            ):
                existing["finding_risk_score"] = (
                    finding_score
                )

                existing["priority"] = priority

                existing["attack_path_id"] = (
                    path["id"]
                )

                existing["control_status"] = (
                    gap.get(
                        "status",
                        "missing",
                    )
                )

                existing["effective_score"] = float(
                    gap.get(
                        "effective_score",
                        0.0,
                    )
                )

    findings = list(
        findings_by_action.values()
    )

    for finding in findings:
        finding["attack_path_ids"].sort()

        priority = finding["priority"]
        sla_days = SLA_DAYS[priority]

        due_date = (
            assessment_date
            + timedelta(days=sla_days)
        )

        finding["sla_days"] = sla_days

        finding["due_date"] = (
            due_date.isoformat()
        )

        finding["sla_status"] = "Within SLA"

        finding["days_remaining"] = sla_days

        path_count = len(
            finding["attack_path_ids"]
        )

        path_label = (
            "attack path"
            if path_count == 1
            else "attack paths"
        )

        finding["remediation"] = (
            f"Implement or strengthen "
            f"{finding['control_name']} "
            f"({finding['control_id']}) "
            f"for {finding['asset']}. "
            f"This gap affects "
            f"{path_count} {path_label}."
        )

    findings.sort(
        key=lambda finding: (
            PRIORITY_ORDER[
                finding["priority"]
            ],
            -finding["finding_risk_score"],
            finding["id"],
        )
    )

    return findings
