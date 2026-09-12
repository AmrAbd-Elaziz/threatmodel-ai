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
    "TM-C003": "Application Security Team",
    "TM-C004": "Application Team",
    "TM-C008": "Platform Engineering Team",
    "TM-C009": "Platform Engineering Team",
    "TM-C010": "IAM / Application Team",
    "TM-C011": "IAM / Application Team",
}



def _finding_id(
    attack_path_id,
    control_id,
    asset,
):
    fingerprint = (
        f"{attack_path_id}|"
        f"{control_id}|"
        f"{asset}"
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

    findings = []

    for path in attack_paths:
        priority = path[
            "residual_path_priority"
        ]

        sla_days = SLA_DAYS[priority]

        for gap in path.get(
            "control_gaps",
            [],
        ):
            affected_asset = (
                gap.get("component_id")
                or path["critical_asset"]
            )

            finding_id = _finding_id(
                path["id"],
                gap["id"],
                affected_asset,
            )

            owner = OWNER_MAPPING.get(
                gap["id"],
                "Security Engineering Team",
            )

            due_date = (
                assessment_date
                + timedelta(days=sla_days)
            )

            days_remaining = (
                due_date - assessment_date
            ).days

            if days_remaining < 0:
                sla_status = "Overdue"
            elif days_remaining == 0:
                sla_status = "Due Today"
            else:
                sla_status = "Within SLA"

            findings.append(
                {
                    "id": finding_id,
                    "attack_path_id": path["id"],
                    "control_id": gap["id"],
                    "control_name": gap["name"],
                    "asset": affected_asset,
                    "status": "Open",
                    "control_status": gap["status"],
                    "owner": owner,
                    "priority": priority,
                    "sla_days": sla_days,
                    "assessment_date": (
                        assessment_date.isoformat()
                    ),
                    "due_date": (
                        due_date.isoformat()
                    ),
                    "sla_status": sla_status,
                    "days_remaining": (
                        days_remaining
                    ),
                    "inherent_path_risk": (
                        path["path_risk"]
                    ),
                    "estimated_residual_risk": (
                        path[
                            "residual_path_risk"
                        ]
                    ),
                    "remediation": (
                        f"Implement or strengthen "
                        f"{gap['name']} "
                        f"({gap['id']}) for the "
                        "affected attack path."
                    ),
                }
            )


    findings.sort(
        key=lambda finding: (
            finding["priority"],
            finding["id"],
        )
    )

    return findings
