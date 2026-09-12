STATUS_WEIGHT = {
    "implemented": 1.0,
    "partial": 0.5,
    "missing": 0.0,
}

EFFECTIVENESS_WEIGHT = {
    "low": 0.5,
    "medium": 0.75,
    "high": 1.0,
}


def assess_attack_path_controls(
    attack_path,
    architecture,
):
    existing_controls = {}

    for control in architecture.existing_controls:
        existing_controls.setdefault(
            control.id,
            [],
        ).append(control)

    required_controls = (
        attack_path.get(
            "recommended_controls",
            []
        )
    )

    assessed_controls = []

    implemented = 0
    partial = 0
    missing = 0

    earned_score = 0.0
    maximum_score = 0.0

    for required in required_controls:
        control_id = required["id"]

        candidates = existing_controls.get(
            control_id,
            [],
        )

        path_nodes = set(
            attack_path.get(
                "nodes",
                [],
            )
        )

        applicable = [
            control
            for control in candidates
            if (
                control.component_id is None
                or control.component_id
                in path_nodes
            )
        ]

        existing = (
            applicable[0]
            if applicable
            else None
        )

        maximum_score += 1.0

        if existing:
            status = existing.status
            effectiveness = existing.effectiveness

            status_weight = (
                STATUS_WEIGHT[status]
            )

            effectiveness_weight = (
                EFFECTIVENESS_WEIGHT[
                    effectiveness
                ]
            )

            effective_score = (
                status_weight
                * effectiveness_weight
            )

            earned_score += effective_score

            if status == "implemented":
                implemented += 1
            elif status == "partial":
                partial += 1
            else:
                missing += 1

            assessed_controls.append(
                {
                    "id": control_id,
                    "name": required["name"],
                    "status": status,
                    "effectiveness": effectiveness,
                    "component_id": (
                        existing.component_id
                    ),
                    "notes": existing.notes,
                    "effective_score": round(
                        effective_score,
                        2,
                    ),
                }
            )

        else:
            missing += 1

            assessed_controls.append(
                {
                    "id": control_id,
                    "name": required["name"],
                    "status": "missing",
                    "effectiveness": "low",
                    "component_id": None,
                    "notes": (
                        "Required control is not "
                        "defined in the current "
                        "architecture assessment."
                    ),
                    "effective_score": 0.0,
                }
            )

    coverage = (
        earned_score / maximum_score
        if maximum_score
        else 0.0
    )

    coverage_percentage = round(
        coverage * 100,
        1,
    )

    inherent_risk = attack_path.get(
        "path_risk",
        0,
    )

    residual_risk = round(
        inherent_risk
        * (1 - coverage)
    )

    residual_risk = max(
        0,
        min(
            residual_risk,
            25,
        ),
    )

    if residual_risk >= 20:
        residual_severity = "CRITICAL"
        residual_priority = "P1"
    elif residual_risk >= 15:
        residual_severity = "HIGH"
        residual_priority = "P2"
    elif residual_risk >= 10:
        residual_severity = "MEDIUM"
        residual_priority = "P3"
    elif residual_risk >= 5:
        residual_severity = "LOW"
        residual_priority = "P4"
    else:
        residual_severity = "INFO"
        residual_priority = "P5"

    control_gaps = [
        control
        for control in assessed_controls
        if control["status"] in {
            "partial",
            "missing",
        }
    ]

    return {
        **attack_path,
        "controls_assessed": (
            assessed_controls
        ),
        "control_summary": {
            "required": len(
                required_controls
            ),
            "implemented": implemented,
            "partial": partial,
            "missing": missing,
            "coverage_percentage": (
                coverage_percentage
            ),
        },
        "control_gaps": control_gaps,
        "residual_path_risk": (
            residual_risk
        ),
        "residual_path_severity": (
            residual_severity
        ),
        "residual_path_priority": (
            residual_priority
        ),
    }


def assess_attack_paths(
    attack_paths,
    architecture,
):
    assessed_paths = [
        assess_attack_path_controls(
            path,
            architecture,
        )
        for path in attack_paths
    ]

    assessed_paths.sort(
        key=lambda path:
            path["residual_path_risk"],
        reverse=True,
    )

    return assessed_paths
