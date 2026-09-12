def reassess_attack_paths(
    previous_paths,
    current_paths,
):
    previous_by_id = {
        path["id"]: path
        for path in previous_paths
    }

    results = []

    for current in current_paths:
        previous = previous_by_id.get(
            current["id"]
        )

        if previous is None:
            results.append(
                {
                    "attack_path_id": current["id"],
                    "status": "New",
                    "previous_residual_risk": None,
                    "current_residual_risk": (
                        current[
                            "residual_path_risk"
                        ]
                    ),
                    "risk_change": None,
                    "previous_coverage": None,
                    "current_coverage": (
                        current[
                            "control_summary"
                        ][
                            "coverage_percentage"
                        ]
                    ),
                }
            )
            continue

        previous_risk = previous[
            "residual_path_risk"
        ]

        current_risk = current[
            "residual_path_risk"
        ]

        risk_change = (
            current_risk - previous_risk
        )

        if risk_change < 0:
            status = "Improved"
        elif risk_change > 0:
            status = "Regressed"
        else:
            status = "Unchanged"

        results.append(
            {
                "attack_path_id": current["id"],
                "status": status,
                "previous_residual_risk": (
                    previous_risk
                ),
                "current_residual_risk": (
                    current_risk
                ),
                "risk_change": risk_change,
                "previous_coverage": (
                    previous[
                        "control_summary"
                    ][
                        "coverage_percentage"
                    ]
                ),
                "current_coverage": (
                    current[
                        "control_summary"
                    ][
                        "coverage_percentage"
                    ]
                ),
            }
        )

    return results
