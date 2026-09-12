def calculate_residual_risk(threat):
    inherent_risk = threat["risk_score"]

    controls = threat.get(
        "recommended_controls",
        [],
    )

    remaining_factor = 1.0

    for control in controls:
        effectiveness = control.get(
            "effectiveness",
            0,
        )

        remaining_factor *= (
            1 - effectiveness
        )

    residual_score = round(
        inherent_risk * remaining_factor
    )

    if residual_score >= 20:
        severity = "CRITICAL"
    elif residual_score >= 15:
        severity = "HIGH"
    elif residual_score >= 8:
        severity = "MEDIUM"
    elif residual_score > 0:
        severity = "LOW"
    else:
        severity = "INFO"

    return {
        **threat,
        "inherent_risk": inherent_risk,
        "residual_risk": residual_score,
        "residual_severity": severity,
    }


def calculate_residual_risks(threats):
    return [
        calculate_residual_risk(threat)
        for threat in threats
    ]