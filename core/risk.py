IMPACT_WEIGHTS = {
    "Spoofing": 4,
    "Tampering": 4,
    "Repudiation": 3,
    "Information Disclosure": 5,
    "Denial of Service": 4,
    "Elevation of Privilege": 5,
}


def calculate_threat_risk(
    threat,
    architecture,
):
    components = {
        component.id: component
        for component in architecture.components
    }

    target = components[threat["target"]]

    impact = IMPACT_WEIGHTS.get(
        threat["category"],
        3,
    )

    likelihood = 2

    if target.internet_exposed:
        likelihood += 2

    if target.stores_sensitive_data:
        impact = min(5, impact + 1)

    if threat["category"] in {
        "Spoofing",
        "Elevation of Privilege",
    }:
        likelihood += 1

    likelihood = min(likelihood, 5)

    score = likelihood * impact

    if score >= 20:
        severity = "CRITICAL"
        priority = "P1"
    elif score >= 15:
        severity = "HIGH"
        priority = "P2"
    elif score >= 8:
        severity = "MEDIUM"
        priority = "P3"
    elif score > 0:
        severity = "LOW"
        priority = "P4"
    else:
        severity = "INFO"
        priority = "P5"

    return {
        **threat,
        "likelihood": likelihood,
        "impact": impact,
        "risk_score": score,
        "severity": severity,
        "priority": priority,
    }


def score_threats(
    threats,
    architecture,
):
    scored = [
        calculate_threat_risk(
            threat,
            architecture,
        )
        for threat in threats
    ]

    return sorted(
        scored,
        key=lambda threat: threat["risk_score"],
        reverse=True,
    )