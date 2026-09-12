CRITICALITY_WEIGHT = {
    "low": 1,
    "medium": 2,
    "high": 4,
    "critical": 5,
}

CLASSIFICATION_WEIGHT = {
    "public": 0,
    "internal": 1,
    "confidential": 3,
    "restricted": 5,
}


def score_attack_path(
    attack_path,
    architecture,
):
    components = {
        component.id: component
        for component in architecture.components
    }

    flows = {
        (
            flow.source,
            flow.destination,
        ): flow
        for flow in architecture.data_flows
    }

    nodes = attack_path["nodes"]

    entry = components[nodes[0]]
    asset = components[nodes[-1]]

    drivers = []
    score = 0

    # --------------------------------------------------------
    # 1. EXISTING THREAT EVIDENCE
    # --------------------------------------------------------

    threat_risk = attack_path.get(
        "path_risk",
        0,
    )

    threat_component = round(
        threat_risk / 5
    )

    score += threat_component

    if threat_risk >= 20:
        drivers.append(
            "Critical threat exposure exists "
            "along the path."
        )
    elif threat_risk >= 15:
        drivers.append(
            "High-risk threat exposure exists "
            "along the path."
        )

    # --------------------------------------------------------
    # 2. ENTRY POINT EXPOSURE
    # --------------------------------------------------------

    if entry.internet_exposed:
        score += 4

        drivers.append(
            "Attack path begins at an "
            "internet-exposed component."
        )

    # --------------------------------------------------------
    # 3. ASSET CRITICALITY
    # --------------------------------------------------------

    criticality_score = (
        CRITICALITY_WEIGHT.get(
            asset.criticality,
            2,
        )
    )

    score += criticality_score

    if asset.criticality in {
        "high",
        "critical",
    }:
        drivers.append(
            f"Path reaches a "
            f"{asset.criticality} asset."
        )

    # --------------------------------------------------------
    # 4. DATA CLASSIFICATION
    # --------------------------------------------------------

    classification_score = (
        CLASSIFICATION_WEIGHT.get(
            asset.data_classification,
            1,
        )
    )

    score += classification_score

    if asset.data_classification in {
        "confidential",
        "restricted",
    }:
        drivers.append(
            "Path reaches "
            f"{asset.data_classification} data."
        )

    # --------------------------------------------------------
    # 5. TRUST BOUNDARY CROSSINGS
    # --------------------------------------------------------

    boundary_crossings = attack_path.get(
        "boundary_crossings",
        0,
    )

    boundary_score = min(
        boundary_crossings,
        3,
    )

    score += boundary_score

    if boundary_crossings:
        boundary_label = (
            "trust boundary"
            if boundary_crossings == 1
            else "trust boundaries"
        )

        drivers.append(
            f"Path crosses "
            f"{boundary_crossings} "
            f"{boundary_label}."
        )

    # --------------------------------------------------------
    # 6. FLOW SECURITY WEAKNESSES
    # --------------------------------------------------------

    unauthenticated_flows = 0
    unencrypted_flows = 0
    sensitive_flows = 0
    missing_authorization = 0

    for index in range(
        len(nodes) - 1
    ):
        flow = flows.get(
            (
                nodes[index],
                nodes[index + 1],
            )
        )

        if not flow:
            continue

        if not flow.authentication:
            unauthenticated_flows += 1

        if not flow.encrypted:
            unencrypted_flows += 1

        if flow.sensitive_data:
            sensitive_flows += 1

        if not flow.authorization_required:
            missing_authorization += 1

    if unauthenticated_flows:
        score += min(
            unauthenticated_flows * 2,
            4,
        )

        drivers.append(
            f"{unauthenticated_flows} flow(s) "
            "lack authentication."
        )

    if unencrypted_flows:
        score += min(
            unencrypted_flows * 2,
            4,
        )

        drivers.append(
            f"{unencrypted_flows} flow(s) "
            "are not encrypted."
        )

    if missing_authorization:
        score += min(
            missing_authorization * 2,
            4,
        )

        drivers.append(
            f"{missing_authorization} flow(s) "
            "lack explicit authorization."
        )

    if sensitive_flows:
        score += min(
            sensitive_flows,
            2,
        )

        drivers.append(
            f"{sensitive_flows} sensitive "
            "data flow(s) exist along the path."
        )

    # --------------------------------------------------------
    # 7. NORMALIZE TO 25
    # --------------------------------------------------------

    normalized_score = min(
        round(score),
        25,
    )

    if normalized_score >= 20:
        severity = "CRITICAL"
        priority = "P1"
    elif normalized_score >= 15:
        severity = "HIGH"
        priority = "P2"
    elif normalized_score >= 10:
        severity = "MEDIUM"
        priority = "P3"
    elif normalized_score >= 5:
        severity = "LOW"
        priority = "P4"
    else:
        severity = "INFO"
        priority = "P5"

    return {
        **attack_path,
        "path_risk": normalized_score,
        "path_severity": severity,
        "path_priority": priority,
        "risk_drivers": drivers,
        "risk_factors": {
            "threat_component": (
                threat_component
            ),
            "internet_exposure": (
                4
                if entry.internet_exposed
                else 0
            ),
            "asset_criticality": (
                criticality_score
            ),
            "data_classification": (
                classification_score
            ),
            "trust_boundaries": (
                boundary_score
            ),
            "unauthenticated_flows": (
                unauthenticated_flows
            ),
            "unencrypted_flows": (
                unencrypted_flows
            ),
            "missing_authorization": (
                missing_authorization
            ),
            "sensitive_flows": (
                sensitive_flows
            ),
        },
    }


def score_attack_paths(
    attack_paths,
    architecture,
):
    scored_paths = [
        score_attack_path(
            path,
            architecture,
        )
        for path in attack_paths
    ]

    scored_paths.sort(
        key=lambda path:
            path["path_risk"],
        reverse=True,
    )

    return scored_paths
