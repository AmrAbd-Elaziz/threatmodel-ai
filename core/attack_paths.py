from collections import defaultdict


def discover_attack_paths(
    architecture,
    threats,
):
    """
    Discover plausible architecture attack paths from
    internet-facing entry points to critical assets.

    This is architecture-based path analysis and does not
    claim confirmed exploitability.
    """

    components = {
        component.id: component
        for component in architecture.components
    }

    adjacency = defaultdict(list)

    for flow in architecture.data_flows:
        adjacency[flow.source].append(
            flow.destination
        )

    # Prefer system-side internet-facing components.
    # Client components are treated as external context.
    entry_points = [
        component.id
        for component in architecture.components
        if component.internet_exposed
        and component.type != "client"
    ]

    # Fallback in case the architecture only contains
    # internet-facing client nodes.
    if not entry_points:
        entry_points = [
            component.id
            for component in architecture.components
            if component.internet_exposed
        ]

    critical_assets = [
        component.id
        for component in architecture.components
        if component.stores_sensitive_data
        or component.type in {
            "database",
            "storage",
        }
    ]

    discovered_paths = []

    def walk(
        current,
        target,
        visited,
        path,
    ):
        if current == target:
            discovered_paths.append(
                list(path)
            )
            return

        for neighbor in adjacency.get(
            current,
            [],
        ):
            if neighbor in visited:
                continue

            walk(
                neighbor,
                target,
                visited | {neighbor},
                path + [neighbor],
            )

    for entry_point in entry_points:
        for critical_asset in critical_assets:
            if entry_point == critical_asset:
                continue

            walk(
                entry_point,
                critical_asset,
                {entry_point},
                [entry_point],
            )

    attack_paths = []

    for index, path in enumerate(
        discovered_paths,
        start=1,
    ):
        boundary_crossings = 0

        for position in range(
            len(path) - 1
        ):
            source = components[
                path[position]
            ]

            destination = components[
                path[position + 1]
            ]

            if (
                source.trust_zone
                != destination.trust_zone
            ):
                boundary_crossings += 1

        path_threats = [
            threat
            for threat in threats
            if threat.get("target")
            in path
        ]

        highest_threat = max(
            path_threats,
            key=lambda threat:
                threat.get(
                    "inherent_risk",
                    0,
                ),
            default=None,
        )

        path_risk = (
            highest_threat.get(
                "inherent_risk",
                0,
            )
            if highest_threat
            else 0
        )

        controls = {}

        for threat in path_threats:
            for control in threat.get(
                "recommended_controls",
                [],
            ):
                control_id = control.get(
                    "id"
                )

                if control_id:
                    controls[
                        control_id
                    ] = control

        attack_paths.append(
            {
                "id": (
                    f"AP-{index:03d}"
                ),
                "entry_point": path[0],
                "critical_asset": path[-1],
                "nodes": path,
                "boundary_crossings": (
                    boundary_crossings
                ),
                "threat_count": len(
                    path_threats
                ),
                "path_risk": path_risk,
                "priority": (
                    highest_threat.get(
                        "priority"
                    )
                    if highest_threat
                    else None
                ),
                "severity": (
                    highest_threat.get(
                        "severity"
                    )
                    if highest_threat
                    else None
                ),
                "highest_threat": (
                    highest_threat
                ),
                "recommended_controls": (
                    list(
                        controls.values()
                    )
                ),
                "analysis_basis": (
                    "Architecture reachability "
                    "and maximum inherent threat "
                    "risk observed on the path."
                ),
            }
        )

    attack_paths.sort(
        key=lambda item:
            item["path_risk"],
        reverse=True,
    )

    return attack_paths
