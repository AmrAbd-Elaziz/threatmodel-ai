STRIDE = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}


def generate_threats(architecture, boundaries):
    components = {
        component.id: component
        for component in architecture.components
    }

    threats = []

    for boundary in boundaries:
        source = components[boundary["source"]]
        destination = components[boundary["destination"]]

        if boundary["authentication"] is False:
            threats.append(
                {
                    "category": "Spoofing",
                    "flow_id": boundary["flow_id"],
                    "target": destination.id,
                    "description": (
                        "Unauthenticated communication may allow "
                        "an attacker to impersonate a trusted entity."
                    ),
                }
            )

        if boundary["encrypted"] is False:
            threats.append(
                {
                    "category": "Information Disclosure",
                    "flow_id": boundary["flow_id"],
                    "target": destination.id,
                    "description": (
                        "Unencrypted communication may expose "
                        "sensitive data in transit."
                    ),
                }
            )

        if boundary["sensitive_data"]:
            threats.append(
                {
                    "category": "Tampering",
                    "flow_id": boundary["flow_id"],
                    "target": destination.id,
                    "description": (
                        "Sensitive data crossing a trust boundary "
                        "may be modified if integrity controls fail."
                    ),
                }
            )

        if source.trust_zone == "internet":
            threats.append(
                {
                    "category": "Denial of Service",
                    "flow_id": boundary["flow_id"],
                    "target": destination.id,
                    "description": (
                        "Internet-facing communication may expose "
                        "the destination to denial-of-service attacks."
                    ),
                }
            )

        if destination.type in {
            "service",
            "gateway",
        }:
            threats.append(
                {
                    "category": "Elevation of Privilege",
                    "flow_id": boundary["flow_id"],
                    "target": destination.id,
                    "description": (
                        "Compromise of the destination service may "
                        "allow an attacker to gain elevated privileges."
                    ),
                }
            )

    return threats