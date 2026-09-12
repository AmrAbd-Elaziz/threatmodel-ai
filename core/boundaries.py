def detect_trust_boundaries(architecture):
    components = {
        component.id: component
        for component in architecture.components
    }

    boundaries = []

    for flow in architecture.data_flows:
        source = components[flow.source]
        destination = components[flow.destination]

        if source.trust_zone != destination.trust_zone:
            boundaries.append(
                {
                    "flow_id": flow.id,
                    "source": source.id,
                    "destination": destination.id,
                    "source_zone": source.trust_zone,
                    "destination_zone": destination.trust_zone,
                    "encrypted": flow.encrypted,
                    "authentication": flow.authentication,
                    "sensitive_data": flow.sensitive_data,
                }
            )

    return boundaries