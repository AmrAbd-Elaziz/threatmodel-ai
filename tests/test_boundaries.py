from core.boundaries import detect_trust_boundaries
from core.parser import load_architecture


def test_detect_trust_boundaries():
    architecture = load_architecture(
        "data/banking_architecture.yaml"
    )

    boundaries = detect_trust_boundaries(
        architecture
    )

    assert len(boundaries) == 5


def test_internet_to_dmz_boundary():
    architecture = load_architecture(
        "data/banking_architecture.yaml"
    )

    boundaries = detect_trust_boundaries(
        architecture
    )

    boundary = next(
        item
        for item in boundaries
        if item["flow_id"] == "flow-001"
    )

    assert boundary["source_zone"] == "internet"
    assert boundary["destination_zone"] == "dmz"


def test_sensitive_data_crosses_boundaries():
    architecture = load_architecture(
        "data/banking_architecture.yaml"
    )

    boundaries = detect_trust_boundaries(
        architecture
    )

    sensitive = [
        boundary
        for boundary in boundaries
        if boundary["sensitive_data"]
    ]

    assert len(sensitive) == 5