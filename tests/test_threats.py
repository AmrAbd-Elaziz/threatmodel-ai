from core.boundaries import detect_trust_boundaries
from core.parser import load_architecture
from core.threats import generate_threats


def test_generate_threats():
    architecture = load_architecture(
        "data/banking_architecture.yaml"
    )

    boundaries = detect_trust_boundaries(
        architecture
    )

    threats = generate_threats(
        architecture,
        boundaries,
    )

    assert len(threats) > 0


def test_sensitive_flows_generate_tampering():
    architecture = load_architecture(
        "data/banking_architecture.yaml"
    )

    boundaries = detect_trust_boundaries(
        architecture
    )

    threats = generate_threats(
        architecture,
        boundaries,
    )

    categories = [
        threat["category"]
        for threat in threats
    ]

    assert "Tampering" in categories


def test_internet_flow_generates_dos():
    architecture = load_architecture(
        "data/banking_architecture.yaml"
    )

    boundaries = detect_trust_boundaries(
        architecture
    )

    threats = generate_threats(
        architecture,
        boundaries,
    )

    dos_threats = [
        threat
        for threat in threats
        if threat["category"]
        == "Denial of Service"
    ]

    assert len(dos_threats) >= 1