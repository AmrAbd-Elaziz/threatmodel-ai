from core.boundaries import detect_trust_boundaries
from core.controls import attach_controls
from core.parser import load_architecture
from core.residual import calculate_residual_risks
from core.risk import score_threats
from core.threats import generate_threats


def get_results():
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

    threats = score_threats(
        threats,
        architecture,
    )

    threats = attach_controls(threats)

    return calculate_residual_risks(
        threats
    )


def test_controls_attached():
    threats = get_results()

    assert all(
        len(threat["recommended_controls"]) > 0
        for threat in threats
    )


def test_residual_risk_not_higher():
    threats = get_results()

    assert all(
        threat["residual_risk"]
        <= threat["inherent_risk"]
        for threat in threats
    )


def test_control_ids_exist():
    threats = get_results()

    control_ids = {
        control["id"]
        for threat in threats
        for control in threat[
            "recommended_controls"
        ]
    }

    assert "TM-C003" in control_ids
    assert "TM-C008" in control_ids
    assert "TM-C010" in control_ids