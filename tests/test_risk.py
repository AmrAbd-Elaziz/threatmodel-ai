from core.boundaries import detect_trust_boundaries
from core.parser import load_architecture
from core.risk import score_threats
from core.threats import generate_threats


def get_scored_threats():
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

    return score_threats(
        threats,
        architecture,
    )


def test_threats_receive_risk_scores():
    threats = get_scored_threats()

    assert len(threats) > 0

    for threat in threats:
        assert threat["likelihood"] >= 1
        assert threat["impact"] >= 1
        assert threat["risk_score"] > 0


def test_threats_receive_priorities():
    threats = get_scored_threats()

    valid_priorities = {
        "P1",
        "P2",
        "P3",
        "P4",
        "P5",
    }

    assert all(
        threat["priority"] in valid_priorities
        for threat in threats
    )


def test_threats_sorted_by_risk():
    threats = get_scored_threats()

    scores = [
        threat["risk_score"]
        for threat in threats
    ]

    assert scores == sorted(
        scores,
        reverse=True,
    )