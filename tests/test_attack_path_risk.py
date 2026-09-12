from core.attack_path_risk import (
    score_attack_paths,
)
from core.attack_paths import (
    discover_attack_paths,
)
from core.parser import load_architecture
from core.service import analyze_architecture


INPUT_FILE = (
    "data/banking_architecture.yaml"
)


def _get_scored_paths():
    architecture = load_architecture(
        INPUT_FILE
    )

    report = analyze_architecture(
        INPUT_FILE
    )

    attack_paths = discover_attack_paths(
        architecture,
        report["threats"],
    )

    return (
        architecture,
        score_attack_paths(
            attack_paths,
            architecture,
        ),
    )


def test_attack_path_has_normalized_risk():
    _, paths = _get_scored_paths()

    assert paths

    for path in paths:
        assert 0 <= path["path_risk"] <= 25


def test_attack_path_has_severity():
    _, paths = _get_scored_paths()

    assert paths[0]["path_severity"] in {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
    }


def test_attack_path_has_priority():
    _, paths = _get_scored_paths()

    assert paths[0]["path_priority"] in {
        "P1",
        "P2",
        "P3",
        "P4",
        "P5",
    }


def test_attack_path_has_risk_drivers():
    _, paths = _get_scored_paths()

    assert paths[0]["risk_drivers"]


def test_database_path_reflects_critical_asset():
    _, paths = _get_scored_paths()

    database_path = next(
        path
        for path in paths
        if path["critical_asset"]
        == "customer-db"
    )

    assert (
        database_path[
            "risk_factors"
        ]["asset_criticality"]
        == 5
    )

    assert (
        database_path[
            "risk_factors"
        ]["data_classification"]
        == 5
    )


def test_paths_sorted_by_risk():
    _, paths = _get_scored_paths()

    scores = [
        path["path_risk"]
        for path in paths
    ]

    assert scores == sorted(
        scores,
        reverse=True,
    )
