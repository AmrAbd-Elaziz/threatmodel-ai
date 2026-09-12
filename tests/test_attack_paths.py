from core.attack_paths import (
    discover_attack_paths,
)
from core.parser import load_architecture
from core.service import analyze_architecture


INPUT_FILE = (
    "data/banking_architecture.yaml"
)


def test_discovers_attack_path():
    architecture = load_architecture(
        INPUT_FILE
    )

    report = analyze_architecture(
        INPUT_FILE
    )

    paths = discover_attack_paths(
        architecture,
        report["threats"],
    )

    assert len(paths) >= 1


def test_path_reaches_customer_database():
    architecture = load_architecture(
        INPUT_FILE
    )

    report = analyze_architecture(
        INPUT_FILE
    )

    paths = discover_attack_paths(
        architecture,
        report["threats"],
    )

    database_paths = [
        path
        for path in paths
        if path["critical_asset"]
        == "customer-db"
    ]

    assert database_paths


def test_api_gateway_to_database_path():
    architecture = load_architecture(
        INPUT_FILE
    )

    report = analyze_architecture(
        INPUT_FILE
    )

    paths = discover_attack_paths(
        architecture,
        report["threats"],
    )

    matching_paths = [
        path
        for path in paths
        if path["nodes"] == [
            "api-gateway",
            "banking-api",
            "customer-db",
        ]
    ]

    assert matching_paths


def test_attack_path_crosses_boundaries():
    architecture = load_architecture(
        INPUT_FILE
    )

    report = analyze_architecture(
        INPUT_FILE
    )

    paths = discover_attack_paths(
        architecture,
        report["threats"],
    )

    path = paths[0]

    assert (
        path["boundary_crossings"]
        >= 1
    )


def test_attack_path_has_risk():
    architecture = load_architecture(
        INPUT_FILE
    )

    report = analyze_architecture(
        INPUT_FILE
    )

    paths = discover_attack_paths(
        architecture,
        report["threats"],
    )

    path = paths[0]

    assert path["path_risk"] > 0
    assert path["highest_threat"]


def test_attack_path_controls_deduplicated():
    architecture = load_architecture(
        INPUT_FILE
    )

    report = analyze_architecture(
        INPUT_FILE
    )

    paths = discover_attack_paths(
        architecture,
        report["threats"],
    )

    path = paths[0]

    control_ids = [
        control["id"]
        for control in path[
            "recommended_controls"
        ]
    ]

    assert len(control_ids) == len(
        set(control_ids)
    )
