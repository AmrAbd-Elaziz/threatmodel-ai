from core.control_assessment import (
    assess_attack_paths,
)
from core.parser import load_architecture
from core.service import analyze_architecture


INPUT_FILE = (
    "data/banking_architecture.yaml"
)


def _get_assessed_paths():
    architecture = load_architecture(
        INPUT_FILE
    )

    report = analyze_architecture(
        INPUT_FILE
    )

    paths = assess_attack_paths(
        report["attack_paths"],
        architecture,
    )

    return paths


def test_control_assessment_exists():
    paths = _get_assessed_paths()

    assert paths

    path = paths[0]

    assert "controls_assessed" in path
    assert "control_summary" in path
    assert "control_gaps" in path


def test_control_coverage_is_percentage():
    paths = _get_assessed_paths()

    coverage = (
        paths[0][
            "control_summary"
        ][
            "coverage_percentage"
        ]
    )

    assert 0 <= coverage <= 100


def test_residual_risk_not_higher_than_inherent():
    paths = _get_assessed_paths()

    for path in paths:
        assert (
            path["residual_path_risk"]
            <= path["path_risk"]
        )


def test_missing_control_is_detected():
    paths = _get_assessed_paths()

    controls = (
        paths[0][
            "controls_assessed"
        ]
    )

    statuses = {
        control["id"]:
            control["status"]
        for control in controls
    }

    assert statuses[
        "TM-C010"
    ] == "missing"


def test_partial_control_is_detected():
    paths = _get_assessed_paths()

    controls = (
        paths[0][
            "controls_assessed"
        ]
    )

    statuses = {
        control["id"]:
            control["status"]
        for control in controls
    }

    assert statuses[
        "TM-C011"
    ] == "partial"


def test_control_gaps_include_partial_and_missing():
    paths = _get_assessed_paths()

    gap_statuses = {
        control["status"]
        for control
        in paths[0]["control_gaps"]
    }

    assert "partial" in gap_statuses
    assert "missing" in gap_statuses


def test_control_outside_attack_path_is_not_counted():
    architecture = load_architecture(
        INPUT_FILE
    )

    for control in architecture.existing_controls:
        if control.id == "TM-C003":
            control.component_id = (
                "component-not-on-path"
            )

    report = analyze_architecture(
        INPUT_FILE
    )

    path = report["attack_paths"][0]

    paths = assess_attack_paths(
        [path],
        architecture,
    )

    controls = {
        control["id"]: control
        for control in
        paths[0]["controls_assessed"]
    }

    assert (
        controls["TM-C003"]["status"]
        == "missing"
    )
