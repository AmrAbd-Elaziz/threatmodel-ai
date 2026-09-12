from copy import deepcopy

from core.control_assessment import (
    assess_attack_paths,
)
from core.parser import load_architecture
from core.service import analyze_architecture
from core.reassessment import (
    reassess_attack_paths,
)


INPUT_FILE = (
    "data/banking_architecture.yaml"
)


def _before_and_after():
    architecture = load_architecture(
        INPUT_FILE
    )

    report = analyze_architecture(
        INPUT_FILE
    )

    before = deepcopy(
        report["attack_paths"]
    )

    for control in architecture.existing_controls:
        if control.id == "TM-C010":
            control.status = "implemented"
            control.effectiveness = "high"

        if control.id == "TM-C011":
            control.status = "implemented"
            control.effectiveness = "high"

    after = assess_attack_paths(
        deepcopy(before),
        architecture,
    )

    return before, after


def test_reassessment_detects_improvement():
    before, after = _before_and_after()

    results = reassess_attack_paths(
        before,
        after,
    )

    assert results
    assert results[0]["status"] == "Improved"


def test_remediation_reduces_residual_risk():
    before, after = _before_and_after()

    results = reassess_attack_paths(
        before,
        after,
    )

    assert (
        results[0]["current_residual_risk"]
        <
        results[0]["previous_residual_risk"]
    )


def test_remediation_increases_control_coverage():
    before, after = _before_and_after()

    results = reassess_attack_paths(
        before,
        after,
    )

    assert (
        results[0]["current_coverage"]
        >
        results[0]["previous_coverage"]
    )


def test_unchanged_assessment_is_detected():
    before, _ = _before_and_after()

    results = reassess_attack_paths(
        before,
        deepcopy(before),
    )

    assert results[0]["status"] == "Unchanged"


def test_risk_change_is_negative_when_improved():
    before, after = _before_and_after()

    results = reassess_attack_paths(
        before,
        after,
    )

    assert results[0]["risk_change"] < 0
