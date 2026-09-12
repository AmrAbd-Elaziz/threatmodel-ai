from core.boundaries import detect_trust_boundaries
from core.controls import attach_controls
from core.parser import load_architecture
from core.residual import calculate_residual_risks
from core.risk import score_threats
from core.threats import generate_threats
from core.attack_paths import discover_attack_paths
from core.attack_path_risk import score_attack_paths
from core.control_assessment import assess_attack_paths
from core.findings import generate_findings


def analyze_architecture(input_file):
    architecture = load_architecture(input_file)

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

    threats = attach_controls(
        threats
    )

    threats = calculate_residual_risks(
        threats
    )

    priorities = {
        "P1": 0,
        "P2": 0,
        "P3": 0,
        "P4": 0,
        "P5": 0,
    }
    attack_paths = discover_attack_paths(
        architecture,
        threats,
    )

    attack_paths = score_attack_paths(
        attack_paths,
        architecture,
    )

    attack_paths = assess_attack_paths(
        attack_paths,
        architecture,
    )

    for threat in threats:
        priorities[threat["priority"]] += 1

    highest_risk = max(
        (
            threat["inherent_risk"]
            for threat in threats
        ),
        default=0,
    )

    findings = generate_findings(
        attack_paths,
    )

    highest_attack_path_risk = max(
        (
        path["path_risk"]
        for path in attack_paths
        ),
        default=0,
    )

    return {
        "summary": {
            "architecture": architecture.name,
            "components": len(
                architecture.components
            ),
            "data_flows": len(
                architecture.data_flows
            ),
            "trust_boundaries": len(
                boundaries
            ),
            "threats": len(threats),
            "highest_risk": highest_risk,
            "priorities": priorities,
            "attack_paths": len(attack_paths),
            "highest_attack_path_risk": (
                highest_attack_path_risk
            ),
        },
        "architecture": architecture.model_dump(),
        "boundaries": boundaries,
        "threats": threats,
        "attack_paths": attack_paths,
        "findings": findings,
    }
