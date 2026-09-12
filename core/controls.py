from pathlib import Path

import yaml


CONTROLS_FILE = (
    Path(__file__).resolve().parent.parent
    / "rules"
    / "security_controls.yaml"
)


def load_controls():
    with open(
        CONTROLS_FILE,
        "r",
        encoding="utf-8",
    ) as file:
        data = yaml.safe_load(file)

    return data["controls"]


def attach_controls(threats):
    control_library = load_controls()

    results = []

    for threat in threats:
        controls = control_library.get(
            threat["category"],
            [],
        )

        results.append(
            {
                **threat,
                "recommended_controls": controls,
            }
        )

    return results