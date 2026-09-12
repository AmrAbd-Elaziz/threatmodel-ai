import yaml

from core.models import Architecture


def load_architecture(path):
    with open(path, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    return Architecture.model_validate(data)