from core.parser import load_architecture


def test_load_banking_architecture():
    architecture = load_architecture(
        "data/banking_architecture.yaml"
    )

    assert architecture.name == (
        "Cloud Banking Application"
    )

    assert len(architecture.components) == 6
    assert len(architecture.data_flows) == 5


def test_sensitive_database_exists():
    architecture = load_architecture(
        "data/banking_architecture.yaml"
    )

    sensitive_databases = [
        component
        for component in architecture.components
        if component.type == "database"
        and component.stores_sensitive_data
    ]

    assert len(sensitive_databases) == 1


def test_internet_exposed_components():
    architecture = load_architecture(
        "data/banking_architecture.yaml"
    )

    exposed = [
        component.name
        for component in architecture.components
        if component.internet_exposed
    ]

    assert "Mobile Banking Client" in exposed
    assert "API Gateway" in exposed