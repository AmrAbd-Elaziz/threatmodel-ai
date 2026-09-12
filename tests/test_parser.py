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

def test_security_context_is_parsed():
    architecture = load_architecture(
        "data/banking_architecture.yaml"
    )

    customer_db = next(
        component
        for component
        in architecture.components
        if component.id == "customer-db"
    )

    assert (
        customer_db.criticality
        == "critical"
    )

    assert (
        customer_db.data_classification
        == "restricted"
    )

def test_existing_controls_are_parsed():
    architecture = load_architecture(
        "data/banking_architecture.yaml"
    )

    assert architecture.existing_controls

    control_ids = {
        control.id
        for control in architecture.existing_controls
    }

    assert "TM-C010" in control_ids
    assert "TM-C011" in control_ids
