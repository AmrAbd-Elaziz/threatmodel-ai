from typing import Literal
from pydantic import BaseModel, Field


ComponentType = Literal[
    "client",
    "gateway",
    "service",
    "database",
    "storage",
    "external_service",
    "security_service",
]


class Component(BaseModel):
    id: str
    name: str
    type: ComponentType
    trust_zone: str
    internet_exposed: bool = False
    stores_sensitive_data: bool = False


class DataFlow(BaseModel):
    id: str
    source: str
    destination: str
    protocol: str
    encrypted: bool = True
    authentication: bool = True
    sensitive_data: bool = False


class Architecture(BaseModel):
    name: str
    description: str = ""
    components: list[Component] = Field(
        default_factory=list
    )
    data_flows: list[DataFlow] = Field(
        default_factory=list
    )