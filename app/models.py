from __future__ import annotations

from enum import StrEnum
from pydantic import BaseModel, Field


class SourceKind(StrEnum):
    mermaid = "mermaid"
    drawio = "drawio"
    terraform = "terraform"
    kubernetes = "kubernetes"
    compose = "compose"


class Component(BaseModel):
    id: str
    name: str
    kind: str = "component"
    internet_exposed: bool = False
    privileged: bool = False
    stores_data: bool = False
    logging_enabled: bool | None = None
    confidence: str = "medium"
    metadata: dict[str, object] = Field(default_factory=dict)


class DataFlow(BaseModel):
    source: str
    target: str
    label: str = "connects"
    encrypted: bool | None = None


class Architecture(BaseModel):
    components: list[Component] = Field(default_factory=list)
    flows: list[DataFlow] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    coverage: dict[str, object] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    stride: str
    title: str
    description: str
    component: str
    severity: str
    likelihood: str
    evidence: list[str]
    mitre_attack: list[str]
    recommendations: list[str]
    confidence: str
    status: str = "candidate"


class AttackPath(BaseModel):
    id: str
    title: str
    steps: list[str]
    severity: str
    rationale: str
    mitre_attack: list[str]
    confidence: str = "medium"


class ThreatModel(BaseModel):
    title: str
    summary: str
    architecture: Architecture
    findings: list[Finding]
    attack_paths: list[AttackPath]
    recommendations: list[str]
    methodology: str
    disclaimer: str
    ruleset_version: str = "2026.07"
    attack_version: str = "Enterprise ATT&CK v18"
    ai_enriched: bool = False
