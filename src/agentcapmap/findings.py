"""Evaluation output: per-agent capabilities, findings with evidence, coverage gaps."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from agentcapmap import __version__
from agentcapmap.models import SourceLocation

EVALUATION_SCHEMA_VERSION = "1"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class ToolRef(BaseModel):
    server: str
    tool: str
    # Phrase from the tool definition that justified the tag, when there is one.
    evidence: str | None = None
    # True when the phrase was not found verbatim in the tool definition.
    unverified: bool = False


class AgentCapabilities(BaseModel):
    """Union of non-default capabilities across an agent's tools, with provenance."""

    agent_id: str
    client: str
    config_path: str
    # "egress=external" -> the tools that contribute it.
    capabilities: dict[str, list[ToolRef]] = Field(default_factory=dict)
    tools_total: int = 0
    tools_assessed: int = 0


class FindingEvidence(BaseModel):
    server: str
    tool: str | None = None
    # The fields that matched and their actual values, e.g. {"egress": "external"}.
    matched: dict[str, str | bool] = Field(default_factory=dict)
    # Source phrases from the tool definition (or config) backing each matched field.
    phrases: dict[str, str] = Field(default_factory=dict)
    unverified: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    message: str
    maps_to: list[str] = Field(default_factory=list)
    agent_id: str
    config_path: str
    location: SourceLocation | None = None
    servers: list[str]
    tools: list[str] = Field(default_factory=list)  # "server/tool"
    evidence: list[FindingEvidence] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    # Stable identity across runs (for SARIF partialFingerprints and suppressions).
    fingerprint: str


class NotAssessed(BaseModel):
    agent_id: str
    server: str
    tool: str | None = None
    reason: str


class SkippedRule(BaseModel):
    rule_id: str
    reason: str


class PolicyInfo(BaseModel):
    source: str
    version: int
    taxonomy_version: str
    sha256: str


class Evaluation(BaseModel):
    schema_version: str = EVALUATION_SCHEMA_VERSION
    tool_version: str = __version__
    policy: PolicyInfo
    baseline_used: bool = False
    agents: list[AgentCapabilities] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    not_assessed: list[NotAssessed] = Field(default_factory=list)
    skipped_rules: list[SkippedRule] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)
