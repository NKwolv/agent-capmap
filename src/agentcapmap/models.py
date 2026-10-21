"""Internal inventory model: Agent -> [Server] -> [Tool].

Serialized fields are always redacted. Raw launch details needed to actually start a
server live in `LaunchSpec`, which is excluded from serialization and from repr.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from agentcapmap import __version__

INVENTORY_SCHEMA_VERSION = "1"


class Transport(StrEnum):
    STDIO = "stdio"
    HTTP = "http"  # Streamable HTTP
    SSE = "sse"  # legacy HTTP+SSE
    WS = "ws"  # WebSocket (Claude Code); listed, not enumerated


class AuthMethod(StrEnum):
    NONE = "none"
    STATIC = "static"
    OAUTH = "oauth"
    UNKNOWN = "unknown"


class AuthHint(BaseModel):
    method: AuthMethod
    # Where the credential comes from, by name only: "env:GITHUB_TOKEN", "header:Authorization".
    evidence: list[str] = Field(default_factory=list)


class SourceLocation(BaseModel):
    path: str
    line: int | None = None


class LaunchSpec(BaseModel):
    """Unredacted launch details. Never serialized, never repr'd."""

    model_config = ConfigDict(frozen=True)

    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    env_file: str | None = None
    cwd: str | None = None
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    # Directory used to resolve ${workspaceFolder} and relative paths.
    base_dir: str | None = None

    def __repr__(self) -> str:
        return "LaunchSpec(<redacted>)"

    __str__ = __repr__


class ToolTags(BaseModel):
    """The six taxonomy axes (see schemas/tool-tags.schema.json)."""

    data_access: Literal["none", "private_read", "secrets_read"]
    untrusted_input: bool
    egress: Literal["none", "internal", "external"]
    mutation: Literal["none", "reversible_write", "destructive"]
    execution: Literal["none", "sandboxed", "host"]
    privilege: Literal["none", "identity_admin"]


class SuspiciousDescription(BaseModel):
    flag: bool
    reason: str = ""


class ClassificationStatus(StrEnum):
    CLASSIFIED = "classified"
    UNCLASSIFIED = "unclassified"


class ToolClassification(BaseModel):
    status: ClassificationStatus
    # Set only when status is "classified".
    tags: ToolTags | None = None
    confidence: float | None = None
    # Per-axis phrase justifying each non-default tag.
    evidence: dict[str, str] = Field(default_factory=dict)
    # Axes whose evidence phrase could not be found in the tool definition text.
    unverified_evidence: list[str] = Field(default_factory=list)
    suspicious_description: SuspiciousDescription | None = None
    # Why the tool is unclassified.
    error: str | None = None
    # Provenance: results are only comparable under the same versions and model.
    model: str | None = None
    taxonomy_version: str
    prompt_version: str
    from_cache: bool = False


class ToolDefinition(BaseModel):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] | None = None
    definition_hash: str
    classification: ToolClassification | None = None


class EnumerationStatus(StrEnum):
    OK = "ok"
    ERROR = "error"
    TIMEOUT = "timeout"
    AUTH_REQUIRED = "auth_required"
    SKIPPED = "skipped"


class EnumerationResult(BaseModel):
    status: EnumerationStatus
    error: str | None = None
    protocol_version: str | None = None
    server_info: dict[str, Any] | None = None
    tools: list[ToolDefinition] = Field(default_factory=list)
    # Hash over the sorted tool definition hashes: changes if any tool changes.
    definition_hash: str | None = None


class ApprovalConfig(BaseModel):
    """Whether a person must approve each tool call, as far as the client config shows.

    Most clients do not record this, so `default_gate` is "unknown" unless a format knows
    better (Claude Code: "required" in its default permission mode).
    """

    auto_approve_all: bool = False
    # Exact tool names that skip approval (e.g. Cline `alwaysAllow`).
    auto_approved_tools: list[str] = Field(default_factory=list)
    # Glob patterns over tool names that skip approval (e.g. Claude Code allow rules).
    auto_approved_patterns: list[str] = Field(default_factory=list)
    # Glob patterns over tool names the client removes from the agent (deny rules).
    denied_patterns: list[str] = Field(default_factory=list)
    # Gate for tools no rule matches: "required" | "none" | "unknown" | "blocked"
    # ("blocked": the client refuses calls that would need approval, e.g. dontAsk mode).
    default_gate: Literal["required", "none", "unknown", "blocked"] = "unknown"
    default_reason: str = ""
    # Config keys or rules the settings came from, for evidence.
    sources: list[str] = Field(default_factory=list)


class Server(BaseModel):
    name: str
    transport: Transport
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    url: str | None = None
    env: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    auth: AuthHint
    location: SourceLocation
    disabled: bool = False
    approval: ApprovalConfig = Field(default_factory=ApprovalConfig)
    enumeration: EnumerationResult | None = None
    launch: LaunchSpec = Field(default_factory=LaunchSpec, exclude=True, repr=False)


class Agent(BaseModel):
    id: str
    client: str
    config_path: str
    servers: list[Server] = Field(default_factory=list)


class DiscoveryError(BaseModel):
    path: str
    message: str


class Inventory(BaseModel):
    schema_version: str = INVENTORY_SCHEMA_VERSION
    tool_version: str = __version__
    agents: list[Agent] = Field(default_factory=list)
    errors: list[DiscoveryError] = Field(default_factory=list)
