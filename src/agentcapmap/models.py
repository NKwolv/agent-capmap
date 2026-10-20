"""Internal inventory model: Agent -> [Server] -> [Tool].

Serialized fields are always redacted. Raw launch details needed to actually start a
server live in `LaunchSpec`, which is excluded from serialization and from repr.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agentcapmap import __version__

INVENTORY_SCHEMA_VERSION = "1"


class Transport(StrEnum):
    STDIO = "stdio"
    HTTP = "http"  # Streamable HTTP
    SSE = "sse"  # legacy HTTP+SSE


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


class ToolDefinition(BaseModel):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] | None = None
    definition_hash: str


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
