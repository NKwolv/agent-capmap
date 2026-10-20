"""Connect to MCP servers and list their tools. Only `initialize` and `tools/list` are sent."""

from __future__ import annotations

import os
import re
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agentcapmap import __version__
from agentcapmap.enumerate.hashing import server_definition_hash, tool_definition_hash
from agentcapmap.enumerate.http import LegacySseTransport, StreamableHttpTransport
from agentcapmap.enumerate.stdio import StdioTransport
from agentcapmap.enumerate.transport import (
    AuthRequired,
    MCPError,
    RequestTimeout,
    Transport,
    TransportError,
)
from agentcapmap.limits import MAX_CONFIG_BYTES, MAX_TOOLS_PER_SERVER
from agentcapmap.models import (
    AuthHint,
    AuthMethod,
    EnumerationResult,
    EnumerationStatus,
    Inventory,
    LaunchSpec,
    Server,
    ToolDefinition,
)
from agentcapmap.models import Transport as TransportKind
from agentcapmap.redact import get_logger, known_secrets, redact_text

log = get_logger(__name__)

PROTOCOL_VERSION = "2025-06-18"
DEFAULT_TIMEOUT = 30.0
_MAX_PAGES = 100
_VAR = re.compile(r"\$\{([^}]+)\}")


class UnresolvedVariable(Exception):
    pass


def _load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise ValueError("envFile too large")
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.removeprefix("export ").partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def _resolver(spec: LaunchSpec, env: dict[str, str]) -> Callable[[str], str]:
    base_dir = spec.base_dir or str(Path.cwd())

    def resolve(text: str) -> str:
        def sub(m: re.Match[str]) -> str:
            name = m.group(1).strip()
            if name in ("workspaceFolder", "workspaceRoot"):
                return base_dir
            if name == "userHome":
                return str(Path.home())
            if name.startswith("input:"):
                raise UnresolvedVariable(f"requires interactive input ${{{name}}}")
            if name.startswith("env:"):
                name = name[4:]
            name, _, default = name.partition(":-")
            if name in env:
                return env[name]
            if default:
                return default
            raise UnresolvedVariable(f"environment variable {name} is not set")

        return _VAR.sub(sub, text)

    return resolve


def resolve_launch(spec: LaunchSpec) -> LaunchSpec:
    """Expand ${...} references the way MCP clients do. Raises UnresolvedVariable."""
    lookup_env = dict(os.environ)
    resolve = _resolver(spec, lookup_env)
    file_env: dict[str, str] = {}
    if spec.env_file:
        env_path = Path(resolve(spec.env_file))
        if not env_path.is_absolute():
            env_path = Path(spec.base_dir or ".") / env_path
        try:
            file_env = _load_env_file(env_path)
        except OSError as exc:
            raise UnresolvedVariable(f"cannot read envFile: {exc.strerror}") from None
        except (UnicodeDecodeError, ValueError):
            raise UnresolvedVariable("cannot read envFile: not a UTF-8 text file") from None
        for value in file_env.values():
            known_secrets.add(value)
    lookup_env.update(file_env)
    env = {**file_env, **{k: resolve(v) for k, v in spec.env.items()}}
    lookup_env.update(env)
    resolve = _resolver(spec, lookup_env)
    resolved = LaunchSpec(
        command=resolve(spec.command) if spec.command else None,
        args=[resolve(a) for a in spec.args],
        env=env,
        cwd=resolve(spec.cwd) if spec.cwd else spec.base_dir,
        url=resolve(spec.url) if spec.url else None,
        headers={k: resolve(v) for k, v in spec.headers.items()},
        base_dir=spec.base_dir,
    )
    for value in [*resolved.env.values(), *resolved.headers.values()]:
        known_secrets.add(value)
    return resolved


def open_transport(server: Server, spec: LaunchSpec, timeout: float) -> Transport:
    if server.transport is TransportKind.STDIO:
        if not spec.command:
            raise TransportError("stdio server has no command")
        cwd = spec.cwd if spec.cwd and Path(spec.cwd).is_dir() else None
        return StdioTransport(spec.command, spec.args, spec.env, cwd)
    if not spec.url:
        raise TransportError("remote server has no URL")
    if urlsplit(spec.url).scheme.lower() not in ("http", "https"):
        raise TransportError("remote server URL must use http or https")
    if server.transport is TransportKind.SSE:
        return LegacySseTransport(spec.url, spec.headers, timeout)
    return StreamableHttpTransport(spec.url, spec.headers, timeout)


def _parse_tools(raw_tools: Any) -> list[ToolDefinition]:
    if not isinstance(raw_tools, list):
        raise TransportError("tools/list result has no 'tools' array")
    tools: list[ToolDefinition] = []
    for raw in raw_tools:
        if not isinstance(raw, dict) or not isinstance(raw.get("name"), str):
            log.debug("skipping malformed tool entry")
            continue
        description = raw.get("description")
        schema = raw.get("inputSchema")
        annotations = raw.get("annotations")
        description = description if isinstance(description, str) else ""
        schema = schema if isinstance(schema, dict) else {}
        tools.append(
            ToolDefinition(
                name=raw["name"],
                description=description,
                input_schema=schema,
                annotations=annotations if isinstance(annotations, dict) else None,
                definition_hash=tool_definition_hash(raw["name"], description, schema),
            )
        )
    return tools


def list_tools(transport: Transport, timeout: float) -> EnumerationResult:
    """Run the handshake and page through tools/list within one overall deadline."""
    deadline = time.monotonic() + timeout

    def remaining() -> float:
        left = deadline - time.monotonic()
        if left <= 0:
            raise RequestTimeout(f"enumeration exceeded {timeout:.0f}s")
        return left

    init = transport.request(
        "initialize",
        {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "agent-capmap", "version": __version__},
        },
        remaining(),
    )
    transport.notify("notifications/initialized")
    server_info = init.get("serverInfo") if isinstance(init.get("serverInfo"), dict) else None
    protocol_version = init.get("protocolVersion")
    capabilities = init.get("capabilities") if isinstance(init.get("capabilities"), dict) else {}

    tools: list[ToolDefinition] = []
    if capabilities is not None and "tools" in capabilities:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for _ in range(_MAX_PAGES):
            params: dict[str, Any] = {"cursor": cursor} if cursor else {}
            page = transport.request("tools/list", params, remaining())
            tools.extend(_parse_tools(page.get("tools")))
            if len(tools) > MAX_TOOLS_PER_SERVER:
                raise TransportError(f"server returned more than {MAX_TOOLS_PER_SERVER} tools")
            next_cursor = page.get("nextCursor")
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen_cursors:
                break
            seen_cursors.add(next_cursor)
            cursor = next_cursor

    return EnumerationResult(
        status=EnumerationStatus.OK,
        protocol_version=protocol_version if isinstance(protocol_version, str) else None,
        server_info=server_info,
        tools=tools,
        definition_hash=server_definition_hash(t.definition_hash for t in tools),
    )


def enumerate_server(server: Server, timeout: float = DEFAULT_TIMEOUT) -> EnumerationResult:
    """Enumerate one server's tools. Never raises; failures become a non-OK status."""
    if server.disabled:
        return EnumerationResult(status=EnumerationStatus.SKIPPED, error="disabled in config")
    try:
        spec = resolve_launch(server.launch)
    except UnresolvedVariable as exc:
        return EnumerationResult(status=EnumerationStatus.SKIPPED, error=redact_text(str(exc)))

    transport: Transport | None = None
    try:
        transport = open_transport(server, spec, timeout)
        result = list_tools(transport, timeout)
    except AuthRequired as exc:
        challenge = (exc.www_authenticate or "").lower()
        if server.auth.method is AuthMethod.UNKNOWN and "bearer" in challenge:
            server.auth = AuthHint(method=AuthMethod.OAUTH, evidence=["www-authenticate:Bearer"])
        return EnumerationResult(
            status=EnumerationStatus.AUTH_REQUIRED, error=redact_text(str(exc))
        )
    except RequestTimeout as exc:
        return EnumerationResult(status=EnumerationStatus.TIMEOUT, error=redact_text(str(exc)))
    except (TransportError, MCPError) as exc:
        return EnumerationResult(status=EnumerationStatus.ERROR, error=redact_text(str(exc)))
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception as exc:  # cleanup must not mask the real result
                log.debug("error closing transport for %s: %s", server.name, exc)

    if server.transport is not TransportKind.STDIO and server.auth.method is AuthMethod.UNKNOWN:
        server.auth = AuthHint(
            method=AuthMethod.NONE, evidence=["tools/list succeeded without credentials"]
        )
    return result


def enumerate_inventory(
    inventory: Inventory, *, timeout: float = DEFAULT_TIMEOUT, concurrency: int = 4
) -> None:
    """Enumerate every server in place."""
    servers: Iterable[Server] = [s for agent in inventory.agents for s in agent.servers]

    def run(server: Server) -> None:
        log.info("enumerating %s (%s)", server.name, server.transport.value)
        server.enumeration = enumerate_server(server, timeout)
        log.info(
            "  %s: %s, %d tool(s)",
            server.name,
            server.enumeration.status.value,
            len(server.enumeration.tools),
        )

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        list(pool.map(run, servers))
