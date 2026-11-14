"""OpenAI Codex CLI: `[mcp_servers.<name>]` tables in `~/.codex/config.toml`.

Local servers use `command`, `args`, `env` and `cwd`; remote ones `url` with
`bearer_token_env_var`, `http_headers` or `env_http_headers` (header name to environment
variable). `enabled = false` turns a server off and `disabled_tools` removes tools.
`enabled_tools` (an allowlist) is not applied, which can only over-report.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from agentcapmap.discovery._common import ConfigError, ConfigFormat, build_server, deny_tools
from agentcapmap.models import Server


def matches(path: Path) -> bool:
    return path.name.lower() == "config.toml" and path.parent.name.lower() == ".codex"


def _table(value: Any, field: str, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"server {name!r}: {field!r} must be a table")
    return value


def _normalize(name: str, entry: dict[str, Any]) -> dict[str, Any]:
    headers = dict(_table(entry.get("http_headers"), "http_headers", name))
    # Values come from the environment at launch; `${NAME}` is resolved the same way here.
    for header, variable in _table(entry.get("env_http_headers"), "env_http_headers", name).items():
        headers[header] = "${" + str(variable) + "}"
    if bearer := entry.get("bearer_token_env_var"):
        headers["Authorization"] = "Bearer ${" + str(bearer) + "}"
    normalized = {key: entry.get(key) for key in ("command", "args", "env", "cwd", "url")}
    normalized["headers"] = headers or None
    normalized["disabled"] = entry.get("enabled") is False
    return normalized


def _line(text: str, name: str) -> int | None:
    """1-based line of the `[mcp_servers.<name>]` table header (or a sub-table of it)."""
    key = re.escape(name)
    header = re.compile(
        r"^[ \t]*\[[ \t]*mcp_servers[ \t]*\.[ \t]*"
        + f"(?:\"{key}\"|'{key}'|{key})"
        + r"[ \t]*[\].]",
        re.MULTILINE,
    )
    match = header.search(text)
    return text.count("\n", 0, match.start()) + 1 if match else None


def parse(text: str, path: Path, display_path: str) -> list[Server]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        raise ConfigError("invalid TOML") from None
    except RecursionError:
        raise ConfigError("invalid TOML: nested too deeply") from None
    entries = data.get("mcp_servers")
    if entries is None:
        return []
    if not isinstance(entries, dict):
        raise ConfigError("'mcp_servers' must be a table of servers")
    servers = []
    for name, entry in entries.items():
        if not isinstance(entry, dict):
            raise ConfigError(f"server {name!r}: entry must be a table")
        server = build_server(
            name,
            _normalize(name, entry),
            config_path=display_path,
            text=text,
            section_start=0,
            base_dir=path.parent,
        )
        server.location.line = _line(text, name)
        deny_tools(server, entry, "disabled_tools")
        servers.append(server)
    return servers


FORMATS = [ConfigFormat("codex", "codex", matches, parse)]
