"""Gemini CLI (and its fork Qwen Code): the `mcpServers` key of `settings.json`.

Read from `~/.gemini/settings.json` and a project `.gemini/settings.json` (`.qwen` for
Qwen Code). Differences from the common shape: `httpUrl` is a Streamable HTTP endpoint
and a bare `url` is legacy SSE; `trust: true` skips every confirmation for the server
(read by the shared parser); `excludeTools` removes tools from the model.

`includeTools` (an allowlist) is not applied: tools outside it are still counted, which
can only over-report what the agent can reach, never hide something.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from agentcapmap.discovery._common import (
    ConfigError,
    ConfigFormat,
    deny_tools,
    load_jsonc,
    parse_server_map,
)
from agentcapmap.models import Server

_DIRS = {".gemini": "gemini-cli", ".qwen": "qwen-code"}


def _matches(directory: str) -> Callable[[Path], bool]:
    def matches(path: Path) -> bool:
        return path.name.lower() == "settings.json" and path.parent.name.lower() == directory

    return matches


def _normalize(entry: Any) -> Any:
    if not isinstance(entry, dict):
        return entry
    entry = dict(entry)
    http_url = entry.pop("httpUrl", None)
    if http_url:
        entry["url"] = http_url
        entry.setdefault("type", "http")
    elif entry.get("url") and not (entry.get("type") or entry.get("transport")):
        entry["type"] = "sse"
    return entry


def parse(text: str, path: Path, display_path: str) -> list[Server]:
    data = load_jsonc(text)
    if not isinstance(data, dict):
        raise ConfigError("top level must be an object")
    entries = data.get("mcpServers")
    if entries is None:
        return []
    if not isinstance(entries, dict):
        raise ConfigError("'mcpServers' must be an object mapping names to servers")
    servers = parse_server_map(
        {name: _normalize(entry) for name, entry in entries.items()},
        config_path=display_path,
        text=text,
        section_key="mcpServers",
        base_dir=path.parent.parent,  # the directory holding .gemini/
    )
    for server in servers:
        deny_tools(server, entries[server.name], "excludeTools")
    return servers


FORMATS = [
    ConfigFormat(client.replace("-", "_"), client, _matches(directory), parse)
    for directory, client in _DIRS.items()
]
