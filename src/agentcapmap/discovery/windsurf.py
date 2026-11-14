"""Windsurf: `~/.codeium/windsurf/mcp_config.json`.

The `mcpServers` shape of Claude Desktop; remote entries use `serverUrl` (or `url`), and
`disabledTools` lists tools the client withholds from the model.
"""

from __future__ import annotations

from pathlib import Path

from agentcapmap.discovery._common import (
    ConfigError,
    ConfigFormat,
    deny_tools,
    load_jsonc,
    parse_server_map,
)
from agentcapmap.models import Server


def matches(path: Path) -> bool:
    return path.name.lower() == "mcp_config.json" and path.parent.name.lower() == "windsurf"


def parse(text: str, path: Path, display_path: str) -> list[Server]:
    data = load_jsonc(text)
    if not isinstance(data, dict):
        raise ConfigError("top level must be an object")
    entries = data.get("mcpServers")
    servers = parse_server_map(
        entries,
        config_path=display_path,
        text=text,
        section_key="mcpServers",
        base_dir=path.parent,
    )
    for server in servers:  # non-empty only when `entries` is a mapping
        deny_tools(server, dict(entries or {}).get(server.name), "disabledTools")
    return servers


FORMATS = [ConfigFormat("windsurf", "windsurf", matches, parse)]
