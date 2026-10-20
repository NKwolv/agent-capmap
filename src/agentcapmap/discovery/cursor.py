"""Cursor: `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global).

Same `mcpServers` shape as Claude Desktop, but entries may be remote (`url` + `headers`)
and values may use `${env:NAME}` interpolation.
"""

from __future__ import annotations

from pathlib import Path

from agentcapmap.discovery._common import ConfigError, ConfigFormat, load_jsonc, parse_server_map
from agentcapmap.models import Server


def matches(path: Path) -> bool:
    return path.name.lower() == "mcp.json" and path.parent.name.lower() == ".cursor"


def parse(text: str, path: Path, display_path: str) -> list[Server]:
    data = load_jsonc(text)
    if not isinstance(data, dict):
        raise ConfigError("top level must be an object")
    # Workspace root is the directory containing .cursor/.
    return parse_server_map(
        data.get("mcpServers"),
        config_path=display_path,
        text=text,
        section_key="mcpServers",
        base_dir=path.parent.parent,
    )


FORMATS = [ConfigFormat("cursor", "cursor", matches, parse)]
