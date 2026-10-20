"""VS Code: `.vscode/mcp.json`, user-profile `mcp.json`, and the `mcp` key in settings.json.

VS Code files are JSONC. Servers live under `servers` (not `mcpServers`), declare
`type` explicitly, and may reference prompted secrets via `${input:id}`.
"""

from __future__ import annotations

import re
from pathlib import Path

from agentcapmap.discovery._common import ConfigError, ConfigFormat, load_jsonc, parse_server_map
from agentcapmap.models import Server


def _workspace_root(path: Path) -> Path:
    return path.parent.parent if path.parent.name.lower() == ".vscode" else path.parent


def matches_mcp_json(path: Path) -> bool:
    return path.name.lower() == "mcp.json" and path.parent.name.lower() in (".vscode", "user")


def parse_mcp_json(text: str, path: Path, display_path: str) -> list[Server]:
    data = load_jsonc(text)
    if not isinstance(data, dict):
        raise ConfigError("top level must be an object")
    return parse_server_map(
        data.get("servers"),
        config_path=display_path,
        text=text,
        section_key="servers",
        base_dir=_workspace_root(path),
    )


def matches_settings(path: Path) -> bool:
    return path.name.lower() == "settings.json" and path.parent.name.lower() in (".vscode", "user")


def parse_settings(text: str, path: Path, display_path: str) -> list[Server]:
    """settings.json with an embedded `"mcp": {"servers": {...}}` block."""
    data = load_jsonc(text)
    if not isinstance(data, dict):
        raise ConfigError("top level must be an object")
    mcp = data.get("mcp")
    if mcp is None:
        return []
    if not isinstance(mcp, dict):
        raise ConfigError("'mcp' must be an object")
    m = re.search(r'"mcp"\s*:', text)
    return parse_server_map(
        mcp.get("servers"),
        config_path=display_path,
        text=text,
        section_key="servers",
        base_dir=_workspace_root(path),
        search_from=m.end() if m else 0,
    )


FORMATS = [
    ConfigFormat("vscode", "vscode", matches_mcp_json, parse_mcp_json),
    ConfigFormat("vscode_settings", "vscode", matches_settings, parse_settings),
]
