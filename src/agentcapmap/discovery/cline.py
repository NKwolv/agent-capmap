"""Cline and Roo Code (VS Code extensions).

Cline keeps `cline_mcp_settings.json` in its VS Code global storage; Roo Code keeps
`mcp_settings.json` there and also reads a project `.roo/mcp.json`. Both use the
`mcpServers` shape with `disabled`, and list tools that skip confirmation under
`autoApprove` (Cline) or `alwaysAllow` (Roo), which the shared parser already reads.
"""

from __future__ import annotations

from pathlib import Path

from agentcapmap.discovery._common import ConfigError, ConfigFormat, load_jsonc, parse_server_map
from agentcapmap.models import Server


def matches_cline(path: Path) -> bool:
    return path.name.lower() == "cline_mcp_settings.json"


def matches_roo(path: Path) -> bool:
    name, parent = path.name.lower(), path.parent.name.lower()
    if name == "mcp.json":
        return parent == ".roo"
    return (
        name == "mcp_settings.json"
        and parent == "settings"
        and path.parent.parent.name.lower().startswith("rooveterinaryinc.")
    )


def parse(text: str, path: Path, display_path: str) -> list[Server]:
    data = load_jsonc(text)
    if not isinstance(data, dict):
        raise ConfigError("top level must be an object")
    # A project `.roo/mcp.json` resolves paths from the workspace root.
    base_dir = path.parent.parent if path.parent.name.lower() == ".roo" else path.parent
    return parse_server_map(
        data.get("mcpServers"),
        config_path=display_path,
        text=text,
        section_key="mcpServers",
        base_dir=base_dir,
    )


FORMATS = [
    ConfigFormat("cline", "cline", matches_cline, parse),
    ConfigFormat("roo_code", "roo-code", matches_roo, parse),
]
