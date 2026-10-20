"""Claude Code's project-scoped `.mcp.json` and generic `mcp.json` files.

Both use the `mcpServers` map. A generic `mcp.json` that uses `servers` instead is
treated as VS Code-shaped.
"""

from __future__ import annotations

from pathlib import Path

from agentcapmap.discovery._common import ConfigError, ConfigFormat, load_jsonc, parse_server_map
from agentcapmap.models import Server


def parse(text: str, path: Path, display_path: str) -> list[Server]:
    data = load_jsonc(text)
    if not isinstance(data, dict):
        raise ConfigError("top level must be an object")
    key = "servers" if "servers" in data and "mcpServers" not in data else "mcpServers"
    return parse_server_map(
        data.get(key),
        config_path=display_path,
        text=text,
        section_key=key,
        base_dir=path.parent,
    )


FORMATS = [
    ConfigFormat("claude_code", "claude-code", lambda p: p.name.lower() == ".mcp.json", parse),
    ConfigFormat("mcp_json", "generic", lambda p: p.name.lower() == "mcp.json", parse),
]
