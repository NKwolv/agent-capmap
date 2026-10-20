"""Claude Desktop: claude_desktop_config.json with a top-level `mcpServers` map."""

from __future__ import annotations

from pathlib import Path

from agentcapmap.discovery._common import ConfigError, ConfigFormat, load_jsonc, parse_server_map
from agentcapmap.models import Server


def matches(path: Path) -> bool:
    return path.name.lower() == "claude_desktop_config.json"


def parse(text: str, path: Path, display_path: str) -> list[Server]:
    data = load_jsonc(text)
    if not isinstance(data, dict):
        raise ConfigError("top level must be an object")
    return parse_server_map(
        data.get("mcpServers"),
        config_path=display_path,
        text=text,
        section_key="mcpServers",
        base_dir=path.parent,
    )


FORMATS = [ConfigFormat("claude_desktop", "claude-desktop", matches, parse)]
