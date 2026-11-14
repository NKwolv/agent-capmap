"""Zed: the `context_servers` key of `settings.json` (user or project `.zed/`).

Entries are `{"command": "...", "args": [...], "env": {...}}`, the older nested
`{"command": {"path": "...", "args": [...], "env": {...}}}`, or remote
`{"url": "...", "headers": {...}}`. `"enabled": false` turns one off.

Servers installed by a Zed extension appear with settings only and no command: what
they launch is not in this file, so they are skipped (and are not assessed).
`agent.always_allow_tool_actions: true` means no tool call asks for confirmation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agentcapmap.discovery._common import ConfigError, ConfigFormat, load_jsonc, parse_server_map
from agentcapmap.models import Server

_ALWAYS_ALLOW = "always_allow_tool_actions"


def matches(path: Path) -> bool:
    return path.name.lower() == "settings.json" and path.parent.name.lower() in (".zed", "zed")


def _normalize(entry: Any) -> Any:
    if not isinstance(entry, dict):
        return entry
    entry = dict(entry)
    command = entry.get("command")
    if isinstance(command, dict):  # older shape: command.path / command.args / command.env
        entry["command"] = command.get("path")
        entry.setdefault("args", command.get("args"))
        entry.setdefault("env", command.get("env"))
    if entry.get("enabled") is False:
        entry["disabled"] = True
    return entry


def _launchable(entry: Any) -> bool:
    return not isinstance(entry, dict) or bool(entry.get("command") or entry.get("url"))


def _always_allow(data: dict[str, Any]) -> bool:
    for section in ("agent", "assistant"):
        settings = data.get(section)
        if isinstance(settings, dict) and settings.get(_ALWAYS_ALLOW) is True:
            return True
    return False


def parse(text: str, path: Path, display_path: str) -> list[Server]:
    data = load_jsonc(text)
    if not isinstance(data, dict):
        raise ConfigError("top level must be an object")
    entries = data.get("context_servers")
    if entries is None:
        return []
    if not isinstance(entries, dict):
        raise ConfigError("'context_servers' must be an object mapping names to servers")
    normalized = {name: _normalize(entry) for name, entry in entries.items()}
    base_dir = path.parent.parent if path.parent.name.lower() == ".zed" else path.parent
    servers = parse_server_map(
        {name: entry for name, entry in normalized.items() if _launchable(entry)},
        config_path=display_path,
        text=text,
        section_key="context_servers",
        base_dir=base_dir,
    )
    if _always_allow(data):
        for server in servers:
            server.approval.auto_approve_all = True
            server.approval.sources.append(f"agent.{_ALWAYS_ALLOW}")
    return servers


FORMATS = [ConfigFormat("zed", "zed", matches, parse)]
