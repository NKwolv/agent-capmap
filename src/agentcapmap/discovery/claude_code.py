"""Claude Code: project `.mcp.json`, the user's `~/.claude.json`, and permission settings.

Where Claude Code keeps MCP servers (https://code.claude.com/docs/en/mcp):
- user scope:    top-level `mcpServers` in `~/.claude.json` (every project)
- local scope:   `projects.<path>.mcpServers` in `~/.claude.json` (one project, private)
- project scope: `.mcp.json` at the project root (shared through version control)
The same name in several scopes resolves local > project > user, whole entry.

Approval (https://code.claude.com/docs/en/permissions): in the default permission
mode Claude Code asks before an MCP tool call unless a `permissions.allow` rule
(`mcp__<server>`, `mcp__<server>__*`, `mcp__<server>__<tool>`) covers it.
`bypassPermissions` and `auto` modes skip the human prompt; `dontAsk` refuses calls that
would prompt; `permissions.deny` rules remove tools.

`~/.claude.json` also holds account data (and possibly `primaryApiKey`). Only MCP
server entries and per-project MCP toggles are read from it; nothing else is output.
"""

from __future__ import annotations

import fnmatch
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from agentcapmap.discovery._common import ConfigError, ConfigFormat, load_jsonc, parse_server_map
from agentcapmap.limits import MAX_CONFIG_BYTES
from agentcapmap.models import ApprovalConfig, Server
from agentcapmap.redact import get_logger, known_secrets

log = get_logger(__name__)

# ~/.claude.json grows with per-project history; allow more than a normal config.
USER_CONFIG_MAX_BYTES = 64 * 1024 * 1024
_RULE_NAME = re.compile(r"[^A-Za-z0-9_-]")
_PROMPTING_MODES = {None, "default", "manual", "acceptEdits", "plan"}
_NO_PROMPT_MODES = {"bypassPermissions", "auto"}


@dataclass
class Permissions:
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)
    mode: str | None = None
    sources: list[str] = field(default_factory=list)
    disabled_mcpjson: set[str] = field(default_factory=set)


def _read_json(path: Path, limit: int = MAX_CONFIG_BYTES) -> dict[str, Any] | None:
    try:
        if not path.is_file() or path.stat().st_size > limit:
            return None
        data = load_jsonc(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, ConfigError) as exc:
        log.warning("ignoring unreadable Claude Code file %s: %s", path.name, exc)
        return None
    return data if isinstance(data, dict) else None


def _strings(value: Any) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


def read_permissions(settings_files: list[Path]) -> Permissions:
    """Merge permission settings; later files (higher precedence) win for the mode."""
    perms = Permissions()
    for path in settings_files:
        data = _read_json(path)
        if data is None:
            continue
        raw = data.get("permissions")
        section: dict[str, Any] = raw if isinstance(raw, dict) else {}
        perms.allow += _strings(section.get("allow"))
        perms.deny += _strings(section.get("deny"))
        mode = section.get("defaultMode", data.get("defaultMode"))
        if isinstance(mode, str):
            perms.mode = mode
        perms.disabled_mcpjson |= set(_strings(data.get("disabledMcpjsonServers")))
        perms.sources.append(path.name if path.parent.name != ".claude" else f".claude/{path.name}")
    return perms


def _tool_pattern(rule: str, server_key: str) -> str | None:
    """The tool-name glob an `mcp__...` rule grants for this server, if any."""
    if "(" in rule:  # Claude Code skips parameterized mcp__ rules in settings files
        return None
    if rule == server_key:
        return "*"
    prefix = f"{server_key}__"
    if rule.startswith(prefix):
        return rule[len(prefix) :] or "*"
    return None


def server_approval(
    name: str, perms: Permissions, extra_allow: Sequence[str] = ()
) -> ApprovalConfig:
    key = "mcp__" + _RULE_NAME.sub("_", name)
    allow = [p for r in [*perms.allow, *extra_allow] if (p := _tool_pattern(r, key))]
    deny = [p for r in perms.deny if (p := _tool_pattern(r, key))]
    if any(r in ("*", "mcp__*") for r in perms.deny):
        deny.append("*")
    mode = perms.mode
    gate: Literal["required", "none", "unknown", "blocked"]
    if mode in _NO_PROMPT_MODES:
        gate, reason = "none", f"Claude Code permission mode {mode!r} skips approval prompts"
    elif mode == "dontAsk":
        gate, reason = "blocked", "Claude Code 'dontAsk' mode refuses calls that need approval"
    elif mode in _PROMPTING_MODES:
        gate, reason = "required", "Claude Code asks before MCP tool calls in this permission mode"
    else:
        gate, reason = "unknown", f"unrecognized Claude Code permission mode {mode!r}"
    return ApprovalConfig(
        auto_approve_all="*" in allow,
        auto_approved_patterns=sorted(set(allow)),
        denied_patterns=sorted(set(deny)),
        default_gate=gate,
        default_reason=reason,
        sources=[f"settings: {', '.join(perms.sources)}"] if perms.sources else [],
    )


def tool_matches(patterns: list[str], tool: str) -> bool:
    return any(fnmatch.fnmatchcase(tool, p) for p in patterns)


def _project_settings(project: Path) -> list[Path]:
    return [project / ".claude" / "settings.json", project / ".claude" / "settings.local.json"]


def _apply(servers: list[Server], perms: Permissions, extra_allow: Sequence[str] = ()) -> None:
    for server in servers:
        server.approval = server_approval(server.name, perms, extra_allow)


# --- project .mcp.json ------------------------------------------------------------------


def _parse_mcp_json(text: str, path: Path, display: str) -> list[Server]:
    data = load_jsonc(text)
    if not isinstance(data, dict):
        raise ConfigError("top level must be an object")
    return parse_server_map(
        data.get("mcpServers"),
        config_path=display,
        text=text,
        section_key="mcpServers",
        base_dir=path.parent,
    )


def parse_project(text: str, path: Path, display: str) -> list[Server]:
    """A repository's `.mcp.json`, with approvals from that project's own settings only
    (a repository scan must not depend on the scanning machine's user settings)."""
    servers = _parse_mcp_json(text, path, display)
    perms = read_permissions(_project_settings(path.parent))
    servers = [s for s in servers if s.name not in perms.disabled_mcpjson]
    _apply(servers, perms)
    return servers


# --- ~/.claude.json ---------------------------------------------------------------------


def _merge(*scopes: list[Server]) -> list[Server]:
    """First scope wins per name (pass highest precedence first)."""
    merged: dict[str, Server] = {}
    for scope in scopes:
        for server in scope:
            merged.setdefault(server.name, server)
    return list(merged.values())


def _section_start(text: str, project_key: str) -> int:
    """Offset just after the project's key, matching the JSON-escaped form in the file."""
    match = re.search(re.escape(json.dumps(project_key)) + r"\s*:", text)
    return match.end() if match else 0


def parse_user_agents(text: str, path: Path, display: str) -> list[tuple[str, list[Server]]]:
    data = load_jsonc(text)
    if not isinstance(data, dict):
        raise ConfigError("top level must be an object")
    if isinstance(data.get("primaryApiKey"), str):
        known_secrets.add(data["primaryApiKey"])  # never output, scrubbed if it ever appears

    user_settings = [path.parent / ".claude" / "settings.json"]

    def user_scope() -> list[Server]:
        return parse_server_map(
            data.get("mcpServers"),
            config_path=display,
            text=text,
            section_key="mcpServers",
            base_dir=path.parent,
        )

    user_servers = user_scope()
    _apply(user_servers, read_permissions(user_settings))
    agents: list[tuple[str, list[Server]]] = [("user", user_servers)]

    projects = data.get("projects")
    for project_key, entry in sorted(projects.items() if isinstance(projects, dict) else []):
        if not isinstance(entry, dict):
            continue
        project = Path(project_key)
        local = parse_server_map(
            entry.get("mcpServers"),
            config_path=display,
            text=text,
            section_key="mcpServers",
            base_dir=project,
            search_from=_section_start(text, project_key),
        )
        mcp_json = project / ".mcp.json"
        shared: list[Server] = []
        if mcp_json.is_file():
            try:
                shared_text = mcp_json.read_text(encoding="utf-8-sig")
                shared = _parse_mcp_json(shared_text, mcp_json, mcp_json.as_posix())
            except (OSError, UnicodeDecodeError, ConfigError) as exc:
                log.warning("ignoring %s: %s", mcp_json.as_posix(), exc)
        if not local and not shared:
            continue  # same reach as the user-scope agent

        perms = read_permissions([*user_settings, *_project_settings(project)])
        perms.disabled_mcpjson |= set(_strings(entry.get("disabledMcpjsonServers")))
        shared = [s for s in shared if s.name not in perms.disabled_mcpjson]
        servers = _merge(local, shared, user_scope())
        toggled_off = set(_strings(entry.get("disabledMcpServers")))
        for server in servers:
            if server.name in toggled_off:
                server.disabled = True
        _apply(servers, perms, _strings(entry.get("allowedTools")))
        agents.append((f"project:{project.as_posix()}", servers))
    return agents


def _parse_user(text: str, path: Path, display: str) -> list[Server]:
    return parse_user_agents(text, path, display)[0][1]


FORMATS = [
    ConfigFormat(
        "claude_code_user",
        "claude-code",
        lambda p: p.name.lower() == ".claude.json",
        _parse_user,
        parse_agents=parse_user_agents,
        max_bytes=USER_CONFIG_MAX_BYTES,
    ),
    ConfigFormat(
        "claude_code", "claude-code", lambda p: p.name.lower() == ".mcp.json", parse_project
    ),
]
