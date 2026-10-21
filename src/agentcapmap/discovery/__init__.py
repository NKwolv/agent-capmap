"""Find MCP client configs and normalize them into `Agent -> [Server]`.

Each config file is one agent: the set of servers one client instance can reach.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

from agentcapmap.discovery import claude_code, claude_desktop, cursor, mcp_json, vscode
from agentcapmap.discovery._common import ConfigError, ConfigFormat, load_jsonc
from agentcapmap.limits import MAX_CONFIG_BYTES
from agentcapmap.models import Agent, DiscoveryError, Inventory
from agentcapmap.redact import get_logger

log = get_logger(__name__)

# Order matters: the first format whose `matches` accepts a path wins.
FORMATS: list[ConfigFormat] = [
    *claude_code.FORMATS,
    *claude_desktop.FORMATS,
    *cursor.FORMATS,
    *vscode.FORMATS,
    *mcp_json.FORMATS,
]
_BY_NAME = {f.name: f for f in FORMATS}

CANDIDATE_NAMES = frozenset(
    {"claude_desktop_config.json", "mcp.json", ".mcp.json", "settings.json"}
)
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        "dist",
        "build",
        "site-packages",
    }
)

__all__ = ["FORMATS", "ConfigError", "detect_format", "discover", "user_config_paths"]


def detect_format(path: Path, text: str | None = None) -> ConfigFormat | None:
    """Pick a format from the file location, falling back to sniffing the content."""
    for fmt in FORMATS:
        if fmt.matches(path):
            return fmt
    if text is None:
        return None
    try:
        data = load_jsonc(text)
    except ConfigError:
        return None
    if not isinstance(data, dict):
        return None
    if "mcpServers" in data:
        return _BY_NAME["mcp_json"]
    if isinstance(data.get("servers"), dict):
        return _BY_NAME["vscode"]
    mcp = data.get("mcp")
    if isinstance(mcp, dict) and isinstance(mcp.get("servers"), dict):
        return _BY_NAME["vscode_settings"]
    return None


def _display_path(path: Path, root: Path | None) -> str:
    if root is not None:
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            pass
    return path.as_posix()


def parse_config_agents(
    path: Path, *, root: Path | None = None, explicit: bool = False
) -> tuple[list[Agent], DiscoveryError | None]:
    """Parse one config file into its agents (most formats describe exactly one).

    Discovered-by-walk files that turn out not to be MCP configs return ([], None);
    `explicit` files the user named directly report an error instead.
    """
    display = _display_path(path, root)
    by_name = detect_format(path)
    limit = (by_name.max_bytes if by_name else None) or MAX_CONFIG_BYTES
    try:
        if path.stat().st_size > limit:
            return [], DiscoveryError(
                path=display, message=f"file larger than {limit} bytes; skipped"
            )
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        return [], DiscoveryError(path=display, message=f"cannot read file: {exc.strerror}")
    except UnicodeDecodeError:
        return [], DiscoveryError(path=display, message="cannot read file: not UTF-8 text")

    fmt = by_name or detect_format(path, text)
    if fmt is None:
        if explicit:
            return [], DiscoveryError(path=display, message="not a recognized MCP config")
        return [], None
    try:
        if fmt.parse_agents is not None:
            groups = fmt.parse_agents(text, path, display)
        else:
            groups = [("", fmt.parse(text, path, display))]
    except ConfigError as exc:
        return [], DiscoveryError(path=display, message=str(exc))

    agents = []
    for suffix, servers in groups:
        if not servers and not explicit and fmt.parse_agents is None:
            continue  # e.g. an unrelated settings.json
        agent_id = f"{fmt.client}:{display}" + (f"#{suffix}" if suffix else "")
        agents.append(Agent(id=agent_id, client=fmt.client, config_path=display, servers=servers))
    log.debug("parsed %s as %s: %d agent(s)", display, fmt.name, len(agents))
    return agents, None


def parse_config_file(
    path: Path, *, root: Path | None = None, explicit: bool = False
) -> tuple[Agent | None, DiscoveryError | None]:
    """Single-agent convenience wrapper around `parse_config_agents`."""
    agents, error = parse_config_agents(path, root=root, explicit=explicit)
    return (agents[0] if agents else None), error


def iter_candidate_files(root: Path) -> Iterator[Path]:
    """Walk a directory tree yielding files whose names match a known config format."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name.lower() in CANDIDATE_NAMES:
                path = Path(dirpath) / name
                if detect_format(path) is not None:
                    yield path


def user_config_paths() -> list[Path]:
    """Known per-user config locations for the supported clients on this OS."""
    home = Path.home()
    if sys.platform == "win32":
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        claude_dir, code_user = appdata / "Claude", appdata / "Code" / "User"
    elif sys.platform == "darwin":
        support = home / "Library" / "Application Support"
        claude_dir, code_user = support / "Claude", support / "Code" / "User"
    else:
        config = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config"))
        claude_dir, code_user = config / "Claude", config / "Code" / "User"
    claude_code_home = Path(os.environ.get("CLAUDE_CONFIG_DIR") or home)
    return [
        claude_code_home / ".claude.json",
        claude_dir / "claude_desktop_config.json",
        home / ".cursor" / "mcp.json",
        code_user / "mcp.json",
        code_user / "settings.json",
    ]


def discover(paths: Iterable[Path], *, user: bool = False, root: Path | None = None) -> Inventory:
    """Build an inventory from files and/or directories, plus user-level configs if asked.

    Config paths in the output are relative to `root` when given (the CLI passes the
    working directory, so SARIF paths are repository-relative), otherwise to each
    scanned directory.
    """
    inventory = Inventory()
    seen: set[Path] = set()

    def add(path: Path, root: Path | None, explicit: bool) -> None:
        resolved = path.resolve()
        if resolved in seen:
            return
        seen.add(resolved)
        agents, error = parse_config_agents(path, root=root, explicit=explicit)
        inventory.agents.extend(agents)
        if error is not None:
            log.warning("%s: %s", error.path, error.message)
            inventory.errors.append(error)

    for target in paths:
        if target.is_dir():
            for candidate in iter_candidate_files(target):
                add(candidate, root or target, explicit=False)
        elif target.is_file():
            add(target, root or Path.cwd(), explicit=True)
        else:
            inventory.errors.append(DiscoveryError(path=str(target), message="path does not exist"))

    if user:
        for candidate in user_config_paths():
            if candidate.is_file():
                add(candidate, None, explicit=False)

    return inventory
