"""Find MCP servers that are running on this machine, whatever started them.

Config files only show what is *declared*. This reads the process table (read-only, the
current user's processes only) to find servers that are actually running, and compares
them with the scanned configs:

- a running process that matches a configured server marks that server as running
  (`Server.runtime`, declared);
- a running process that looks like an MCP server but matches no scanned config becomes a
  server of a `runtime:<client>` agent (undeclared), which policy rule CAP-010 reports;
- listening TCP sockets of those processes are recorded, and a non-loopback bind is
  flagged as exposed (CAP-011).

Design rules (see AGENTS.md, section 14):
- The process table is hostile input: any local process can name itself anything. Command
  lines are redacted like config values and bounded in size and count.
- Nothing is started, connected to or probed. Runtime-found servers are never
  enumerated, because re-running a command taken from the process table would execute
  attacker-influenced text.
- Heuristics identify candidates. A process that merely looks like an MCP server is
  reported as such; it is not proof.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Any, Protocol

from agentcapmap.discovery._common import infer_auth
from agentcapmap.graph.server_attrs import launch_source
from agentcapmap.limits import MAX_CMDLINE_CHARS, MAX_PROCESSES, MAX_RUNTIME_SERVERS
from agentcapmap.models import (
    Agent,
    Inventory,
    LaunchSpec,
    RuntimeInfo,
    Server,
    SourceLocation,
    Transport,
)
from agentcapmap.redact import get_logger, redact_args, redact_text

log = get_logger(__name__)

RUNTIME_CONFIG_PATH = "process table"
_MAX_ANCESTOR_HOPS = 12
_MAX_LISTENERS = 20


class RuntimeDiscoveryError(Exception):
    """The process table cannot be read (for example psutil is not installed)."""


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    ppid: int | None
    name: str
    cmdline: tuple[str, ...]


class ProcessSource(Protocol):
    def snapshot(self) -> list[ProcessInfo]:
        """The current user's processes."""

    def listening(self, pid: int) -> list[tuple[str, int]]:
        """Listening TCP sockets of one process as (host, port); never probes them."""


class PsutilSource:
    """Reads the process table with psutil (the optional `runtime` extra)."""

    def __init__(self) -> None:
        try:
            import psutil
        except ImportError:
            raise RuntimeDiscoveryError(
                "reading running processes needs psutil: pip install 'agent-capmap[runtime]'"
            ) from None
        self._psutil: Any = psutil

    def snapshot(self) -> list[ProcessInfo]:
        psutil = self._psutil
        try:
            me = psutil.Process().username()
        except psutil.Error as exc:
            raise RuntimeDiscoveryError(f"cannot identify the current user: {exc}") from None
        found: list[ProcessInfo] = []
        attrs = ["pid", "ppid", "name", "cmdline", "username"]
        for proc in psutil.process_iter(attrs, ad_value=None):
            info = proc.info
            if info.get("username") != me or not info.get("cmdline"):
                continue  # other users' processes, kernel threads, unreadable ones
            found.append(
                ProcessInfo(
                    pid=int(info["pid"]),
                    ppid=info.get("ppid"),
                    name=str(info.get("name") or ""),
                    cmdline=tuple(str(a) for a in info["cmdline"]),
                )
            )
            if len(found) >= MAX_PROCESSES:
                log.warning("process table truncated at %d processes", MAX_PROCESSES)
                break
        return found

    def listening(self, pid: int) -> list[tuple[str, int]]:
        psutil = self._psutil
        try:
            proc = psutil.Process(pid)
            read = getattr(proc, "net_connections", None) or proc.connections
            connections = read(kind="tcp")
        except psutil.Error:
            return []
        out = []
        for conn in connections:
            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                out.append((str(conn.laddr.ip), int(conn.laddr.port)))
        return sorted(set(out))[:_MAX_LISTENERS]


# --- classification ---------------------------------------------------------------------

# Client applications, by process name. Their process trees hold the servers they start.
_CLIENT_NAMES = {
    "claude": "claude",
    "cursor": "cursor",
    "code": "vscode",
    "code - insiders": "vscode",
    "windsurf": "windsurf",
    "zed": "zed",
}
_MCP_STRONG = re.compile(
    r"@modelcontextprotocol/|modelcontextprotocol|fastmcp|mcp[-_]server|server[-_]mcp"
    r"|mcp[-_]remote|mcp[-_]proxy|supergateway",
    re.IGNORECASE,
)
# A bare "mcp" word, but only in a program or script name, never in a flag such as
# `--mcp-config` (which belongs to a client, not a server).
_MCP_WORD = re.compile(r"(?<![a-z0-9])mcp(?![a-z0-9])", re.IGNORECASE)
_LOOPBACK_NAMES = frozenset({"localhost"})
# Programs that start servers from a package, module, script or image name.
_RUNTIMES = frozenset(
    {"node", "npx", "bunx", "bun", "deno", "tsx", "ts-node", "uvx", "uv", "python", "python3",
     "pythonw", "pipx", "docker", "podman", "java", "dotnet", "ruby", "php", "go"}
)  # fmt: skip
# Shells and everyday tools whose arguments are text or data, never a server's identity.
_NEVER_SERVERS = frozenset(
    {"bash", "sh", "zsh", "fish", "dash", "ksh", "tcsh", "cmd", "powershell", "pwsh", "conhost",
     "wsl", "grep", "rg", "egrep", "find", "cat", "less", "more", "tail", "head", "vim", "nvim",
     "nano", "git", "ssh", "sudo", "tmux", "screen", "ps", "pgrep", "pkill", "watch", "echo"}
)  # fmt: skip
_MAX_POSITIONAL = 6
_MAX_TOKEN_CHARS = 300
# Inline code or a command line passed as one argument, not a package or path.
_INLINE_CODE = re.compile(r"[\n;|&`$]")


def _stem(text: str) -> str:
    name = PurePath(text.replace("\\", "/")).name.lower()
    return re.sub(r"\.(exe|cmd|bat)$", "", name)


def client_of(proc: ProcessInfo) -> str | None:
    """The client application this process is, if it is one."""
    stem = _stem(proc.name) or _stem(proc.cmdline[0])
    joined = " ".join(proc.cmdline).lower()
    if "claude-code" in joined or "@anthropic-ai/claude-code" in joined:
        return "claude-code"
    return _CLIENT_NAMES.get(stem)


def _norm(text: str) -> str:
    return text.replace("\\", "/").lower()


def _mentions_mcp(text: str) -> bool:
    return bool(_MCP_STRONG.search(text) or _MCP_WORD.search(text))


def looks_like_mcp_server(proc: ProcessInfo) -> bool:
    """A cheap heuristic, tuned against false positives in a noisy process table.

    The program itself may be an MCP server binary. A known runtime (node, npx, uvx,
    python, docker, ...) counts when one of its first few positional arguments (the
    package, module, script or image) mentions MCP. Clients, shells and everything else
    never count: a shell's `-c "..."` text or `grep mcp` is not a server.
    """
    if client_of(proc) is not None:
        return False  # a client mentioning MCP flags is not a server
    stem = _stem(proc.cmdline[0])
    if stem in _NEVER_SERVERS:
        return False
    if _mentions_mcp(_norm(proc.cmdline[0])):
        return True
    if stem not in _RUNTIMES:
        return False
    positional = [a for a in proc.cmdline[1:] if not a.startswith("-")][:_MAX_POSITIONAL]
    return any(
        len(a) <= _MAX_TOKEN_CHARS and not _INLINE_CODE.search(a) and _mentions_mcp(_norm(a))
        for a in positional
    )


def _matches_declared(proc: ProcessInfo, server: Server) -> bool:
    """Does this process run the server a config declares? Conservative on purpose."""
    if server.transport is not Transport.STDIO or not server.launch.command:
        return False
    text = _norm(" ".join(proc.cmdline))
    source = launch_source(server)
    sid = source.source_id or ""
    if sid.startswith("npm:"):
        pattern = r"(?<![\w@.-])" + re.escape(sid[4:].lower()) + r"(?![\w.-])"
        return bool(re.search(pattern, text))
    if sid.startswith("pypi:"):
        parts = re.split(r"[-_.]+", sid[5:].lower())
        pattern = r"(?<![\w.-])" + r"[-_.]".join(re.escape(p) for p in parts) + r"(?![\w.-])"
        return bool(re.search(pattern, text))
    if sid.startswith("docker:"):
        return bool(re.search(r"(?<![\w.-])" + re.escape(sid[7:].lower()) + r"(?![\w.-])", text))
    # Local scripts and plain binaries: same program and the same arguments.
    command = server.launch.command
    args = server.launch.args
    return bool(
        _stem(command) == _stem(proc.cmdline[0])
        and [_norm(a) for a in args] == [_norm(a) for a in proc.cmdline[1:]]
    )


def _is_loopback(host: str) -> bool:
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False  # unknown form: treat as reachable, the safer reading


# --- discovery --------------------------------------------------------------------------


@dataclass
class RuntimeReport:
    declared: int = 0
    undeclared: int = 0
    exposed: int = 0
    notes: list[str] = field(default_factory=list)


def _ancestors(pid: int, by_pid: dict[int, ProcessInfo]) -> list[ProcessInfo]:
    chain: list[ProcessInfo] = []
    seen = {pid}
    current = by_pid.get(pid)
    for _ in range(_MAX_ANCESTOR_HOPS):
        if current is None or current.ppid is None or current.ppid in seen:
            break
        seen.add(current.ppid)
        current = by_pid.get(current.ppid)
        if current is not None:
            chain.append(current)
    return chain


_NODE_MODULES = re.compile(r"node_modules/(@[^/]+/[^/]+|[^/@][^/]*)/")


def _label(proc: ProcessInfo, redacted_args: list[str]) -> str:
    # `node .../node_modules/@scope/pkg/dist/index.js` is the package, whatever started it.
    for arg in redacted_args:
        if match := _NODE_MODULES.search(arg.replace("\\", "/")):
            return f"npm:{match.group(1).lower()}"
    stub = Server(
        name="x",
        transport=Transport.STDIO,
        command=redact_text(proc.cmdline[0]),
        args=redacted_args,
        auth=infer_auth(Transport.STDIO, {}, {}, [], None, None),
        location=SourceLocation(path=RUNTIME_CONFIG_PATH),
    )
    sid = launch_source(stub).source_id
    if sid and sid.startswith("local:"):
        return "local:" + PurePath(sid[6:].replace("\\", "/")).name  # the script, not its path
    return sid or _stem(proc.cmdline[0]) or "process"


def _runtime_server(
    proc: ProcessInfo,
    name: str,
    runtime: RuntimeInfo,
    redacted_args: list[str],
    raw_args: list[str],
) -> Server:
    transport = Transport.HTTP if runtime.listening else Transport.STDIO
    return Server(
        name=name,
        transport=transport,
        command=redact_text(proc.cmdline[0]),
        args=redacted_args,
        auth=infer_auth(transport, {}, {}, raw_args, None, None),
        location=SourceLocation(path=RUNTIME_CONFIG_PATH),
        runtime=runtime,
        launch=LaunchSpec(),  # never launchable: see the module docstring
    )


def discover_running(
    inventory: Inventory, source: ProcessSource, *, own_pid: int | None = None
) -> RuntimeReport:
    """Annotate declared servers that are running and add undeclared running ones."""
    own_pid = os.getpid() if own_pid is None else own_pid
    everything = [p for p in source.snapshot() if p.cmdline]
    by_pid = {p.pid: p for p in everything}
    # Never report ourselves: this process, the launcher/shell chain that started it (on
    # Windows a venv's python.exe is a separate launcher process) and anything running us.
    ours = {own_pid, *(a.pid for a in _ancestors(own_pid, by_pid))}
    processes = [
        p
        for p in everything
        if p.pid not in ours and "agentcapmap" not in _norm(" ".join(p.cmdline))
    ]
    by_pid = {p.pid: p for p in processes}
    declared = [s for agent in inventory.agents for s in agent.servers]

    # Candidates: anything that looks like an MCP server or runs a declared server.
    candidates: dict[int, ProcessInfo] = {}
    matched: dict[int, list[Server]] = {}
    for proc in processes:
        hits = [s for s in declared if _matches_declared(proc, s)]
        if hits:
            matched[proc.pid] = hits
        if hits or looks_like_mcp_server(proc):
            candidates[proc.pid] = proc

    # Wrappers (npx, uvx, shells) are ancestors of the real server: keep only leaves.
    wrapper_pids = {
        anc.pid for pid in candidates for anc in _ancestors(pid, by_pid) if anc.pid in candidates
    }
    leaves = [p for pid, p in sorted(candidates.items()) if pid not in wrapper_pids]

    report = RuntimeReport()
    new_servers: dict[str, list[Server]] = {}
    seen_undeclared: set[tuple[str, str]] = set()
    for proc in leaves:
        clients = [c for a in _ancestors(proc.pid, by_pid) if (c := client_of(a))]
        client = clients[0] if clients else None
        listening = source.listening(proc.pid)
        sockets = [f"{host}:{port}" for host, port in listening]
        exposed = any(not _is_loopback(host) for host, _ in listening)

        if proc.pid in matched:
            for server in matched[proc.pid]:
                server.runtime = RuntimeInfo(
                    pid=proc.pid, client=client, declared=True, listening=sockets, exposed=exposed
                )
            report.declared += 1
            report.exposed += int(exposed)
            continue

        if report.undeclared >= MAX_RUNTIME_SERVERS:
            report.notes.append(
                f"more than {MAX_RUNTIME_SERVERS} running servers; the rest are not listed"
            )
            break
        cmdline = [a[:MAX_CMDLINE_CHARS] for a in proc.cmdline]
        redacted = redact_args(cmdline[1:])
        key = (client or "", " ".join([_stem(cmdline[0]), *redacted]))
        if key in seen_undeclared:
            continue  # the same server started twice (for example two client windows)
        seen_undeclared.add(key)
        runtime = RuntimeInfo(
            pid=proc.pid, client=client, declared=False, listening=sockets, exposed=exposed
        )
        group = new_servers.setdefault(client or "unknown", [])
        name = _label(proc, redacted)
        if any(s.name == name for s in group):
            name = f"{name} (pid {proc.pid})"
        group.append(_runtime_server(proc, name, runtime, redacted, cmdline[1:]))
        report.undeclared += 1
        report.exposed += int(exposed)

    for client_name, servers in sorted(new_servers.items()):
        inventory.agents.append(
            Agent(
                id=f"runtime:{client_name}",
                client=client_name,
                config_path=RUNTIME_CONFIG_PATH,
                servers=servers,
            )
        )
    return report
