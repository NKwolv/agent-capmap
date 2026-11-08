"""Runtime discovery of running MCP servers: detection, matching, safety, policy rules."""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from agentcapmap import cli
from agentcapmap.discovery import runtime
from agentcapmap.discovery.runtime import (
    ProcessInfo,
    PsutilSource,
    RuntimeDiscoveryError,
    client_of,
    discover_running,
    looks_like_mcp_server,
)
from agentcapmap.enumerate import enumerate_server
from agentcapmap.models import (
    Agent,
    AuthHint,
    AuthMethod,
    EnumerationStatus,
    Inventory,
    LaunchSpec,
    Server,
    SourceLocation,
    Transport,
)
from agentcapmap.policy import evaluate, load_policy
from tests import fake_secrets

OWN_PID = 99999


class FakeSource:
    def __init__(self, processes: list[ProcessInfo], listening: dict[int, list[tuple[str, int]]]):
        self._processes = processes
        self._listening = listening

    def snapshot(self) -> list[ProcessInfo]:
        return list(self._processes)

    def listening(self, pid: int) -> list[tuple[str, int]]:
        return self._listening.get(pid, [])


def proc(pid: int, ppid: int | None, *cmdline: str, name: str | None = None) -> ProcessInfo:
    return ProcessInfo(pid=pid, ppid=ppid, name=name or Path(cmdline[0]).name, cmdline=cmdline)


def source(*processes: ProcessInfo, **listening: list[tuple[str, int]]) -> FakeSource:
    return FakeSource(list(processes), {int(k.removeprefix("p")): v for k, v in listening.items()})


def declared_server(name: str, command: str, *args: str) -> Server:
    return Server(
        name=name,
        transport=Transport.STDIO,
        command=command,
        args=list(args),
        auth=AuthHint(method=AuthMethod.NONE),
        location=SourceLocation(path="mcp.json", line=1),
        launch=LaunchSpec(command=command, args=list(args)),
    )


def inventory_with(*servers: Server) -> Inventory:
    return Inventory(
        agents=[
            Agent(
                id="generic:mcp.json",
                client="generic",
                config_path="mcp.json",
                servers=list(servers),
            )
        ]
    )


CLAUDE = proc(10, 1, "C:/Program Files/Claude/Claude.exe")
SHELL = proc(11, 10, "C:/Windows/System32/cmd.exe", "/c", "npx", "-y", "@acme/mcp-mailer@2.0.1")
NPX = proc(
    12, 11, "C:/Program Files/nodejs/node.exe", "C:/npm/npx-cli.js", "-y", "@acme/mcp-mailer@2.0.1"
)
SERVER = proc(
    13, 12, "C:/Program Files/nodejs/node.exe",
    "C:\\Users\\u\\_npx\\abc\\node_modules\\@acme\\mcp-mailer\\dist\\index.js",
)  # fmt: skip


def run(inv: Inventory, *processes: ProcessInfo, **listening: list[tuple[str, int]]) -> Any:
    return discover_running(inv, source(*processes, **listening), own_pid=OWN_PID)


# --- detection ---------------------------------------------------------------------------


def test_wrapper_chain_yields_one_undeclared_server_under_its_client() -> None:
    inv = Inventory()
    report = run(inv, CLAUDE, SHELL, NPX, SERVER)
    assert (report.declared, report.undeclared) == (0, 1)
    [agent] = inv.agents
    assert agent.id == "runtime:claude" and agent.config_path == "process table"
    [server] = agent.servers
    assert server.name == "npm:@acme/mcp-mailer"  # the real server, not npx or cmd.exe
    assert server.runtime is not None
    assert (server.runtime.pid, server.runtime.client, server.runtime.declared) == (
        13,
        "claude",
        False,
    )


@pytest.mark.parametrize(
    "process",
    [
        proc(20, 1, "/bin/bash", "-c", "cat mcp.json && echo mcp-server"),
        proc(21, 1, "grep", "-r", "mcp-server", "."),
        proc(22, 1, "node", "app.js", "--mcp-config", "x.json"),
        proc(23, 1, "python", "-c", "import mcp_server; print(1)"),
        proc(24, 1, "C:/Program Files/Claude/Claude.exe", "--mcp-server-debug"),
        proc(25, 1, "node", "server.js"),
    ],
)
def test_noise_is_not_reported(process: ProcessInfo) -> None:
    inv = Inventory()
    assert run(inv, process).undeclared == 0 and inv.agents == []


@pytest.mark.parametrize(
    "process",
    [
        proc(30, 1, "npx", "-y", "@modelcontextprotocol/server-filesystem", "./data"),
        proc(31, 1, "uvx", "mcp-server-fetch"),
        proc(32, 1, "python", "-m", "mcp_server_time"),
        proc(33, 1, "docker", "run", "-i", "--rm", "ghcr.io/acme/mcp-thing"),
        proc(34, 1, "/usr/local/bin/mcp-server-foo", "--stdio"),
    ],
)
def test_common_launch_styles_are_recognized(process: ProcessInfo) -> None:
    assert looks_like_mcp_server(process)


def test_client_detection() -> None:
    assert client_of(CLAUDE) == "claude"
    assert client_of(proc(1, None, "node", "/x/@anthropic-ai/claude-code/cli.js")) == "claude-code"
    assert client_of(proc(2, None, "C:/x/Cursor.exe")) == "cursor"
    assert client_of(proc(3, None, "/usr/bin/code")) == "vscode"
    assert client_of(proc(4, None, "node", "server.js")) is None


def test_the_tool_never_reports_itself() -> None:
    launcher = proc(40, 1, ".venv/Scripts/python.exe", "-m", "agentcapmap", "scan", "mcp.json")
    child = proc(OWN_PID, 40, "python.exe", "-m", "agentcapmap", "scan", "mcp.json")
    other = proc(41, 1, "python", "run_agentcapmap_wrapper_for_mcp.py")
    inv = Inventory()
    assert run(inv, launcher, child, other).undeclared == 0


def test_duplicates_from_two_windows_collapse() -> None:
    twin = proc(50, 12, *SERVER.cmdline)
    inv = Inventory()
    assert run(inv, CLAUDE, SHELL, NPX, SERVER, twin).undeclared == 1


def test_caps_are_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runtime, "MAX_RUNTIME_SERVERS", 2)
    many = [proc(100 + i, 1, "uvx", f"mcp-server-{i}") for i in range(5)]
    report = run(Inventory(), *many)
    assert report.undeclared == 2 and report.notes


# --- matching declared servers -----------------------------------------------------------


@pytest.mark.parametrize(
    ("server", "process"),
    [
        (
            declared_server("mail", "npx", "-y", "@acme/mcp-mailer@2.0.1"),
            SERVER,
        ),
        (
            declared_server("time", "uvx", "mcp-server-time"),
            proc(60, 1, "C:/py/python.exe", "-m", "mcp_server_time"),
        ),
        (
            declared_server(
                "gh", "docker", "run", "-i", "--rm", "ghcr.io/github/github-mcp-server"
            ),
            proc(61, 1, "docker", "run", "-i", "--rm", "ghcr.io/github/github-mcp-server"),
        ),
        (
            declared_server("mine", "python", "tools/server.py", "--stdio"),
            proc(62, 1, "C:/Python/python.exe", "tools/server.py", "--stdio"),
        ),
    ],
    ids=["npm", "pypi", "docker", "local-script"],
)
def test_declared_servers_are_marked_running_not_duplicated(
    server: Server, process: ProcessInfo
) -> None:
    inv = inventory_with(server)
    report = run(inv, CLAUDE, process)
    assert (report.declared, report.undeclared) == (1, 0)
    assert len(inv.agents) == 1  # no runtime agent for a declared server
    assert server.runtime is not None and server.runtime.declared


def test_a_different_package_does_not_match_a_declared_one() -> None:
    inv = inventory_with(declared_server("mail", "npx", "-y", "@acme/mcp-mailer@2.0.1"))
    lookalike = proc(70, 1, "node", "C:/x/node_modules/@acme/mcp-mailer-evil/index.js")
    report = run(inv, lookalike)
    assert (report.declared, report.undeclared) == (0, 1)


# --- exposure and policy -----------------------------------------------------------------


def test_listening_sockets_and_exposure() -> None:
    local = proc(80, 1, "uvx", "mcp-server-a")
    public = proc(81, 1, "uvx", "mcp-server-b")
    inv = Inventory()
    report = run(
        inv, local, public, p80=[("127.0.0.1", 8000), ("::1", 8000)], p81=[("192.168.1.5", 9000)]
    )
    assert (report.undeclared, report.exposed) == (2, 1)
    servers = {s.name: s for a in inv.agents for s in a.servers}
    a, b = servers["pypi:mcp-server-a"], servers["pypi:mcp-server-b"]
    assert (
        a.runtime
        and not a.runtime.exposed
        and a.runtime.listening == ["127.0.0.1:8000", "::1:8000"]
    )
    assert b.runtime and b.runtime.exposed and b.transport is Transport.HTTP


def test_policy_rules_cap_010_and_cap_011() -> None:
    inv = Inventory()
    run(
        inv,
        proc(80, 1, "uvx", "mcp-server-a"),
        proc(81, 1, "uvx", "mcp-server-b"),
        p81=[("192.168.1.5", 9000)],
    )
    evaluation = evaluate(inv, load_policy(), None)
    by_rule: dict[str, list[str]] = {}
    for finding in evaluation.findings:
        by_rule.setdefault(finding.rule_id, []).extend(finding.servers)
    assert sorted(by_rule["CAP-010"]) == ["pypi:mcp-server-a", "pypi:mcp-server-b"]
    assert by_rule["CAP-011"] == ["pypi:mcp-server-b"]
    evidence = next(f for f in evaluation.findings if f.rule_id == "CAP-011").evidence[0]
    assert evidence.matched == {"exposure": "network"}


def test_declared_running_servers_do_not_trigger_cap_010() -> None:
    inv = inventory_with(declared_server("mail", "npx", "-y", "@acme/mcp-mailer@2.0.1"))
    run(inv, CLAUDE, SERVER)
    assert "CAP-010" not in {f.rule_id for f in evaluate(inv, load_policy(), None).findings}


# --- safety ------------------------------------------------------------------------------


def test_secrets_in_command_lines_are_redacted() -> None:
    secret_proc = proc(
        90,
        1,
        "uvx",
        "mcp-server-x",
        "--api-key",
        fake_secrets.GITHUB_PAT,
        f"TOKEN={fake_secrets.SLACK_TOKEN}",
    )
    inv = Inventory()
    run(inv, secret_proc)
    dumped = inv.model_dump_json()
    fake_secrets.assert_no_secrets(dumped)
    [server] = inv.agents[0].servers
    assert server.auth.method is AuthMethod.STATIC  # names only, as for configs


def test_runtime_only_servers_are_never_started(tmp_path: Path) -> None:
    marker = tmp_path / "ran.txt"
    # If this command were ever executed, it would leave the marker file behind.
    hostile = proc(91, 1, sys.executable, "-c", f"open({str(marker)!r}, 'w'); mcp_server=1")
    inv = Inventory()
    run(inv, hostile)
    runtime_servers = [s for a in inv.agents for s in a.servers]
    for server in runtime_servers:
        assert server.launch.command is None
        assert enumerate_server(server, timeout=5).status is EnumerationStatus.SKIPPED
    assert not marker.exists()


# --- the real process table and the CLI --------------------------------------------------


def test_psutil_source_reads_this_process() -> None:
    src = PsutilSource()
    me = next(p for p in src.snapshot() if p.pid == os.getpid())
    assert me.cmdline and me.ppid is not None
    assert isinstance(src.listening(os.getpid()), list)


def test_missing_psutil_gives_an_actionable_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "psutil", None)
    with pytest.raises(RuntimeDiscoveryError, match=r"agent-capmap\[runtime\]"):
        PsutilSource()


def test_cli_scan_running(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "PsutilSource", lambda: source(CLAUDE, SHELL, NPX, SERVER))
    config = tmp_path / "mcp.json"
    config.write_text('{"mcpServers": {}}', encoding="utf-8")
    assert cli.main(["scan", str(config), "--running"]) == 0
    out, err = capsys.readouterr()
    assert "0 declared and 1 undeclared" in err and "add --user" in err
    data = json.loads(out)
    assert [a["id"] for a in data["agents"]] == ["generic:" + config.as_posix(), "runtime:claude"]
    assert data["agents"][1]["servers"][0]["runtime"]["pid"] == 13


def test_cli_running_without_psutil_exits_with_a_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def missing() -> Any:
        raise RuntimeDiscoveryError(
            "reading running processes needs psutil: pip install 'agent-capmap[runtime]'"
        )

    monkeypatch.setattr(cli, "PsutilSource", missing)
    config = tmp_path / "mcp.json"
    config.write_text('{"mcpServers": {}}', encoding="utf-8")
    assert cli.main(["scan", str(config), "--running"]) == 2
    assert "agent-capmap[runtime]" in capsys.readouterr().err


def test_subprocess_import_does_not_require_psutil() -> None:
    """The base install works without the optional extra: nothing imports psutil eagerly."""
    code = "import sys; sys.modules['psutil'] = None; import agentcapmap.cli"
    assert subprocess.run([sys.executable, "-I", "-c", code], check=False).returncode == 0  # noqa: S603
