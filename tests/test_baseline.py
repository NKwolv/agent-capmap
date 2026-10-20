import json
from pathlib import Path

import pytest

from agentcapmap.baseline import BaselineError, create_baseline, diff_server, load_baseline
from agentcapmap.models import EnumerationStatus
from tests.scenarios import load_scenario

GOOD_HASH = "a" * 64


def _write(tmp_path: Path, data: object) -> Path:
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(data))
    return path


def test_round_trip(tmp_path: Path) -> None:
    inventory = load_scenario("trifecta")
    baseline = create_baseline(inventory)
    assert len(baseline.servers) == 2
    path = tmp_path / "b.json"
    path.write_text(baseline.model_dump_json())
    assert load_baseline(path) == baseline
    for server in inventory.agents[0].servers:
        diff = diff_server(baseline, server)
        assert diff is not None and not diff


def test_failed_or_disabled_servers_are_not_pinned() -> None:
    inventory = load_scenario("trifecta")
    github, mailer = inventory.agents[0].servers
    assert github.enumeration is not None
    github.enumeration.status = EnumerationStatus.ERROR
    mailer.disabled = True
    assert create_baseline(inventory).servers == {}


def test_config_change_is_a_new_server_not_a_rug_pull() -> None:
    inventory = load_scenario("trifecta")
    baseline = create_baseline(inventory)
    server = inventory.agents[0].servers[1]
    server.args = ["-y", "@acme/mcp-mailer@2.0.2"]
    assert diff_server(baseline, server) is None


@pytest.mark.parametrize(
    "data",
    [
        {"baseline_version": 2, "servers": {}},
        {"baseline_version": 1, "servers": {"not-a-hash": {"name": "x", "tools": {}}}},
        {"baseline_version": 1, "servers": {GOOD_HASH: {"name": "x", "tools": {"t": "zz"}}}},
        {"baseline_version": 1, "servers": {GOOD_HASH: {"name": "x", "tools": {}, "extra": 1}}},
        {"baseline_version": 1, "servers": {}, "include": "/etc/passwd"},
        {"baseline_version": "1", "servers": {}},
        [],
    ],
)
def test_malformed_baselines_are_rejected(tmp_path: Path, data: object) -> None:
    with pytest.raises(BaselineError, match="expected format"):
        load_baseline(_write(tmp_path, data))


def test_baseline_io_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(BaselineError, match="cannot read"):
        load_baseline(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("[" * 100_000)
    with pytest.raises(BaselineError, match="not valid JSON"):
        load_baseline(bad)
    monkeypatch.setattr("agentcapmap.baseline._MAX_BASELINE_BYTES", 10)
    with pytest.raises(BaselineError, match="larger than 10 bytes"):
        load_baseline(_write(tmp_path, {"baseline_version": 1, "servers": {}}))
