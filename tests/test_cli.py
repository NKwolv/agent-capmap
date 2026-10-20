import json
from collections.abc import Callable
from pathlib import Path

import pytest

from agentcapmap import cli
from agentcapmap.cli import main
from tests import fake_secrets
from tests.conftest import CONFIG_FIXTURES
from tests.fake_llm import FakeProvider
from tests.scenarios import FIXTURES, load_scenario


def test_scan_fixture_directory(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(CONFIG_FIXTURES), "-vv"]) == 0
    out, err = capsys.readouterr()
    fake_secrets.assert_no_secrets(out)
    fake_secrets.assert_no_secrets(err)
    data = json.loads(out)
    assert data["schema_version"] == "1"
    assert len(data["agents"]) == 6
    assert data["errors"] == []
    assert all(s.get("enumeration") is None for a in data["agents"] for s in a["servers"])


def test_scan_writes_output_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out_file = tmp_path / "inventory.json"
    assert main(["scan", str(CONFIG_FIXTURES / "generic" / "mcp.json"), "-o", str(out_file)]) == 0
    assert capsys.readouterr().out == ""
    text = out_file.read_text(encoding="utf-8")
    fake_secrets.assert_no_secrets(text)
    assert [s["name"] for s in json.loads(text)["agents"][0]["servers"]] == ["zapier", "proxy"]


def test_scan_enumerate_end_to_end_without_leaks(
    mock_stdio_config: Callable[..., tuple[Path, Path]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    config, _ = mock_stdio_config(
        env={"GITHUB_TOKEN": fake_secrets.GITHUB_PAT, "API_KEY": fake_secrets.SETTINGS_API_KEY}
    )
    assert main(["scan", str(config), "--enumerate", "-vv", "--timeout", "20"]) == 0
    out, err = capsys.readouterr()
    fake_secrets.assert_no_secrets(out)
    fake_secrets.assert_no_secrets(err)
    assert "Only enumerate configs you trust" in err

    server = json.loads(out)["agents"][0]["servers"][0]
    assert server["enumeration"]["status"] == "ok"
    assert [t["name"] for t in server["enumeration"]["tools"]] == ["read_file", "send_email"]
    assert all(len(t["definition_hash"]) == 64 for t in server["enumeration"]["tools"])


def test_scan_requires_subcommand() -> None:
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_classify_requires_enumerate(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(CONFIG_FIXTURES), "--classify"]) == 2
    assert "--classify needs tool definitions" in capsys.readouterr().err


def test_scan_classify_end_to_end_second_run_makes_zero_llm_calls(
    mock_stdio_config: Callable[..., tuple[Path, Path]],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    providers: list[FakeProvider] = []

    def make_provider(model: str | None = None) -> FakeProvider:
        providers.append(FakeProvider())
        return providers[-1]

    monkeypatch.setattr(cli, "AnthropicProvider", make_provider)
    config, _ = mock_stdio_config()
    argv = ["scan", str(config), "--enumerate", "--classify", "--timeout", "20"]

    assert main(argv) == 0
    first = json.loads(capsys.readouterr().out)
    tools = first["agents"][0]["servers"][0]["enumeration"]["tools"]
    assert [t["classification"]["status"] for t in tools] == ["classified", "classified"]
    assert len(providers[0].calls) == 2

    assert main(argv) == 0
    second = json.loads(capsys.readouterr().out)
    assert len(providers[1].calls) == 0
    tools = second["agents"][0]["servers"][0]["enumeration"]["tools"]
    assert all(t["classification"]["from_cache"] for t in tools)


def test_classify_saved_inventory_offline(
    mock_stdio_config: Callable[..., tuple[Path, Path]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("offline mode must not create an LLM client")

    monkeypatch.setattr(cli, "AnthropicProvider", forbidden)
    config, _ = mock_stdio_config()
    inventory = tmp_path / "inventory.json"
    assert main(["scan", str(config), "--enumerate", "--timeout", "20", "-o", str(inventory)]) == 0
    capsys.readouterr()

    assert main(["classify", str(inventory), "--offline"]) == 0
    data = json.loads(capsys.readouterr().out)
    tools = data["agents"][0]["servers"][0]["enumeration"]["tools"]
    assert {t["classification"]["status"] for t in tools} == {"unclassified"}
    assert tools[0]["classification"]["error"] == "offline mode: no cached classification"


def test_classify_rejects_bad_inventory(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"agents": "nope"}')
    assert main(["classify", str(bad), "--offline"]) == 2
    assert "not a valid inventory" in capsys.readouterr().err
    assert main(["classify", str(tmp_path / "missing.json"), "--offline"]) == 2


def _write_inventory(tmp_path: Path, name: str) -> Path:
    path = tmp_path / f"{name}.json"
    path.write_text(load_scenario(name).model_dump_json(), encoding="utf-8")
    return path


def test_evaluate_saved_inventory(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["evaluate", str(_write_inventory(tmp_path, "trifecta"))]) == 0
    data = json.loads(capsys.readouterr().out)
    assert [f["rule_id"] for f in data["findings"]] == ["CAP-001"]
    assert data["policy"]["source"] == "builtin:default.yaml"
    assert data["skipped_rules"] == [
        {"rule_id": "CAP-006", "reason": "no baseline provided (--baseline)"}
    ]


def test_baseline_create_then_detect_change(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = tmp_path / "before.json"
    before.write_text(load_scenario("rug-pull", baseline_tools=True).model_dump_json())
    baseline = tmp_path / "baseline.json"
    assert main(["baseline", "create", str(before), "-o", str(baseline)]) == 0
    capsys.readouterr()

    after = _write_inventory(tmp_path, "rug-pull")
    assert main(["evaluate", str(after), "--baseline", str(baseline)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert "CAP-006" in {f["rule_id"] for f in data["findings"]}
    assert data["baseline_used"] is True


def test_baseline_create_needs_enumerated_servers(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    inventory = tmp_path / "inv.json"
    assert main(["scan", str(CONFIG_FIXTURES / "generic" / "mcp.json"), "-o", str(inventory)]) == 0
    assert main(["baseline", "create", str(inventory)]) == 2
    assert "no successfully enumerated servers" in capsys.readouterr().err


def test_scan_evaluate_without_enumeration_reports_server_rules_and_coverage(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    saved = tmp_path / "inventory.json"
    argv = [
        "scan",
        str(FIXTURES / "overscoped-token" / "mcp.json"),
        "--evaluate",
        "--save-inventory",
        str(saved),
    ]
    assert main(argv) == 0
    out, err = capsys.readouterr()
    data = json.loads(out)
    # Config-only rules still work; tag rules wait for enumeration + classification.
    assert [f["rule_id"] for f in data["findings"]] == ["CAP-007"]
    assert data["summary"]["not_assessed"] == 2
    assert "not assessed" in err
    assert json.loads(saved.read_text())["agents"][0]["servers"][1]["name"] == "crm"


def test_policy_and_baseline_errors_are_clean(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    inventory = _write_inventory(tmp_path, "trifecta")
    bad_policy = tmp_path / "p.yaml"
    bad_policy.write_text("version: 1\nrules: []\n")
    assert main(["evaluate", str(inventory), "--policy", str(bad_policy)]) == 2
    assert "invalid policy" in capsys.readouterr().err
    bad_baseline = tmp_path / "b.json"
    bad_baseline.write_text('{"baseline_version": 9, "servers": {}}')
    assert main(["evaluate", str(inventory), "--baseline", str(bad_baseline)]) == 2
    assert "expected format" in capsys.readouterr().err
    assert main(["scan", "--save-inventory", str(tmp_path / "x.json")]) == 2
