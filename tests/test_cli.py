import json
from collections.abc import Callable
from pathlib import Path

import pytest

from agentcapmap import cli
from agentcapmap.cli import main
from tests import fake_secrets
from tests.conftest import CONFIG_FIXTURES
from tests.fake_llm import FakeProvider


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
