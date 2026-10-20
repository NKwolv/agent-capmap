import json
from collections.abc import Callable
from pathlib import Path

import pytest

from agentcapmap.cli import main
from tests import fake_secrets
from tests.conftest import CONFIG_FIXTURES


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
