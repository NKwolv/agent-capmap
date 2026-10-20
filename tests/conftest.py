from __future__ import annotations

import json
import socket
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from agentcapmap.redact import known_secrets

TESTS_DIR = Path(__file__).parent
CONFIG_FIXTURES = TESTS_DIR / "fixtures" / "configs"
MOCK_SERVER = TESTS_DIR / "mock_mcp_server.py"

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


@pytest.fixture(autouse=True)
def _block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit tests must not touch the network; only loopback mock servers are allowed."""
    real_connect = socket.socket.connect

    def guarded(self: socket.socket, address: Any) -> None:
        if isinstance(address, tuple) and address[0] not in _LOOPBACK:
            raise RuntimeError(f"network access blocked in tests: {address[0]}")
        real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded)


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Keep tests off the user's classification cache and model settings."""
    monkeypatch.setenv("AGENTCAPMAP_CACHE_DIR", str(tmp_path / "classification-cache"))
    monkeypatch.delenv("AGENTCAPMAP_MODEL", raising=False)
    monkeypatch.delenv("AGENTCAPMAP_EFFORT", raising=False)


@pytest.fixture(autouse=True)
def _reset_known_secrets() -> Iterator[None]:
    known_secrets.clear()
    yield
    known_secrets.clear()


@pytest.fixture
def mock_stdio_config(tmp_path: Path) -> Callable[..., tuple[Path, Path]]:
    """Write a mock-server spec plus an mcp.json pointing at it. Returns (config, call_log)."""

    def make(
        spec: dict[str, Any] | None = None,
        *,
        env: dict[str, str] | None = None,
        extra: dict[str, Any] | None = None,
        name: str = "mock",
    ) -> tuple[Path, Path]:
        call_log = tmp_path / f"{name}-calls.log"
        spec_path = tmp_path / f"{name}-spec.json"
        spec_path.write_text(json.dumps({"call_log": str(call_log), **(spec or {})}))
        entry: dict[str, Any] = {
            "command": sys.executable,
            "args": [str(MOCK_SERVER), str(spec_path)],
            **(extra or {}),
        }
        if env:
            entry["env"] = env
        config = tmp_path / "mcp.json"
        config.write_text(json.dumps({"mcpServers": {name: entry}}))
        return config, call_log

    return make
