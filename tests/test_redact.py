import logging

import pytest

from agentcapmap.redact import (
    REDACTED,
    get_logger,
    is_sensitive_name,
    known_secrets,
    redact_args,
    redact_text,
    redact_url,
    redact_value,
)
from tests import fake_secrets


@pytest.mark.parametrize(
    "name",
    ["GITHUB_TOKEN", "Authorization", "X-API-Key", "--api-key", "password", "OPENAI_KEY", "GH_PAT"],
)
def test_sensitive_names(name: str) -> None:
    assert is_sensitive_name(name)


@pytest.mark.parametrize("name", ["PATH", "AWS_REGION", "--port", "LOG_LEVEL", "-y", "keyboard"])
def test_non_sensitive_names(name: str) -> None:
    assert not is_sensitive_name(name)


@pytest.mark.parametrize(
    "secret",
    [
        fake_secrets.GITHUB_PAT,
        fake_secrets.OPENAI_KEY,
        fake_secrets.ANTHROPIC_KEY,
        fake_secrets.SLACK_TOKEN,
        fake_secrets.AWS_ACCESS_KEY_ID,
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    ],
)
def test_token_patterns_in_free_text(secret: str) -> None:
    out = redact_text(f"failed to auth with {secret} at startup")
    assert secret not in out
    assert REDACTED in out


def test_bearer_and_named_values() -> None:
    out = redact_text("Authorization: Bearer abcdefgh12345678 password=hunter2hunter2")
    assert "abcdefgh12345678" not in out
    assert "hunter2hunter2" not in out


def test_known_secrets_are_scrubbed_verbatim() -> None:
    known_secrets.add("not-shaped-like-a-token")
    assert "not-shaped-like-a-token" not in redact_text("value=not-shaped-like-a-token ok")
    known_secrets.add("${GITHUB_TOKEN}")  # references are not secrets
    assert redact_text("${GITHUB_TOKEN}") == "${GITHUB_TOKEN}"


def test_redact_value_keeps_references_only() -> None:
    assert redact_value("${env:TOKEN}") == "${env:TOKEN}"
    assert redact_value("${input:gh-pat}") == "${input:gh-pat}"
    assert redact_value("") == ""
    assert redact_value("us-east-1") == REDACTED


def test_redact_url() -> None:
    out = redact_url(f"postgresql://admin:{fake_secrets.PG_PASSWORD}@db.internal:5432/prod")
    assert out == f"postgresql://admin:{REDACTED}@db.internal:5432/prod"

    out = redact_url(f"https://mcp.example.com/mcp?api_key={fake_secrets.QUERY_KEY}&region=eu")
    assert fake_secrets.QUERY_KEY not in out
    assert "region=eu" in out

    out = redact_url(f"https://actions.example.com/mcp/{fake_secrets.PATH_SECRET}/sse")
    assert out == f"https://actions.example.com/mcp/{REDACTED}/sse"

    assert redact_url("https://mcp.linear.app/sse") == "https://mcp.linear.app/sse"


def test_redact_args() -> None:
    args = [
        "run",
        "-e",
        f"GITHUB_TOKEN={fake_secrets.GITHUB_PAT}",
        f"--api-key={fake_secrets.OPENAI_KEY}",
        "--token",
        fake_secrets.ANTHROPIC_KEY,
        "--port",
        "8080",
        f"postgresql://u:{fake_secrets.PG_PASSWORD}@h/db",
        "/Users/alice/Documents",
    ]
    out = redact_args(args)
    fake_secrets.assert_no_secrets(" ".join(out))
    assert out[:2] == ["run", "-e"]
    assert out[2] == f"GITHUB_TOKEN={REDACTED}"
    assert out[3] == f"--api-key={REDACTED}"
    assert out[4:8] == ["--token", REDACTED, "--port", "8080"]
    assert out[-1] == "/Users/alice/Documents"


def test_logger_redacts(caplog: pytest.LogCaptureFixture) -> None:
    log = get_logger("agentcapmap.test")
    with caplog.at_level(logging.DEBUG, logger="agentcapmap.test"):
        log.warning("token is %s", fake_secrets.GITHUB_PAT)
    fake_secrets.assert_no_secrets(caplog.text)
    assert REDACTED in caplog.text
