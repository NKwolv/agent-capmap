"""Every fake credential planted in test fixtures. None may ever appear in output or logs."""

GITHUB_PAT = "ghp_FAKEfake0000000000000000000000000001"
GITHUB_PAT_DOCKER = "ghp_FAKEfake0000000000000000000000000002"
PG_PASSWORD = "S3cretPassw0rd!"
CURSOR_BEARER = "fake-bearer-value-123456"
OPENAI_KEY = "sk-FAKEfakeFAKEfake1234567890"
ANTHROPIC_KEY = "sk-ant-FAKE-api03-abcdefghijkl"
SLACK_TOKEN = "xoxb-0000-FAKE-slacktoken"
AWS_ACCESS_KEY_ID = "AKIAFAKEFAKEFAKE1234"
AWS_SECRET = "wJalrXUtnFEMIK7MDENGbPxRfiCYFAKEKEY99"
QUERY_KEY = "FAKEQUERYKEY123456"
PATH_SECRET = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
SETTINGS_API_KEY = "plain-api-key-value-777"

ALL = [
    GITHUB_PAT,
    GITHUB_PAT_DOCKER,
    PG_PASSWORD,
    CURSOR_BEARER,
    OPENAI_KEY,
    ANTHROPIC_KEY,
    SLACK_TOKEN,
    AWS_ACCESS_KEY_ID,
    AWS_SECRET,
    QUERY_KEY,
    PATH_SECRET,
    SETTINGS_API_KEY,
]


def assert_no_secrets(text: str) -> None:
    leaked = [s for s in ALL if s in text]
    assert not leaked, f"secret(s) leaked into output: {leaked}"
