# Contributing to agent-capmap

Thanks for helping. This guide covers setup, the quality gates every change must pass,
and the rules that keep results trustworthy.

## Setup

```sh
git clone https://github.com/NKwolv/agent-capmap
cd agent-capmap
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install   # optional: runs ruff and mypy on commit
```

Python 3.11 or newer is required.

## Quality gates

Every pull request must pass, and CI runs the same checks on Linux and Windows for
Python 3.11 to 3.13:

```sh
ruff check .                     # lint, including the security (S / bandit) rules
ruff format --check .
mypy
pytest
bandit -c pyproject.toml -r src  # SAST
pip-audit --strict .             # SCA: known-vulnerable dependencies
zizmor --offline --persona auditor .github/workflows/   # GitHub Actions security
```

CodeQL (`security-extended` queries) also runs on every pull request.

**Zero findings is the bar.** Fix a finding rather than suppressing it. A suppression
is acceptable only for a verified false positive or an unavoidable, documented design
property (today: launching the configured server command in `enumerate/stdio.py`), and
it must name the specific rule (`# noqa: S603  # nosec B603`) with a comment explaining
why.

## Ground rules

These come from the project's design rules. Pull requests that break them will not be
merged.

1. **The LLM only classifies.** Risk decisions (combinations, severities) are
   deterministic code driven by the policy file. Never add an LLM call to the policy
   engine or reporting.
2. **Never execute tools.** The MCP client may send only `initialize`,
   `notifications/initialized` and `tools/list`. The allowlist in
   `src/agentcapmap/enumerate/transport.py` enforces this; do not widen it.
3. **No secrets in output or logs.** Anything derived from a config must go through
   `agentcapmap.redact`. Use `redact.get_logger(__name__)` for logging. Raw values
   belong only in `LaunchSpec`, which is never serialized.
4. **No network in tests.** `tests/conftest.py` blocks non-loopback connections. Use the
   mock MCP server (`tests/mock_mcp_server.py`) and the fake LLM provider
   (`tests/fake_llm.py`).
5. **Treat everything from a server or config as hostile.** Bound its size (see
   `agentcapmap/limits.py`), parse JSON with `loads_untrusted`, never follow redirects
   or cross-origin endpoints with credentials, never pass our own environment to a
   launched server beyond the allowlist, and escape control characters before printing.
6. **No secrets in the repo.** Fixture credentials must be obviously fake and listed in
   `tests/fake_secrets.py`, so the leak tests check them.

## Common changes

### Adding a client config format

1. Create a module in `src/agentcapmap/discovery/` exporting
   `FORMATS = [ConfigFormat(name, client, matches, parse)]`. Keep each format in its
   own module so format changes stay isolated.
2. Reuse `parse_server_map` / `build_server` from `discovery/_common.py`; they handle
   redaction, auth hints and line numbers.
3. Register it in `FORMATS` in `discovery/__init__.py` (order matters: the first match
   wins) and add the filename to `CANDIDATE_NAMES` if needed.
4. Add a fixture under `tests/fixtures/configs/` containing fake credentials, and
   tests in `tests/test_discovery.py`.

### Changing the classifier prompt

- Bump `PROMPT_VERSION` in `src/agentcapmap/classify/prompt.py`. It is part of the cache
  key, so stale classifications will not be reused.
- If you change a definition or ruling, update `docs/taxonomy.md` to match.
- Evaluation results are only valid for one prompt version. Re-run the eval and
  update `eval/results.md` (once Phase 5 lands) rather than reusing old numbers.

### Changing the taxonomy

Adding, removing or redefining an axis or value is a breaking change:

- update `schemas/tool-tags.schema.json` and bump `x-taxonomy-version`;
- update `TAXONOMY_VERSION`, `AXES` and `DEFAULTS` in `src/agentcapmap/taxonomy.py`
  and `ToolTags` in `models.py` (a test checks they agree);
- update the prompt (and bump `PROMPT_VERSION`) and `docs/taxonomy.md`;
- relabel the evaluation set.

## Commits and pull requests

- Keep each pull request focused, and describe *why* as well as *what*.
- Include tests for new behavior and for bugs you fix.
- Never include real credentials, tokens or private MCP configs, even in examples.

## Reporting security issues

Do not open a public issue for vulnerabilities. See [SECURITY.md](SECURITY.md).
