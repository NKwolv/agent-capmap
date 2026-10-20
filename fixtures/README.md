# Scenario fixtures

Each directory is one agent configuration with a known risk (or none), used for the
golden-file tests in `tests/test_fixtures.py`.

| File | Contents |
|---|---|
| `mcp.json` | The client config, exactly as discovery reads it. |
| `tools.json` | What each server returns from `tools/list`, plus the tags a classifier would assign. The tags go through the real classifier validation, including evidence-phrase checks. |
| `expected.json` | Golden output: the findings, not-assessed items and summary for the default policy. |
| `baseline.json` | (rug-pull only) Baseline pinned before the definitions changed. |

| Scenario | Expected |
|---|---|
| `clean` | No findings. One tool is unclassified and reported as not assessed. |
| `trifecta` | CAP-001: GitHub issues (untrusted) + private repo read + email to any address. |
| `exec-injection` | CAP-002: web fetch + host shell. Also CAP-003, because the shell has no approval gate. |
| `no-approval-destructive` | CAP-003: a delete tool listed in `alwaysAllow`. |
| `poisoned-description` | CAP-008: a hidden `<IMPORTANT>` block in a tool description. |
| `overscoped-token` | CAP-005: a remote server answering without authentication. CAP-007: an unpinned (`@latest`) server holding a static admin token. |
| `rug-pull` | CAP-006: one tool changed and one added since the baseline. Also CAP-008, because the change slipped a hidden instruction into the description (the typical shape of a rug pull). |
| `shadowing` | CAP-009: two servers expose `read_file`. |

No fixture contains a real credential: values are `${VAR}` references or contain `fake`.

To regenerate golden files after an intentional change, run
`AGENTCAPMAP_UPDATE_GOLDEN=1 pytest tests/test_fixtures.py`, then review the diff.
