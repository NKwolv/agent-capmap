# GitHub Action

agent-capmap ships as a composite action (`action.yml` at the repository root). It scans
MCP configs, evaluates them against a policy, writes SARIF for GitHub code scanning,
adds a Markdown summary to the job page, and fails the job when findings reach the
`fail-on` severity.

A complete example is in [`examples/agentcapmap.yml`](examples/agentcapmap.yml).

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Directory or config file to scan, relative to the workspace. |
| `policy` | built-in | Policy YAML file. |
| `baseline` | none | Baseline JSON for rug-pull detection (CAP-006). |
| `fail-on` | `high` | `critical`, `high`, `medium`, `low`, `info` or `none`. |
| `fail-on-not-assessed` | `false` | Also fail when any server or tool could not be assessed. |
| `enumerate` | `false` | Start the configured servers and list their tools. **Runs the commands in the scanned configs.** |
| `classify` | `false` | Classify tools with the LLM. Needs `enumerate: true` and `ANTHROPIC_API_KEY` (unless `offline`). |
| `offline` | `false` | Classify from the cache only. |
| `cache-dir` | none | Classification cache directory; restore it with `actions/cache`. |
| `sarif-file` | `agentcapmap.sarif` | Where to write SARIF (relative path inside the workspace). |
| `python-version` | `3.12` | Python used to run agent-capmap. |

Outputs: `sarif-file`, `findings` (count), `not-assessed` (count).

Exit status: the action fails when a finding is at or above `fail-on` (or, with
`fail-on-not-assessed`, when anything was not assessed). The SARIF file and summary
are written first, so upload them in a step with `if: always()`.

## Choosing a mode

| Mode | When | What it catches |
|---|---|---|
| Config-only (default) | Every pull request, including from forks | Rules that need only the config: unpinned or unvetted servers (CAP-007), plus anything recorded in a committed baseline. Tools are reported as not assessed. |
| Enumerate + classify | Trusted events only (pushes to `main`, schedules) | Every rule, including the capability combinations (CAP-001 to CAP-005, CAP-008, CAP-009) and rug pulls (CAP-006). |

## Security

- **Enumeration executes code.** `enumerate: true` runs the server commands from the
  scanned configs, so a pull request could make the runner execute anything. Only
  enable it for code you have reviewed: never on `pull_request` from forks, and never
  with `pull_request_target`.
- **Secrets and launched servers.** Launched servers get a minimal environment, but on
  Linux a process can read its parent's environment through `/proc`. Treat any secret
  in a job that enumerates as visible to the enumerated servers. Keep
  `ANTHROPIC_API_KEY` in a GitHub Environment restricted to `main`, as in the example.
- **Pinning.** Reference the action by full commit SHA. The action itself installs
  agent-capmap and its dependencies from hash-pinned lockfiles (`--require-hashes`) and
  pins the actions it uses by SHA.
- **Least privilege.** The scan needs `contents: read`; only the SARIF upload step needs
  `security-events: write`. Check out with `persist-credentials: false`.
- **Inputs** are passed to the script through environment variables, never interpolated
  into shell code, and validated against allowlists.

## Code scanning availability

Uploading SARIF needs GitHub code scanning, which is free for public repositories and
requires GitHub Advanced Security (Code Security) for private ones. Without it, keep
the Markdown summary and the `fail-on` gate, and skip the upload step.
