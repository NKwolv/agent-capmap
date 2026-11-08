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
| `waivers` | none | Waivers YAML (see the README). A PR can edit it: put it under `CODEOWNERS`. |
| `fail-on` | `high` | `critical`, `high`, `medium`, `low`, `info` or `none`. |
| `fail-on-not-assessed` | `false` | Also fail when any server or tool could not be assessed. |
| `enumerate` | `false` | Start the configured servers and list their tools. **Runs the commands in the scanned configs.** |
| `classify` | `false` | Classify tools with the LLM. Needs `enumerate: true` and `ANTHROPIC_API_KEY` (unless `offline`). |
| `offline` | `false` | Classify from the cache only. |
| `cache-dir` | none | Classification cache directory; restore it with `actions/cache`. |
| `comment` | `false` | On `pull_request`, post what changed against the base branch as one comment (see below). Config-only; cannot be combined with `enumerate`. |
| `github-token` | `github.token` | Token used to post the comment. |
| `sarif-file` | `agentcapmap.sarif` | Where to write SARIF (relative path inside the workspace). |
| `python-version` | `3.12` | Python used to run agent-capmap. |

Outputs: `sarif-file`, `findings` (count), `not-assessed` (count).

Exit status: the action fails when a finding is at or above `fail-on` (or, with
`fail-on-not-assessed`, when anything was not assessed). The SARIF file and summary
are written first, so upload them in a step with `if: always()`.

## Pull request comment

With `comment: "true"`, the action scans the base commit as well, compares the two with
`agentcapmap diff`, and posts a single comment that lists **new findings**, **newly
unassessed servers** (in config-only mode this is how an added MCP server shows up),
gained capabilities and resolved findings. The comment is updated on every push instead
of adding new ones, and nothing is posted when nothing changed and there is no earlier
comment. The same text goes to the job summary.

Requirements:

- `permissions: pull-requests: write` on the job (plus `contents: read`).
- `actions/checkout` with `fetch-depth: 0`, so the base commit is available. Without it
  the comparison is skipped with a warning.
- The `pull_request` event. Do not use `pull_request_target` to get write access on
  forks: that runs with secrets against untrusted code. On a fork the token is read-only,
  so the comment cannot be posted and the diff appears in the job summary only.
- Not with `enumerate: "true"`: the comment mode never starts servers, so it is safe on
  pull requests.

Waivers a pull request adds appear under **Newly waived** with their reason and owner: the
comparison uses the base branch's waivers file, so a PR cannot quietly waive its own
finding. Protect the file with `CODEOWNERS` so a maintainer must approve such changes.

The head's policy and baseline are used for both sides, so only the pull request's own
changes appear. A bot comment is only ever updated if the `github-actions[bot]` user
wrote it and it carries the action's hidden marker.

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
