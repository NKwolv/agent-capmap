<h1 align="center">agent-capmap</h1>

<p align="center">
  <strong>Find out what your AI agents can actually do,<br>
  and which combinations of their tools an attacker could abuse.</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/agent-capmap/"><img alt="PyPI" src="https://img.shields.io/pypi/v/agent-capmap?color=blue"></a>
  <a href="https://pypi.org/project/agent-capmap/"><img alt="Python versions" src="https://img.shields.io/pypi/pyversions/agent-capmap"></a>
  <a href="https://github.com/NKwolv/agent-capmap/blob/main/LICENSE"><img alt="License: MIT" src="https://img.shields.io/github/license/NKwolv/agent-capmap"></a>
  <a href="https://github.com/NKwolv/agent-capmap/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/NKwolv/agent-capmap/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/NKwolv/agent-capmap/actions/workflows/codeql.yml"><img alt="CodeQL" src="https://github.com/NKwolv/agent-capmap/actions/workflows/codeql.yml/badge.svg"></a>
  <img alt="Status: alpha" src="https://img.shields.io/badge/status-alpha-orange">
</p>

<p align="center">
  <img alt="MCP" src="https://img.shields.io/badge/MCP-security-blueviolet">
  <img alt="AI agent security" src="https://img.shields.io/badge/AI%20agent-security-informational">
  <img alt="Prompt injection" src="https://img.shields.io/badge/prompt-injection-informational">
  <img alt="Policy as code" src="https://img.shields.io/badge/policy-as%20code-informational">
  <img alt="SARIF" src="https://img.shields.io/badge/output-SARIF%20%7C%20Markdown%20%7C%20JSON-informational">
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#quickstart-5-minutes-no-api-key">Quickstart</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#policy">Policy</a> ·
  <a href="#ci-and-github-code-scanning">GitHub Action</a> ·
  <a href="#documentation">Docs</a>
</p>

---

## Why

AI assistants such as Claude Desktop, Cursor, VS Code and Claude Code get their powers
from MCP servers: read files, browse the web, send email, run shell commands. Each tool
can look harmless on its own. The danger is usually the **combination**: an agent that can

| 1. Read **private data** | 2. Read **attacker-written content** | 3. **Send data out** |
|---|---|---|
| files, repos, email, databases | a web page, an issue, an email | email, HTTP requests, `git push` |

can be talked into leaking that data by a single poisoned page. That is the
**"lethal trifecta"**, and no single tool shows it.

agent-capmap inventories every MCP server and tool reachable by each agent, classifies
what each tool can do, and applies policy-as-code rules to the **combination** of tools
per agent. Findings come with evidence and can gate CI through SARIF and exit codes.

> **Status: alpha.** All features below work. The classifier's accuracy has not been
> benchmarked yet, and the bundled labels were drafted by AI and reviewed by the
> maintainer, not independently verified; see [Accuracy](#accuracy).

## Highlights

| | |
|---|---|
| 🔎 **Inventory** | Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Cline, Roo Code, Gemini CLI, Zed, Codex CLI and generic `mcp.json`. Secrets are redacted everywhere. |
| 🧰 **Tools, prompts and resources** | Listed read-only, never called, read or fetched. Poisoned descriptions are flagged. |
| 🏷️ **Six-axis classification** | An LLM only tags capabilities; every risk decision is deterministic code. |
| 📜 **Policy as code** | Fourteen built-in rules, your own rules in YAML, and expiring waivers for accepted risks. |
| 🚧 **Runtime guard** | A Claude Code hook that follows what a session has actually done and stops the call that would complete a risky combination. |
| 🔗 **Across agents** | Finds chains no single agent has: one agent writes into a server another agent reads. |
| 🏃 **Runtime discovery** | Finds MCP servers that are running but declared in no config file. |
| 🧾 **Rug-pull detection** | Pin definitions in a baseline; see what a pull request changed in a PR comment. |
| 🛡️ **CI-ready** | Evidence for every finding, SARIF for code scanning, and exit codes for gating. |
| 🔌 **Works without a key** | 381 tools from 28 well-known servers are classified from bundled labels. |

## Contents

- [Install](#install)
- [Quickstart](#quickstart-5-minutes-no-api-key)
- [Example output](#example-output)
- [How it works](#how-it-works)
- [Capability taxonomy](#capability-taxonomy) · [Policy](#policy)
- [CI and GitHub code scanning](#ci-and-github-code-scanning)
- [Accuracy](#accuracy) · [Limitations](#limitations) · [Safety](#safety)
- [Documentation](#documentation)

## Install

Requires Python 3.11+.

```sh
pipx install agent-capmap        # or: uv tool install agent-capmap
```

Releases are built and published by GitHub Actions with PyPI trusted publishing, so
each file on PyPI carries an attestation linking it to the workflow run that built it.

Optional extras: `agent-capmap[runtime]` for `scan --running` and `agent-capmap[ws]` to
enumerate WebSocket servers.

For a fully hash-pinned install, with the exact dependency versions CI tests, install
from a clone instead:

```sh
git clone https://github.com/NKwolv/agent-capmap
cd agent-capmap
python -m venv .venv
. .venv/bin/activate            # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install --require-hashes -r requirements/runtime.lock
pip install --no-deps .
```

> **Locked-down Windows machines:** if your organization's policy (Device Guard,
> AppLocker, Smart App Control) blocks `agentcapmap.exe` or `pipx.exe`, run the tool
> through Python instead, which is the same program. If you installed with
> `pip install agent-capmap`, run `python -m agentcapmap scan --user`. If you installed
> with pipx, the package lives in pipx's own environment, so plain `python` will not
> find it: use that environment's interpreter (`python -m pipx environment --value
> PIPX_LOCAL_VENVS` shows the folder):
> `<venvs>\agent-capmap\Scripts\python.exe -m agentcapmap scan --user`. Do not try to
> bypass the policy; ask your administrator to allow the launcher if you want it.

> **Windows:** if `pip install` fails with "No such file or directory" deep inside
> `site-packages`, the path is too long for Windows' 260-character limit. Clone to a
> short path (for example `C:\src\agent-capmap`) or enable long path support.

## Quickstart (5 minutes, no API key)

```sh
# 1. See findings on a ready-made inventory of five example agents
#    (from a clone, use examples/demo/inventory.json directly)
curl -fsSLO https://raw.githubusercontent.com/NKwolv/agent-capmap/main/examples/demo/inventory.json
agentcapmap evaluate inventory.json --format markdown

# 2. List the MCP servers configured on your own machine (reads files only)
agentcapmap scan --user
```

On Windows PowerShell, use `curl.exe` instead of `curl`.

Step 1 should report 2 critical, 2 high and 1 medium finding. Step 2 lists your
servers with every secret redacted, without starting anything.

## Example output

```markdown
### 1. `CAP-001` | Critical

`Lethal trifecta: the agent can read private data, ingest attacker-controlled content,
and send data externally, so injected instructions can exfiltrate data.`

- **Agent:** `generic:fixtures/trifecta/mcp.json` at `fixtures/trifecta/mcp.json:3`
- **Tools:** `github/get_file_contents`, `github/list_issues`, `mailer/send_email`

| Server | Tool | Matched | Evidence |
|---|---|---|---|
| `github` | `get_file_contents` | `data_access=private_read` | `contents of a file from a private or public repository` |
| `github` | `list_issues` | `untrusted_input=true` | `including issues opened by anyone` |
| `mailer` | `send_email` | `egress=external` | `Send an email to any recipient address` |
```

(Abridged from the real output of step 1.)

## How it works

```
config files ──► discover ──► enumerate ──► classify ──► policy ──► report
                 (read only)  (initialize +  (LLM tags    (YAML      (JSON, Markdown,
                              list calls)    6 axes)      rules)     SARIF, exit code)
```

1. **Discover** MCP configs: Claude Desktop, Cursor, VS Code (`.vscode/mcp.json`,
   `settings.json`), Claude Code (`.mcp.json`, and with `--user` your `~/.claude.json`
   user and per-project servers, including permission rules), Windsurf, Cline, Roo Code,
   Gemini CLI, Qwen Code, Zed, Codex CLI (`config.toml`) and generic `mcp.json`.
   Secrets are redacted everywhere.
2. **Enumerate** (`--enumerate`): start each server and ask only for what it offers: its
   tools, and its prompts and resources if it has them. Nothing is called, read or
   fetched.
3. **Classify** (`--classify`): an LLM tags each tool on six axes and flags descriptions
   that try to manipulate the model. Results are cached and validated against a JSON
   schema.
4. **Evaluate** (`--evaluate`): deterministic rules decide what is dangerous. The LLM
   never makes risk decisions.
5. **Report**: JSON, Markdown, or SARIF for GitHub code scanning; `--fail-on` sets the
   exit code.

### Full scan of your own setup (needs an API key)

```sh
export ANTHROPIC_API_KEY=<YOUR_API_KEY>          # PowerShell: $env:ANTHROPIC_API_KEY = "..."
agentcapmap scan --user --enumerate --classify --evaluate --format markdown -o report.md
```

`--enumerate` **runs the server commands in your configs**: only use it on configs you
trust. To try the whole pipeline on two known servers first, see
[`examples/live-trifecta`](https://github.com/NKwolv/agent-capmap/blob/main/examples/README.md).

### Prompts and resources

MCP servers also offer prompts and resources, and their descriptions are another place a
poisoned instruction can hide. When a server advertises them, `--enumerate` **lists**
them (`prompts/list`, `resources/list`, `resources/templates/list`): it never reads a
resource or gets a prompt. With `--classify`, each one that has any text is checked for
instructions aimed at the model (rule **CAP-008**), and `baseline create` pins them so a
later change is a rug pull (**CAP-006**). They add no capabilities: they are not tools.
Items with no description are skipped, at most 200 per server are sent to the classifier,
and anything not checked is reported under "not assessed".

### Accept a finding on purpose (waivers)

When you have reviewed a finding and accept the risk, record that decision instead of
ignoring the finding. Copy its `fingerprint` from the JSON output into a waivers file
([example](https://github.com/NKwolv/agent-capmap/blob/main/docs/examples/waivers.yaml)):

```yaml
version: 1
waivers:
  - fingerprint: 3f2a9c0b7d1e4a5c8b6d0e2f1a3c5b7d   # from the finding
    rule: CAP-001                                  # optional check
    owner: platform-security
    reason: Filesystem server limited to the sandbox directory; reviewed in SEC-1234.
    expires: 2027-03-31                            # at most a year ahead
```

```sh
agentcapmap evaluate inventory.json --waivers waivers.yaml --fail-on high
```

Waivers are deliberately strict: they match one finding exactly (no wildcards), need an
owner, a reason and an end date, and **stop applying after that date** (the finding comes
back and the waiver is reported). Waived findings leave the exit status and the counts but
stay listed with their reason; a waiver that matches nothing is reported as stale. A broken
waivers file is an error, never silently ignored.

A pull request can edit the waivers file, so keep it under `CODEOWNERS`. In the GitHub
Action, the PR comment compares against the base branch's waivers and lists any waiver the
PR adds under **Newly waived**, so a reviewer sees what was accepted.

### Find servers that are running right now

Config files only show what is *declared*. `--running` also reads the process table and
reports MCP servers that are actually running, including ones that are in no config file:

```sh
pip install "agent-capmap[runtime]"     # adds psutil, needed only for this
agentcapmap scan --user --running --evaluate --format markdown
```

A running server that matches a configured one is marked with its process id. One that
matches no scanned config is added under a `runtime:<client>` agent and reported by
**CAP-010**; one listening on a non-loopback address is reported by **CAP-011**. Use
`--user` so your per-user client configs count as "declared".

It only reads the current user's process list and listening sockets. It never starts,
connects to or probes anything, and servers found this way are never enumerated (that
would re-run a command taken from the process table). Detection is heuristic: it
recognizes common launch styles (`npx`, `uvx`, `python -m`, `docker run`, MCP-named
programs), so a custom server with an unrelated name can be missed.

### Stop a risky combination as it happens (runtime guard)

A scan reports what an agent *could* do. The guard is a Claude Code hook that follows
what one session has *actually* done and steps in at the call that would complete a
rule: for example, sending data out after the session read attacker-written content
and private data.

```sh
# 1. Scan and classify once, then build the guard map (tool tags + enforceable rules)
agentcapmap scan --user --enumerate --classify -o inventory.json
agentcapmap guard build inventory.json -o guard-map.json

# 2. Print the hooks block and add it to ~/.claude/settings.json
agentcapmap guard settings --map guard-map.json
```

From then on, before every MCP tool call, the hook checks the call against the session
so far. Nothing changes until a call would complete **CAP-001**, **CAP-002** or
**CAP-004**; then Claude Code asks you, with the rule and the earlier tools that set it
up (`--on-violation deny` refuses outright, for unattended runs).

- **It decides without an LLM or the network**, from the guard map alone, and adds
  roughly 0.15 s to each MCP tool call (one short Python process).
- **It fails closed.** A missing or damaged map, unreadable state or any internal error
  blocks the call. A tool the map does not know is never treated as safe: you are
  asked (`--unknown ask`, the default). Rebuild the map when your servers change.
- **It never approves anything.** With no objection it stays silent and Claude Code's
  normal permission prompt applies.
- **It records tool names and tags only**, per session, never arguments or results.
- **Order matters, as in a real attack.** Untrusted content must have been read by an
  earlier call; the call that reads it is not blocked, the one that acts on it is.

By default it sees MCP tools only. `--track-builtins` also counts what Claude Code's own
`WebFetch`, `WebSearch`, `Read` and `Grep` bring into the session (they are never
blocked). Rules about configuration (approval settings, pinning, baselines) are not
sequences of calls and stay with `evaluate`. See [Limitations](#limitations).

### Risks that span several agents

Rules are evaluated per agent, because an injected instruction controls one agent. Agents
can still be chained through something they share: agent A, which reads the web, writes
into a notes server; agent B reads those notes and can send email. Neither has the
trifecta alone. **CAP-012** and **CAP-013** find such chains, following content only in
the direction it can flow (from an agent that can write a shared server to one that
reads it), and name every agent and the tools linking them. Two servers count as shared
when their launch command or URL is identical.

### Check what a GitHub token can do

A config shows that a server holds a token, not how much the token can do. With
`--check-token-scopes` (off by default), each GitHub token found in the scanned configs
is presented once to `https://api.github.com`, and nowhere else, to read its scopes;
**CAP-014** reports a token with administrative scopes such as `delete_repo`.

```sh
agentcapmap scan --user --enumerate --check-token-scopes --evaluate --format markdown
```

Only scope names are kept. Fine-grained and app tokens do not expose their permissions
and are reported as not visible without any request; a token configured for a GitHub
Enterprise host or another service is never sent to github.com.

## Capability taxonomy

| Axis | Values | Question |
|---|---|---|
| `data_access` | none, private_read, secrets_read | What non-public data can it read? |
| `untrusted_input` | false, true | Does it return content strangers can write? |
| `egress` | none, internal, external | Can it send data somewhere an outsider can read? |
| `mutation` | none, reversible_write, destructive | What can it change or delete? |
| `execution` | none, sandboxed, host | Does it run code, and where? |
| `privilege` | none, identity_admin | Does it manage users or permissions? |

Definitions and edge-case rulings: [docs/taxonomy.md](https://github.com/NKwolv/agent-capmap/blob/main/docs/taxonomy.md).

## Policy

The built-in [`policies/default.yaml`](https://github.com/NKwolv/agent-capmap/blob/main/policies/default.yaml) has fourteen rules:

| ID | Severity | Fires when an agent has |
|---|---|---|
| CAP-001 | 🔴 critical | private data + untrusted input + external egress (lethal trifecta) |
| CAP-002 | 🔴 critical | untrusted input + host code execution |
| CAP-003 | 🟠 high | a destructive or host-execution tool with no approval gate |
| CAP-004 | 🟠 high | secrets access + external egress |
| CAP-005 | 🟠 high | a remote server with no authentication exposing capabilities |
| CAP-006 | 🟠 high | tool, prompt or resource definitions that changed since the baseline (rug pull) |
| CAP-007 | 🟡 medium | a server not pinned to an exact version, or from an unvetted source |
| CAP-008 | 🟠 high | a tool, prompt or resource description that tries to instruct the model (poisoning) |
| CAP-009 | 🟡 medium | the same tool name on two servers (shadowing) |
| CAP-010 | 🟡 medium | an MCP server is running but is in no scanned config (`scan --running`) |
| CAP-011 | 🟠 high | an MCP server is listening on a non-loopback address (`scan --running`) |
| CAP-012 | 🟠 high | the lethal trifecta spread over agents that share a server (no single agent has it) |
| CAP-013 | 🟠 high | untrusted input in one agent reaching host code execution in another, through a shared server |
| CAP-014 | 🟡 medium | a GitHub token with administrative scopes (`scan --check-token-scopes`) |

Write your own rules in the same format and pass `--policy my-policy.yaml`:

```yaml
- id: ACME-001
  severity: high
  when_server: {remote: true}
  when_agent_has_any:
    - privilege: identity_admin
  message: Remote servers must not manage identities.
```

Conditions: `when_agent_has_all`, `when_agent_has_any`, `when_server`,
`when_hash_changed`, `when_tool_name_shadowed`, `when_agents_chain` (steps in the order
content flows between agents). The format is defined by
[`schemas/policy.schema.json`](https://github.com/NKwolv/agent-capmap/blob/main/schemas/policy.schema.json). Rug-pull detection:

```sh
agentcapmap baseline create inventory.json -o baseline.json   # once, after review
agentcapmap evaluate new-inventory.json --baseline baseline.json
```

To see what changed between two runs (for example `main` versus a pull request), save
each `evaluate` output and compare them:

```sh
agentcapmap diff before.json after.json --format markdown
agentcapmap diff before.json after.json --fail-on high --fail-on-new-capability
```

`diff` lists new and resolved findings and capabilities an agent gained or lost.
`--fail-on` looks at new findings only, so existing, already-accepted findings do not
fail the build; `--fail-on-new-capability` fails when an agent gains any capability.

## CI and GitHub code scanning

```sh
agentcapmap evaluate inventory.json --format sarif -o agentcapmap.sarif --fail-on high
```

Exit codes: `0` passed, `1` findings at or above `--fail-on`, `2` usage or input error.
On pull requests the action can also post one comment that shows only what the PR
changed (`comment: "true"`; see the action docs).
The repository is also a GitHub Action: see [docs/github-action.md](https://github.com/NKwolv/agent-capmap/blob/main/docs/github-action.md)
and the [example workflow](https://github.com/NKwolv/agent-capmap/blob/main/docs/examples/agentcapmap.yml). By default the Action reads
configs only, which is safe for pull requests from forks.

## Accuracy

The classifier is evaluated against hand-labeled tools from real MCP servers (see
[`eval/`](https://github.com/NKwolv/agent-capmap/blob/main/eval/README.md)). **No accuracy numbers are published yet.** The 381 labels
(28 servers) were drafted by one AI model and corrected by a second. The maintainer then
went through **every tool in every file**, with AI-prepared summaries and recommendations,
and confirmed or changed each label (8 tags changed; the rest were confirmed). That is a
person's review, but not an independent one: the labels began as AI output and the review
leaned on AI recommendations, so a model grading itself can still overstate accuracy.
Numbers will be quoted here only from a frozen run (`python eval/run_eval.py`, which needs
an API key). The same labels also power classification without an API key for these known
tools; see [Limitations](#limitations).

## Limitations

- **Descriptions, not behavior.** Tools are classified by what their definitions say. A
  tool that lies about itself will be mis-tagged; agent-capmap never calls tools.
- **Classifier errors.** Tags can be wrong, especially for vague descriptions. Every
  tag carries a confidence and an evidence phrase; phrases not found in the definition
  are marked unverified.
- **Approval gates are mostly invisible.** Claude Code's permission settings are read
  (so its default "ask before each MCP call" counts as a gate), but most other clients do
  not record this, and CAP-003 treats "unknown" as "no gate" by default.
- **Enumeration runs code.** Starting servers executes the configured commands. A
  started server can also read its parent's environment on Linux.
- **Coverage.** Config formats evolve, and allowlists of tools (`includeTools`,
  `enabled_tools`) are not applied, which can over-report but never hide a tool. MCP
  servers that do not live in config files (Claude Code plugins, claude.ai connectors,
  IDE built-in servers, Zed extension servers, managed settings) are not seen. WebSocket
  servers are enumerated only with `pip install "agent-capmap[ws]"`. Token scopes are
  read only for classic GitHub tokens, and only with `--check-token-scopes`.
- **The runtime guard covers Claude Code and MCP tools.** It depends on the tags in its
  map, so a mis-tagged tool is mis-judged, and it only sees calls the hook is run for.
  Claude Code's built-in tools (`Bash`, `WebFetch`, file edits) are outside it unless
  you opt into tracking the reading ones, and it never blocks them. It records that a
  tool ran, not what data moved, so it can ask when the data was in fact harmless.
- **Cross-agent chains are inferred.** Sharing is assumed from an identical launch
  command or URL. That cannot see two tokens for different accounts, or an environment
  variable pointing each agent at a different store, and it misses stores shared by
  other means (the same folder through two different servers).
- **Reference labels are maintainer-reviewed, not independently verified.** For 381 tools
  from 28 well-known servers, the classifier answers from bundled labels (matched by exact
  definition hash) instead of calling a model, so no API key is needed. The maintainer
  reviewed every tool, but the labels began as AI output, and a wrong label is returned with
  full confidence; any change to a tool's definition falls back to the cache or the LLM.
  Treat them as a convenience.
- **Runtime discovery is heuristic.** `--running` recognizes servers by their command line
  and misses ones with unrelated names; a process can also be named to look like a
  declared server. It lists what it sees and is not proof of absence.
- **Not assessed is not safe.** Servers that could not be enumerated and tools that
  could not be classified are listed under `not_assessed`, never assumed safe.

## Safety

Secrets from configs are redacted in all output and logs. Enumeration sends only
`initialize` and the read-only listings of tools, prompts and resources (never calling,
reading or fetching anything), with a minimal environment for launched servers, no
credential-forwarding redirects, connections only to addresses that passed the
metadata-address check (no DNS rebinding), and size limits on everything a server returns.
Reports render untrusted text inertly. See [SECURITY.md](https://github.com/NKwolv/agent-capmap/blob/main/SECURITY.md) and the
[threat model](https://github.com/NKwolv/agent-capmap/blob/main/docs/threat-model.md).

## Documentation

- [Capability taxonomy](https://github.com/NKwolv/agent-capmap/blob/main/docs/taxonomy.md)
- [Threat model](https://github.com/NKwolv/agent-capmap/blob/main/docs/threat-model.md): attacks covered, OWASP / MITRE ATLAS mapping
- [GitHub Action](https://github.com/NKwolv/agent-capmap/blob/main/docs/github-action.md)
- [Comparison with Snyk Agent Scan (mcp-scan)](https://github.com/NKwolv/agent-capmap/blob/main/docs/vs-mcp-scan.md)
- [Examples](https://github.com/NKwolv/agent-capmap/blob/main/examples/README.md) · [Evaluation](https://github.com/NKwolv/agent-capmap/blob/main/eval/README.md) · [POC checklist](https://github.com/NKwolv/agent-capmap/blob/main/docs/poc-checklist.md)
- [Contributing](https://github.com/NKwolv/agent-capmap/blob/main/CONTRIBUTING.md) · [Security policy](https://github.com/NKwolv/agent-capmap/blob/main/SECURITY.md) · [Changelog](https://github.com/NKwolv/agent-capmap/blob/main/CHANGELOG.md)

## License

MIT. See [LICENSE](https://github.com/NKwolv/agent-capmap/blob/main/LICENSE).
