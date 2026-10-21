# agent-capmap

**Find out what your AI agents can actually do, and which combinations of their tools
an attacker could abuse.**

AI assistants such as Claude Desktop, Cursor, VS Code and Claude Code get their powers
from MCP servers: read files, browse the web, send email, run shell commands. Each tool
can look harmless on its own. The danger is usually the combination: an agent that can
read private data, read attacker-written content (a web page, an issue, an email), and
send data out can be talked into leaking that data. That is the "lethal trifecta".

agent-capmap inventories every MCP server and tool reachable by each agent, classifies
what each tool can do, and applies policy-as-code rules to the **combination** of tools
per agent. Findings come with evidence and can gate CI through SARIF and exit codes.

> **Status: pre-release (0.1.0).** All features below work. The classifier's accuracy
> has not been benchmarked yet; see [Accuracy](#accuracy).

## Quickstart (5 minutes, no API key)

Requires Python 3.11+ and git.

```sh
git clone https://github.com/NKwolv/agent-capmap
cd agent-capmap
python -m venv .venv
. .venv/bin/activate            # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install --require-hashes -r requirements/runtime.lock
pip install --no-deps .

# 1. See findings on a ready-made inventory of five example agents
agentcapmap evaluate examples/demo/inventory.json --format markdown

# 2. List the MCP servers configured on your own machine (reads files only)
agentcapmap scan --user
```

Step 1 should report 2 critical, 2 high and 1 medium finding. Step 2 lists your
servers with every secret redacted, without starting anything.

> **Windows:** if `pip install` fails with "No such file or directory" deep inside
> `site-packages`, the path is too long for Windows' 260-character limit. Clone to a
> short path (for example `C:\src\agent-capmap`) or enable long path support.

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
                              tools/list)    6 axes)      rules)     SARIF, exit code)
```

1. **Discover** MCP configs: Claude Desktop, Cursor, VS Code (`.vscode/mcp.json`,
   `settings.json`), Claude Code (`.mcp.json`) and generic `mcp.json`, in a repository
   or on your machine (`--user`). Secrets are redacted everywhere.
2. **Enumerate** (`--enumerate`): start each server and ask only for its tool list.
   Tools are never called.
3. **Classify** (`--classify`): an LLM tags each tool on six axes and flags tool
   descriptions that try to manipulate the model. Results are cached and validated
   against a JSON schema.
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
[`examples/live-trifecta`](examples/README.md).

## Capability taxonomy

| Axis | Values | Question |
|---|---|---|
| `data_access` | none, private_read, secrets_read | What non-public data can it read? |
| `untrusted_input` | false, true | Does it return content strangers can write? |
| `egress` | none, internal, external | Can it send data somewhere an outsider can read? |
| `mutation` | none, reversible_write, destructive | What can it change or delete? |
| `execution` | none, sandboxed, host | Does it run code, and where? |
| `privilege` | none, identity_admin | Does it manage users or permissions? |

Definitions and edge-case rulings: [docs/taxonomy.md](docs/taxonomy.md).

## Policy

The built-in [`policies/default.yaml`](policies/default.yaml) has nine rules:

| ID | Severity | Fires when an agent has |
|---|---|---|
| CAP-001 | critical | private data + untrusted input + external egress (lethal trifecta) |
| CAP-002 | critical | untrusted input + host code execution |
| CAP-003 | high | a destructive or host-execution tool with no approval gate |
| CAP-004 | high | secrets access + external egress |
| CAP-005 | high | a remote server with no authentication exposing capabilities |
| CAP-006 | high | tool definitions that changed since the baseline (rug pull) |
| CAP-007 | medium | a server not pinned to an exact version, or from an unvetted source |
| CAP-008 | high | a tool description that tries to instruct the model (tool poisoning) |
| CAP-009 | medium | the same tool name on two servers (shadowing) |

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
`when_hash_changed`, `when_tool_name_shadowed`. The format is defined by
[`schemas/policy.schema.json`](schemas/policy.schema.json). Rug-pull detection:

```sh
agentcapmap baseline create inventory.json -o baseline.json   # once, after review
agentcapmap evaluate new-inventory.json --baseline baseline.json
```

## CI and GitHub code scanning

```sh
agentcapmap evaluate inventory.json --format sarif -o agentcapmap.sarif --fail-on high
```

Exit codes: `0` passed, `1` findings at or above `--fail-on`, `2` usage or input error.
The repository is also a GitHub Action: see [docs/github-action.md](docs/github-action.md)
and the [example workflow](docs/examples/agentcapmap.yml). By default the Action reads
configs only, which is safe for pull requests from forks.

## Accuracy

The classifier is evaluated against hand-labeled tools from real MCP servers (see
[`eval/`](eval/README.md)). **No accuracy numbers are published yet**: the label set is
still being reviewed, and numbers will be quoted here only from a reviewed, frozen run
of `python eval/run_eval.py`.

## Limitations

- **Descriptions, not behavior.** Tools are classified by what their definitions say. A
  tool that lies about itself will be mis-tagged; agent-capmap never calls tools.
- **Classifier errors.** Tags can be wrong, especially for vague descriptions. Every
  tag carries a confidence and an evidence phrase; phrases not found in the definition
  are marked unverified.
- **Approval gates are mostly invisible.** Few configs record whether a person approves
  each call, so CAP-003 treats "unknown" as "no gate" by default.
- **Enumeration runs code.** Starting servers executes the configured commands. A
  started server can also read its parent's environment on Linux.
- **Coverage.** Config formats evolve; Windsurf and Claude Code's user-level
  `~/.claude.json` are not read yet. Token scopes are not visible.
- **Not assessed is not safe.** Servers that could not be enumerated and tools that
  could not be classified are listed under `not_assessed`, never assumed safe.

## Safety

Secrets from configs are redacted in all output and logs. Enumeration sends only
`initialize` and `tools/list`, with a minimal environment for launched servers, no
credential-forwarding redirects, and size limits on everything a server returns.
Reports render untrusted text inertly. See [SECURITY.md](SECURITY.md) and the
[threat model](docs/threat-model.md).

## Documentation

- [Capability taxonomy](docs/taxonomy.md)
- [Threat model](docs/threat-model.md): attacks covered, OWASP / MITRE ATLAS mapping
- [GitHub Action](docs/github-action.md)
- [Comparison with Snyk Agent Scan (mcp-scan)](docs/vs-mcp-scan.md)
- [Examples](examples/README.md) · [Evaluation](eval/README.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)

## License

MIT. See [LICENSE](LICENSE).
