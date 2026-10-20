# agent-capmap

Inventory the MCP servers and tools reachable by each AI agent, classify their
capabilities, and flag dangerous capability combinations with policy-as-code.

> Status: early development. Discovery, enumeration, classification and the policy
> engine work; SARIF/Markdown reporting and the GitHub Action are in progress.

## Quickstart

```sh
pip install -e ".[dev]"

# Discover MCP configs in a repo (no servers are started)
agentcapmap scan path/to/repo

# Include per-user configs (Claude Desktop, Cursor, VS Code)
agentcapmap scan --user

# Also connect to each server and list its tools
agentcapmap scan path/to/repo --enumerate -o inventory.json
```

## Classification

`--classify` (or `agentcapmap classify inventory.json`) asks an LLM to tag each tool
on six capability axes and to flag suspicious descriptions. Risk decisions are never
made by the LLM; they come from the deterministic policy engine.

```sh
export ANTHROPIC_API_KEY=...
agentcapmap scan path/to/repo --enumerate --classify -o inventory.json
agentcapmap classify inventory.json --offline   # cache only, no API calls
```

- Model: `claude-opus-5-5` by default; override with `--model` or `AGENTCAPMAP_MODEL`
  (effort via `AGENTCAPMAP_EFFORT`, default `medium`).
- Output is constrained by structured outputs and validated against
  [`schemas/tool-tags.schema.json`](schemas/tool-tags.schema.json). Invalid output is
  retried once, then the tool is marked `unclassified`.
- Results are cached on disk keyed by tool definition hash, taxonomy version, prompt
  version and model, so unchanged tools are never re-sent. Set the location with
  `--cache-dir` or `AGENTCAPMAP_CACHE_DIR`.
- Determinism: current Claude models do not accept `temperature`, so it is set to 0
  only for older models that support it. Reproducibility comes from the cache plus the
  pinned model, prompt and taxonomy versions recorded on every result.

Supported config formats: Claude Desktop (`claude_desktop_config.json`), Cursor
(`.cursor/mcp.json`), VS Code (`.vscode/mcp.json`, `mcp` block in `settings.json`),
Claude Code (`.mcp.json`) and generic `mcp.json`.

## Policy and findings

Findings come from deterministic rules in a YAML policy, evaluated per agent over the
union of its tools. The built-in [`policies/default.yaml`](policies/default.yaml)
implements rules CAP-001 to CAP-009 (see the [threat model](docs/threat-model.md)).

```sh
# Evaluate a saved, classified inventory
agentcapmap evaluate inventory.json

# Or scan, enumerate, classify and evaluate in one go
agentcapmap scan path/to/repo --enumerate --classify --evaluate -o findings.json

# Use your own policy
agentcapmap evaluate inventory.json --policy my-policy.yaml

# Rug-pull detection: pin tool definitions once, compare later
agentcapmap baseline create inventory.json -o baseline.json
agentcapmap evaluate new-inventory.json --baseline baseline.json
```

A rule combines conditions on the tools an agent can reach:

```yaml
- id: CAP-001
  severity: critical
  when_agent_has_all:            # each predicate matched by some tool on the agent
    - data_access: [private_read, secrets_read]
    - untrusted_input: true
    - egress: external
  message: "Lethal trifecta: injection can exfiltrate private data"
  maps_to: [OWASP-LLM01, OWASP-LLM06]
```

Other conditions: `when_agent_has_any`, `when_server` (auth, transport, remote,
version_pinned, source_trust), `when_hash_changed` and `when_tool_name_shadowed`. The
format is defined by [`schemas/policy.schema.json`](schemas/policy.schema.json); unknown
fields are rejected.

Every finding includes its evidence (agent, servers, tools, the matched tags and the
phrases from the tool definitions behind them). Tools that could not be enumerated or
classified are listed under `not_assessed` rather than guessed at.

The [`fixtures/`](fixtures/) directory has one example agent per rule.

## Safety

- Secret values from configs (env vars, headers, tokens in args or URLs) are redacted
  from all output and logs.
- `--enumerate` sends only `initialize` and `tools/list`; tools are never called. It
  does, however, **launch the stdio server commands** in the configs, so only enumerate
  configs you trust.

## Documentation

- [Capability taxonomy](docs/taxonomy.md): the six axes, edge-case rulings, versioning
- [Threat model](docs/threat-model.md): attacks covered, OWASP / MITRE ATLAS mapping, policy rules
- [Comparison with Snyk Agent Scan (mcp-scan)](docs/vs-mcp-scan.md)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)

## Development

```sh
ruff check . && ruff format --check . && mypy && pytest
```
