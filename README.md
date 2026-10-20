# agent-capmap

Inventory the MCP servers and tools reachable by each AI agent, classify their
capabilities, and flag dangerous capability combinations with policy-as-code.

> Status: early development. Discovery, enumeration and classification work; the
> policy engine and reporting are in progress.

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

## Safety

- Secret values from configs (env vars, headers, tokens in args or URLs) are redacted
  from all output and logs.
- `--enumerate` sends only `initialize` and `tools/list`; tools are never called. It
  does, however, **launch the stdio server commands** in the configs, so only enumerate
  configs you trust.

## Development

```sh
ruff check . && ruff format --check . && mypy && pytest
```
