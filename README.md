# agent-capmap

Inventory the MCP servers and tools reachable by each AI agent, classify their
capabilities, and flag dangerous capability combinations with policy-as-code.

> Status: early development. Discovery and enumeration work; classification, the
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
