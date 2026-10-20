# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Classifier** (Phase 2): LLM classification of every enumerated tool into the six-axis
  taxonomy v1, with suspicious-description (tool poisoning) flags.
  - Output constrained by structured outputs and validated against
    `schemas/tool-tags.schema.json`; one retry, then `unclassified`.
  - Evidence phrase required for every non-default tag; phrases not found in the tool
    definition are reported as `unverified_evidence`.
  - On-disk cache keyed by definition hash, taxonomy version, prompt version and model.
  - `scan --enumerate --classify`, `classify INVENTORY`, `--offline`, `--cache-dir`,
    `--model`; `AGENTCAPMAP_MODEL`, `AGENTCAPMAP_EFFORT`, `AGENTCAPMAP_CACHE_DIR`.
- **Discovery and enumeration** (Phase 1):
  - Config parsers for Claude Desktop, Cursor, VS Code (`mcp.json` and
    `settings.json`), Claude Code `.mcp.json` and generic `mcp.json`, normalized to
    `Agent -> [Server]` with transport, auth hints and source line numbers.
  - Repository walk and per-user config discovery (`scan --user`).
  - MCP client for stdio, Streamable HTTP and legacy SSE that sends only `initialize`
    and `tools/list`, with timeouts, pagination and `${...}` / `envFile` resolution.
  - Canonical SHA-256 tool definition hashes and a per-server hash.
  - Secret redaction across all output and logs.
- Documentation: taxonomy, threat model, comparison with Snyk Agent Scan (formerly
  mcp-scan), contributing guide, security policy.

### Notes

- Current Claude models do not accept `temperature`; it is set to 0 only for older
  models that support it. Reproducibility relies on the cache and on the recorded
  model, prompt and taxonomy versions.
