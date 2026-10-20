# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Policy engine** (Phase 3):
  - Per-agent capability graph with per-tool provenance (`agents[].capabilities`).
  - YAML policy loader hardened for untrusted files (safe loader only; anchors,
    aliases and duplicate keys rejected; flow-nesting depth and size capped; strict
    schema in `schemas/policy.schema.json`).
  - Deterministic rules with evidence: `when_agent_has_all`, `when_agent_has_any`,
    `when_server`, `when_hash_changed`, `when_tool_name_shadowed`.
  - Default policy `policies/default.yaml` with CAP-001 to CAP-009.
  - Server attributes from config: version pinning (npm, PyPI, Docker digests, local
    scripts), source trust (`trusted_sources`), per-tool approval gates
    (`alwaysAllow`, `autoApprove`, `trust`).
  - Baseline pinning: `agentcapmap baseline create`, `--baseline` (CAP-006).
  - Tools that were not enumerated or classified are reported as `not_assessed`.
  - CLI: `evaluate`, `baseline create`, `scan --evaluate --policy --baseline
    --save-inventory`.
  - Scenario fixtures for every section-7 case with golden-file tests.
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

### Security

- Launched stdio servers inherit only an allowlisted environment, so the scanner's own
  credentials (e.g. `ANTHROPIC_API_KEY`) are not exposed to them.
- HTTP redirects are no longer followed and legacy-SSE endpoints must be same-origin, so
  configured credentials cannot be forwarded to another host. Only `http`/`https` URLs
  are accepted.
- Size limits on all server and config input; tool count cap; deep-nesting and
  non-UTF-8 input handled as clean errors.
- Redaction regexes rewritten to avoid catastrophic backtracking (a 20 KB hostile
  string previously took ~15 s).
- Control characters escaped in log output.
- HTTP error messages no longer include raw exception text that could contain URL
  secrets.
- Security gates: ruff `S` rules, bandit, pip-audit, zizmor and CodeQL in CI; GitHub
  Actions pinned to commit SHAs; Dependabot for pip and Actions with a 14-day cooldown.
- Hash-pinned lockfiles (`requirements/runtime.lock`, `requirements/dev.lock`),
  resolved with a 14-day `--exclude-newer` cutoff; CI installs with `--require-hashes`
  and builds without fetching an unpinned build backend.
- Secret scanning of the full git history with gitleaks (image pinned by digest).
- CycloneDX SBOM of the runtime dependencies generated in CI.
- `AGENTS.md` security rules for people and AI coding tools; `.gitignore` covers key,
  certificate, credential and state files; `.env.example` added.

### Notes

- Current Claude models do not accept `temperature`; it is set to 0 only for older
  models that support it. Reproducibility relies on the cache and on the recorded
  model, prompt and taxonomy versions.
