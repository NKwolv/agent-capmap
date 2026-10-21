# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

Everything below is unreleased work towards 0.1.0, newest first within each section.

### Added

- **Claude Code user configuration**: `scan --user` reads `~/.claude.json` (or
  `$CLAUDE_CONFIG_DIR/.claude.json`): one agent for user scope plus one per project with
  local servers or a `.mcp.json`, applying Claude Code's precedence (local > project >
  user), `/mcp` toggles and `disabledMcpjsonServers`. Only MCP entries are read;
  `primaryApiKey` is registered as a known secret and never output.
- **Approval gates from Claude Code permissions**: `permissions.allow` / `deny` rules
  (`mcp__<server>`, `mcp__<server>__*`, `mcp__<server>__<tool>`), `defaultMode` and legacy
  `allowedTools`. Default mode yields `approval_gate: required`; `bypassPermissions` and
  `auto` yield `none`; denied tools and `dontAsk`-blocked tools are removed from the
  agent. Project `.mcp.json` files use only that project's `.claude/settings*.json`.
- WebSocket (`"type": "ws"`) servers are accepted and listed (not enumerated).
- **Docs and examples** (Phase 6): rewritten README with a 5-minute no-key quickstart,
  `examples/demo` (pre-classified inventory) and `examples/live-trifecta` (real
  servers), `docs/poc-checklist.md`, updated blog outline.
- **Evaluation harness** (Phase 5):
  - `eval/catalog.json` of real MCP servers pinned to vetted versions, `eval/capture.py`
    to record their tool definitions (local paths scrubbed), `eval/apply_labels.py`
    to write labels whose evidence phrases are verified against the definitions.
  - Label files for 28 servers / 381 tools in `eval/labeled_servers/` (AI-drafted,
    pending human review), with integrity checks and freezing (`labels.lock`).
  - `eval/run_eval.py`: per-axis precision/recall/F1, exact match, confusion matrices,
    suspicious-flag precision/recall, rule-level agreement and false-positive rate on
    realistic agents (`eval/agents.json`), planted-risk recall on `fixtures/`. Results
    are marked PROVISIONAL until every label file is reviewed.
- **Reporting and CI** (Phase 4):
  - `--format json|markdown|sarif` on `evaluate` and `scan --evaluate`; `report` command
    to re-render a saved evaluation.
  - `--fail-on <severity>` and `--fail-on-not-assessed`; exit codes 0 / 1 / 2.
  - SARIF 2.1.0 validated against the official OASIS schema: rules with
    `security-severity`, repository-relative locations with related locations per
    server, stable `partialFingerprints`, notifications for not-assessed items, skipped
    rules and omitted results.
  - Markdown report and GitHub job summary, with all untrusted text rendered inertly.
  - Composite GitHub Action (`action.yml`) installing from hash-pinned lockfiles, with
    an example workflow (`docs/examples/agentcapmap.yml`) and a self-test workflow.
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
  mcp-scan), GitHub Action guide, contributing guide, security policy, `AGENTS.md`.

### Security

- `certifi` raised to 2026.10.19 (GHSA-6q48-6c7w-9gw2: older bundles trust emSign root
  CAs whose intermediate keys are compromised); it is the CA bundle behind every HTTPS
  connection agent-capmap makes.
- Dev tool `uv` raised to 0.13.4 (GHSA-hq85-5cpj-mr62, same root cause).
- Both fixes were newer than the 14-day lockfile cutoff, so each was exempted
  individually; the procedure is documented in CONTRIBUTING.md.
- Launched stdio servers inherit only an allowlisted environment, so the scanner's own
  credentials (e.g. `ANTHROPIC_API_KEY`) are not exposed to them.
- HTTP redirects are not followed and legacy-SSE endpoints must be same-origin, so
  configured credentials cannot be forwarded to another host. Only `http`/`https` URLs
  are accepted.
- Size limits on all server and config input; tool count cap; deep-nesting and
  non-UTF-8 input handled as clean errors.
- Redaction regexes rewritten to avoid catastrophic backtracking (a 20 KB hostile
  string previously took ~15 s).
- Control characters escaped in log output.
- HTTP error messages do not include raw exception text that could contain URL secrets.
- Security gates: ruff `S` rules, bandit, pip-audit, zizmor and CodeQL in CI; GitHub
  Actions pinned to commit SHAs; Dependabot for pip and Actions with a 14-day cooldown.
- Hash-pinned lockfiles (`requirements/runtime.lock`, `dev.lock`, `build.lock`),
  resolved with a 14-day `--exclude-newer` cutoff; CI installs with `--require-hashes`
  and builds without fetching an unpinned build backend.
- Secret scanning of the full git history with gitleaks (image pinned by digest).
- CycloneDX SBOM of the runtime dependencies generated in CI.
- `.gitignore` covers key, certificate, credential and state files; `.env.example`.

### Fixed

- `${workspaceFolder}` and the server working directory were relative when the scan path
  was relative, so the path was applied twice (found by the live example).
- A `.gitignore` pattern hid `examples/demo/inventory.json` (found by the fresh-clone
  quickstart test).
- The package now ships a `py.typed` marker.

### Notes

- Current Claude models do not accept `temperature`; it is set to 0 only for older
  models that support it. Reproducibility relies on the cache and on the recorded
  model, prompt and taxonomy versions.
