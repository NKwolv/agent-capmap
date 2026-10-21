# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability
reporting: open the repository's **Security** tab and choose **Report a
vulnerability**. Do not open a public issue.

Include what you found, how to reproduce it, and the impact you expect. We aim to
acknowledge reports within 7 days.

Especially relevant reports:

- secret values appearing in agent-capmap output, logs or error messages;
- any way to make agent-capmap send an MCP request other than `initialize`,
  `notifications/initialized` or `tools/list`;
- a tool definition that can make the classifier ignore its instructions or escape
  the data delimiters;
- a config file that crashes discovery or causes code to run without `--enumerate`.

## Supply chain

- Dependencies are installed from hash-pinned lockfiles (`requirements/`), resolved
  only from releases at least 14 days old.
- Every CI run scans for known-vulnerable dependencies (pip-audit), runs static analysis
  (bandit, CodeQL), audits the CI workflows (zizmor), scans the full git history for
  secrets (gitleaks), and publishes a CycloneDX SBOM of the runtime dependencies as a
  build artifact.

## Supported versions

agent-capmap is pre-1.0. Only the latest release on `main` receives fixes.

## Using agent-capmap safely

- **`scan` without `--enumerate` only reads files.** It is safe to run on untrusted
  repositories.
- **`scan --user` reads your clients' config files**, including Claude Code's
  `~/.claude.json`. From that file only MCP server entries, per-project MCP toggles
  and permission rules are used; account data and chat history are ignored, and a
  stored `primaryApiKey` is treated as a secret that can never appear in output.
- **`--enumerate` starts the stdio server commands found in configs** and connects to
  their URLs. That executes whatever the config specifies. Only enumerate configs you
  trust, and prefer a disposable environment (container, CI runner) for unfamiliar
  ones.
- **Launched servers get a minimal environment.** They inherit only a short allowlist
  of variables (such as `PATH` and `HOME`), not your API keys or cloud credentials.
  Anything else a server needs must be set in its config.
- **Remote servers cannot redirect your credentials.** agent-capmap never follows HTTP
  redirects and rejects cross-origin SSE endpoints.
- **`--classify` sends tool names, descriptions and input schemas** to the configured
  LLM provider (Anthropic by default). Config values such as env vars, headers and
  arguments are never sent. Use `--offline` to classify from the local cache only.
- **The classification cache** (by default under your user cache directory, or
  `AGENTCAPMAP_CACHE_DIR`) holds tool definitions' classifications and evidence
  phrases, not secrets.
- **Results describe what tools claim to do.** A server that lies in its tool
  descriptions can evade classification. See
  [docs/threat-model.md](docs/threat-model.md).
