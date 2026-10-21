# agent-capmap vs. mcp-scan (Snyk Agent Scan)

mcp-scan, created by Invariant Labs, is the best-known MCP security scanner. Snyk
acquired Invariant Labs, and the project is now **Snyk Agent Scan**
([github.com/snyk/agent-scan](https://github.com/snyk/agent-scan)); the `mcp-scan`
package points to it. This page compares the two tools honestly. They overlap, and
they are built around different questions.

> Claims about Snyk Agent Scan were checked against its README on 2026-10-20 (it covers
> the v0.5.x and v0.6+ CLI lines). That project changes quickly, so re-check before
> relying on any specific detail.

## The short version

- **Snyk Agent Scan** asks: *is this server, tool or skill risky?* It covers a broad
  set of agent clients and component types and runs its analysis through Snyk's API.
- **agent-capmap** asks: *given every tool this agent can reach, what dangerous
  combination of capabilities does it have, and does that violate our policy?* It
  classifies each tool into a fixed capability taxonomy, then applies deterministic,
  org-defined rules per agent.

If you want broad, maintained risk detection across many agent clients with minimal
setup, use Snyk Agent Scan. If you want an inspectable, per-agent capability inventory
with rules you write yourself and enforce in CI, that is what agent-capmap is for. The
two can be used together.

## What Snyk Agent Scan already does well

- **Breadth of discovery.** Its README lists Windsurf, Cursor, VS Code, GitHub Copilot,
  Claude Desktop, Claude Code, Gemini CLI, Amp, Amazon Q, Codex, Kiro, OpenCode and
  others. agent-capmap currently reads five config formats.
- **More than MCP.** It also analyzes agent skills (prompt injection, suspicious
  downloads, malicious code, credential handling, secret detection). agent-capmap only
  covers MCP tools.
- **A maintained detection backend.** It reports 14 risk types across MCP servers and
  skills, using local checks plus the Agent Scan API.
- **Cross-tool risks.** The v0.5.x line lists "Toxic Flows" and "Tool Shadowing" among
  its MCP risks, so combination-style analysis is not unique to agent-capmap.
- **Operational features.** It has `--json` output, a `--ci` flag that exits non-zero on
  findings, a background mode that reports to a Snyk instance, and secret redaction
  before anything is sent.

## Where agent-capmap differs

| | Snyk Agent Scan | agent-capmap |
|---|---|---|
| Unit of analysis | Components (servers, tools, skills) on a machine | The **agent**: the union of every tool reachable from one client config |
| Capability model | Risk categories from its backend | An explicit, versioned [six-axis taxonomy](taxonomy.md) per tool, with evidence phrases |
| Who decides "dangerous" | The scanner's analysis | **Your policy file**: deterministic rules over tag combinations, with severities and mappings you control |
| Role of the LLM | Part of the analysis service | Classification only; it never makes risk decisions |
| Where analysis runs | Snyk's Agent Scan API (needs a Snyk account and `SNYK_TOKEN`) | Locally, plus an LLM provider you choose (default: Anthropic API with your own key); `--offline` uses the local cache only |
| What leaves your machine | Per its README: agent application details, server configurations and signatures, tool names and descriptions, skill content (secrets redacted) | With `--classify`: tool names, descriptions and input schemas. Config values are never sent |
| Output for CI | JSON and a `--ci` exit code | JSON, Markdown and **SARIF** for GitHub code scanning; `--fail-on <severity>` exit codes; a composite GitHub Action |
| Repo scanning | Machine and agent oriented | Walks a repository for checked-in configs (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`) without starting anything |
| Accuracy reporting | No published numbers we could find | A benchmark of real servers with per-axis precision/recall ([eval/](../eval/README.md)); numbers are published only from a reviewed, frozen label set |
| License / contributions | Apache-2.0; README says external contributions are not accepted | MIT; contributions welcome |

## What neither tool does

- Neither can see what a tool *actually* does at runtime from its definition alone.
  agent-capmap never calls tools, by design.
- Both start stdio servers when asked to enumerate them (Snyk Agent Scan's flag is
  `--dangerously-run-mcp-servers`; agent-capmap's is `--enumerate`). Only do this for
  configs you trust.

## Status note

agent-capmap is early. Discovery, enumeration, classification, the policy engine,
baseline pinning, JSON/Markdown/SARIF output, `--fail-on` exit codes and the GitHub
Action are implemented. The accuracy benchmark harness exists; its numbers will be
published once the labels have been reviewed. Rows above marked with a phase number
describe that plan.
