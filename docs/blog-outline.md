# Blog post outline (draft)

Working title: **"Your agent's riskiest tool is a combination: mapping MCP capabilities
per agent"**

Audience: engineers and security teams adopting AI coding agents with MCP servers.

Status: outline. Every number marked `TBD` must come from `eval/results.md` after the
labels are reviewed and frozen. **Do not publish placeholder values.**

## 1. Hook

- A concrete scenario: an agent with GitHub (issues + private repos) and an email or
  fetch tool. One public issue is enough to leak private code. No single tool is
  malicious.
- Per-server scanning misses risks that only exist in combination.

## 2. The toxic-combination model

- Six capability axes per tool ([docs/taxonomy.md](taxonomy.md)).
- Risk is a property of the agent (the union of its tools), not of a single server.
- The lethal trifecta (credit Simon Willison), injection to host execution, secrets plus
  egress, destructive tools without approval.
- The LLM classifies; deterministic policy decides. Why that matters for audits and CI.

## 3. How agent-capmap works

- Discover → enumerate (`initialize` + `tools/list` only) → classify → policy → report.
- Safety properties: never calls tools, redacts secrets, minimal environment for
  launched servers, enumeration is opt-in.
- Policy-as-code example and a SARIF finding in the GitHub Security tab (screenshot
  from the POC test repository).

## 4. What real servers look like

From the capture of TBD real MCP servers (TBD tools) in `eval/`:

- Capability mix by category (filesystem, git hosting, search, browser, cloud, shell).
- Observed in captured definitions (verifiable in `eval/labeled_servers/`):
  - Real descriptions contain model-directed instructions. The official `fetch` server
    tells the model that it was "advised to refuse" earlier but now has internet access;
    AWS's server asks the model to tell the user about a deprecation. Where is the line
    between guidance and tool poisoning?
  - A Playwright tool describes itself as "RCE-equivalent".
  - Servers embed local paths in descriptions (a privacy leak when definitions are
    shared).
  - Several popular reference servers are deprecated but still installable.
- Which common agent setups trip which rules (from `eval/results.md`): TBD.

## 5. How accurate is the classifier?

- Benchmark: TBD servers, TBD tools, labels reviewed by TBD on TBD.
- Exact-match accuracy, per-axis detection precision/recall, false-positive rate on
  clean agents, planted-risk recall: all TBD, quoted exactly from `eval/results.md`,
  with the model, prompt version and taxonomy version.
- Failure modes from the disagreements table: TBD.
- Methodology notes: AI-drafted labels were reviewed by a person before scoring; the
  label set was frozen before the run.

## 6. Limitations

- Classification reads descriptions; a tool that lies is mis-tagged.
- Enumerating stdio servers runs their code; a launched process can read its parent's
  environment.
- Approval settings are rarely visible in configs.
- Config formats and the MCP spec keep changing.
- Comparison with Snyk Agent Scan: what it does better (breadth, skills, maintained
  backend) and where this approach differs ([docs/vs-mcp-scan.md](vs-mcp-scan.md)).

## 7. Try it

- README quickstart (no API key) and `examples/live-trifecta`.
- Call for contributions: config formats, labeled servers, policy rules.
