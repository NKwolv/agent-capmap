# Blog post outline (draft)

Working title: **"Your agent's riskiest tool is a combination: mapping MCP capabilities
per agent"**

Audience: engineers and security teams adopting AI coding agents with MCP servers.

Status: outline only. Every number below is a placeholder to be filled from
`eval/results.md` and real scans after Phase 5. **Do not publish placeholder values.**

## 1. Hook

- A concrete scenario: an agent with GitHub (issues + private repos) and an email tool.
  One public issue is enough to leak private code. No individual tool is malicious.
- The point: per-server scanning misses risks that only exist in combination.

## 2. The toxic-combination model

- Six capability axes per tool (link to `docs/taxonomy.md`).
- Risk is a property of the *agent*, the union of its tools, not of any one server.
- The lethal trifecta as the canonical example (credit Simon Willison), plus
  injection → host execution, secrets + egress, and destructive tools without approval.
- Design choice: the LLM classifies, deterministic policy decides. Why this matters
  for auditability and CI.

## 3. How agent-capmap works

- Discover → enumerate (`initialize` + `tools/list` only) → classify → policy → report.
- Safety properties: never calls tools, redacts secrets, enumeration is opt-in.
- Policy-as-code example (a CAP-001 rule in YAML) and a SARIF finding in the GitHub
  Security tab (screenshot after Phase 4).

## 4. What scanning public servers revealed

To be written from real data only:

- Number of servers and tools scanned: `TBD`
- Distribution of capabilities across categories: `TBD`
- How often common server combinations produce a trifecta: `TBD`
- Any suspicious descriptions found (responsibly disclosed first): `TBD`

## 5. How accurate is the classifier?

- Benchmark: `TBD` hand-labeled servers, `TBD` tools, labeled by `TBD` on `TBD`.
- Per-axis precision/recall/F1 and exact-match accuracy: from `eval/results.md`, with
  the model, prompt version and taxonomy version stated.
- Where it fails (vague descriptions, multi-purpose tools) and how evidence phrases and
  `unverified_evidence` help a reviewer catch it.

## 6. Limitations

- Classification reads descriptions; tools that lie are mis-tagged.
- Enumerating stdio servers runs their code.
- Client config formats and the MCP spec keep changing.
- Comparison with Snyk Agent Scan: what it does better (breadth, skills, maintained
  backend), where this approach differs (link to `docs/vs-mcp-scan.md`).

## 7. Try it

- Install and quickstart commands from the README.
- Call for contributions: new config formats, labeled servers for the benchmark.
