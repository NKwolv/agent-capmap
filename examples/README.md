# Examples

## `demo/`: no API key, nothing started

A ready-made inventory of five example agents whose tools are already classified (built
from the scenario fixtures). Use it to see the policy engine and the report formats:

```sh
agentcapmap evaluate examples/demo/inventory.json --format markdown
agentcapmap evaluate examples/demo/inventory.json --format sarif -o demo.sarif
agentcapmap evaluate examples/demo/inventory.json --fail-on high; echo "exit $?"
```

Expected: 2 critical, 2 high and 1 medium finding, plus 1 tool reported as not assessed.

## `live-trifecta/`: real servers, needs an API key

Two real MCP servers that together form the "lethal trifecta": a filesystem server
(reads private files, limited to `live-trifecta/sandbox/`) and a web-fetch server (takes
in untrusted web content and can send data out). This exercises the whole pipeline:
start the servers, list their tools, classify them with Claude, apply the policy.

Needs Node.js (`npx`), uv (`uvx`) and `ANTHROPIC_API_KEY`.

```sh
agentcapmap scan examples/live-trifecta --enumerate --classify --evaluate --format markdown
```

Expected: CAP-001 (critical) on `files` + `fetch`, most likely also CAP-003 (high) for
the filesystem server's write/move tools. A second run makes no API calls (cache).
The exact tags come from the classifier, so check the evidence phrases in the report.
