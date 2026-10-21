# Proof-of-concept checklist (before going public)

A step-by-step plan to convince yourself agent-capmap works, and is safe to publish,
before making the repository public. Each step says what "pass" looks like. Steps 1-4
need no API key.

## 1. It installs cleanly from the lockfile (5 min)

In a fresh clone and a fresh virtual environment, follow the README quickstart exactly.

- [ ] `pip install --require-hashes -r requirements/runtime.lock` and `pip install --no-deps .` succeed.
- [ ] `agentcapmap --version` prints `agentcapmap 0.1.0`.
- [ ] The whole quickstart takes under 5 minutes.

## 2. The test suite passes (2 min)

```sh
pip install --require-hashes -r requirements/dev.lock && pip install --no-deps --no-build-isolation -e .
pytest
```

- [ ] All tests pass (about 290).

## 3. The demo gives the documented findings (1 min)

```sh
agentcapmap evaluate examples/demo/inventory.json --format markdown
agentcapmap evaluate examples/demo/inventory.json --fail-on high; echo "exit $?"
```

- [ ] 2 critical, 2 high, 1 medium finding; 1 tool not assessed.
- [ ] Exit code `1` with `--fail-on high`, `0` with `--fail-on none`.
- [ ] Every finding shows evidence phrases taken from tool descriptions.

## 4. It reads your real setup without leaking anything (5 min)

```sh
agentcapmap scan --user -o my-configs.json
```

- [ ] Every MCP server you actually use (Claude Desktop, Cursor, VS Code, Claude Code
      project files) is listed.
- [ ] Open `my-configs.json` and search it for any real token, password or key you know
      is in your configs: **none may appear**, only `<redacted>`.
- [ ] Nothing was started (no new processes, no network traffic).

## 5. End to end on known servers (10 min, API key)

```sh
export ANTHROPIC_API_KEY=<YOUR_API_KEY>
agentcapmap scan examples/live-trifecta --enumerate --classify --evaluate --format markdown -o live.md
```

- [ ] `live.md` contains CAP-001 (critical) involving `files` and `fetch`.
- [ ] The evidence phrases make sense to you when you read the tool descriptions.
- [ ] Running the same command again is fast and makes no API calls (cached).

## 6. Your own agents (15 min, API key, trusted configs only)

```sh
agentcapmap scan --user --enumerate --classify --evaluate --format markdown -o mine.md
```

- [ ] Read every finding: is it real? Note false alarms and missed risks.
- [ ] Read `not_assessed`: are the reasons understandable (missing credentials, server
      failed to start)?
- [ ] Spot-check 10-20 tool tags against [docs/taxonomy.md](taxonomy.md).

## 7. Accuracy benchmark (1-3 hours of review, API key)

See [eval/README.md](../eval/README.md).

- [ ] Review and correct every file in `eval/labeled_servers/`, setting `status: reviewed`.
- [ ] `python eval/run_eval.py --freeze`, then `python eval/run_eval.py`.
- [ ] `eval/results.md` is no longer marked PROVISIONAL.
- [ ] Write the "Known failure modes" section from the disagreements table.
- [ ] Copy the headline numbers into the README's Accuracy section, exactly as printed.

## 8. CI and the GitHub Action

- [ ] On GitHub, the latest `main` run of **CI** and **Action self-test** is green.
- [ ] Make a throwaway test repository with one of the `fixtures/*/mcp.json` files and
      the [example workflow](examples/agentcapmap.yml) (pin `NKwolv/agent-capmap` to a
      commit SHA). The `pr-check` job fails on findings and writes a job summary.
- [ ] After going public (code scanning is free for public repos), findings appear in
      that test repo's **Security > Code scanning** tab.

## 9. Before flipping the repository to public

- [ ] `gitleaks git . --config .gitleaks.toml` on the full history: no findings.
- [ ] No personal paths, emails or internal hostnames in tracked files
      (`git grep -n -i "users/<you>\|@<your-company>"`).
- [ ] Settings: enable secret scanning + push protection, Dependabot alerts, private
      vulnerability reporting, and branch protection on `main` (require CI).
- [ ] Decide what to do with the deprecated servers and AI-drafted labels in `eval/`
      (keep, with the PROVISIONAL banner, until reviewed).
- [ ] Tag `v0.1.0` and pin the example workflow to that commit SHA.

## 10. After going public

- [ ] CodeQL runs green on `main`.
- [ ] Publish to PyPI with trusted publishing (no stored token), then update the README
      install instructions to `pip install agent-capmap`.
