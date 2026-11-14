"""Runtime guard for Claude Code: build a guard map from a scan, enforce it in a hook.

`build.py` turns a classified inventory and a policy into a guard map (uses the full
package). `hook.py` is the hook itself and imports only the standard library, so it can
run on every tool call without the start-up cost of the scanner.
"""
