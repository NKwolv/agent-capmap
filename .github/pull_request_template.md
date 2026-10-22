## What and why

<!-- What does this change, and why is it needed? Link the issue if there is one. -->

## Checklist

- [ ] All checks from [CONTRIBUTING.md](../CONTRIBUTING.md) pass locally (ruff, mypy,
      pytest, bandit, pip-audit, zizmor, gitleaks).
- [ ] Tests added or updated, including negative cases for anything security-relevant.
- [ ] No secrets, personal paths or real credentials in code, fixtures or output.
- [ ] Untrusted input (configs, server responses, LLM output) is size-bounded and
      validated; nothing from it reaches a shell, `eval` or a file path unchecked.
- [ ] New dependencies are justified, verified on PyPI and added to the lockfiles.
- [ ] Docs and CHANGELOG updated if behavior changed.

## Security notes

<!-- Trust boundaries touched, assumptions made, anything that needs a maintainer
decision. Write "None" if the change has no security impact. -->
