# Contributing to AgentMortem

Thanks for helping make agent sessions safer. AgentMortem is a small,
deterministic tool — keep it that way.

## Ground rules

- **No runtime dependencies.** The core promise is zero-dep, offline,
  stdlib-only. Pull requests that add runtime deps need a strong justification
  (dev-dependencies are fine).
- **Deterministic output.** No network calls, no randomness, no LLM inference.
- **Redaction is sacred.** Reports must never echo raw secret values.

## Setup

```bash
git clone https://github.com/something995/New-idea agentmortem
cd agentmortem
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Development loop

```bash
ruff check --fix src tests   # lint
pytest                       # test (90+ tests, <1s)
```

## Adding a rule

1. Add the rule to the right module (see [docs/rules.md](docs/rules.md) for
   the layout).
2. Add at least one positive test *and* a near-miss negative test in the
   matching `tests/test_*.py` file.
3. Update [docs/rules.md](docs/rules.md) and the rule table in `README.md` if
   the new rule changes the user-visible story.
4. Bump `CHANGELOG.md`.

## Reporting issues

- Bugs: use the bug report template; include a minimal transcript/config
  snippet (with real secrets replaced by dummies).
- Security issues: do **not** open a public issue — see
  [SECURITY.md](SECURITY.md).
- New rules / integrations: open a discussion or issue first so we can align
  on scope.

## Pull requests

- Small, focused PRs win.
- Tests must pass, lint must be clean.
- Squash-merge friendly commit messages: `rule: add AM-2013 for HuggingFace tokens`.
