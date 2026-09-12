# AgentMortem — sample agent configurations

- `bad-agent/` — an intentionally over-permissive agent setup:
  `Bash(*)` allowlist, `dangerouslySkipPermissions`, secrets in `env`,
  an insecure/raw-IP/suspicious MCP endpoint, and an `AGENTS.md` with
  injection-style instructions. Expect multiple findings:

  ```bash
  agentmortem scan bad-agent
  ```

- `good-agent/` — a scoped, well-formed setup. Should produce **zero**
  findings:

  ```bash
  agentmortem scan good-agent   # → "No findings."
  ```

All tokens in these fixtures are synthetic. Never add real secrets here.
