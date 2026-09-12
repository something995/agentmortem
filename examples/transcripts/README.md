# AgentMortem — sample transcripts

- `malicious_session.jsonl` — Claude-Code-style JSONL session containing an
  instruction override, leaked credentials (synthetic), and a complete
  read→send exfiltration chain to a public webhook. Use it to demo findings:

  ```bash
  agentmortem scan malicious_session.jsonl
  ```

- `benign_session.jsonl` — an ordinary development session. Should produce
  **zero** findings:

  ```bash
  agentmortem scan benign_session.jsonl   # → "No findings."
  ```

All credentials in these fixtures are synthetic or public documentation
values (e.g. AWS's `AKIAIOSFODNN7EXAMPLE`). Never add real secrets here.
