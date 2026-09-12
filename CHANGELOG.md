# Changelog

All notable changes to AgentMortem are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-12

### Added

- Initial release.
- Transcript scanning (JSONL event logs and JSON chat logs):
  - prompt-injection patterns (AM-1001 … AM-1008)
  - secret detection with redaction (AM-2001 … AM-2012)
  - capability analysis incl. read→send exfiltration chains (AM-3001 … AM-3007)
- Agent config auditing: allowlists, MCP server configs, instruction files
  (AM-4001 … AM-4009)
- CLI: `agentmortem scan` with `text` / `json` / `sarif` output,
  `--fail-on` severity gate, `--mode` auto-detection
- Python API: `parse_transcript`, `scan_transcript`, `audit_config`
- SARIF 2.1.0 output for GitHub code scanning
- Bundled GitHub Action (`.github/action.yml`) and self-hosting CI workflow
- 90+ tests; zero runtime dependencies
