from __future__ import annotations

from pathlib import Path

from conftest import BAD_CONFIG, GOOD_CONFIG

from agentmortem.config.auditor import audit_config
from agentmortem.models import Severity


def ids_of(findings) -> set[str]:
    return {f.rule_id for f in findings}


def test_bad_config_dir_flagged() -> None:
    findings = audit_config(BAD_CONFIG)
    ids = ids_of(findings)
    assert "AM-4001" in ids  # Bash(*)
    assert "AM-4002" in ids  # dangerouslySkipPermissions
    assert "AM-4003" in ids  # insecure MCP endpoints
    assert "AM-4004" in ids  # secrets in env
    assert "AM-4005" in ids  # injection-like instruction text
    assert "AM-1008" in ids  # exfil host in instruction file
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_good_config_dir_clean() -> None:
    findings = audit_config(GOOD_CONFIG)
    assert findings == []


def test_settings_wildcard_bash_is_high() -> None:
    findings = audit_config(BAD_CONFIG / ".claude" / "settings.json")
    wildcard = [f for f in findings if f.rule_id == "AM-4001" and "Bash(*)" in f.snippet]
    assert wildcard
    assert wildcard[0].severity == Severity.HIGH


def test_skip_permissions_is_critical() -> None:
    findings = audit_config(BAD_CONFIG / ".claude" / "settings.json")
    skip = [f for f in findings if f.rule_id == "AM-4002"]
    assert skip
    assert skip[0].severity == Severity.CRITICAL


def test_mcp_http_endpoint_flagged() -> None:
    findings = audit_config(BAD_CONFIG / ".mcp.json")
    http = [f for f in findings if f.rule_id == "AM-4003" and "HTTP" in f.message]
    assert http
    suspicious = [f for f in findings if f.rule_id == "AM-4003" and f.severity == Severity.HIGH]
    assert suspicious  # webhook.site endpoint


def test_instruction_file_markers() -> None:
    findings = audit_config(BAD_CONFIG / "AGENTS.md")
    markers = [f for f in findings if f.rule_id == "AM-4005"]
    assert len(markers) >= 2  # override + concealment
    assert any(f.rule_id == "AM-1008" for f in findings)  # reqbin.com


def test_unparseable_settings_reported_as_info(tmp_path: Path) -> None:
    cfg = tmp_path / ".claude"
    cfg.mkdir()
    (cfg / "settings.json").write_text("{ this is not json", encoding="utf-8")
    findings = audit_config(cfg / "settings.json")
    assert any(f.rule_id == "AM-4009" and f.severity == Severity.INFO for f in findings)


def test_auto_approve_flagged(tmp_path: Path) -> None:
    cfg = tmp_path / ".claude"
    cfg.mkdir()
    (cfg / "settings.json").write_text('{"autoApprove": true}', encoding="utf-8")
    findings = audit_config(cfg / "settings.json")
    assert any(f.rule_id == "AM-4006" for f in findings)


def test_unknown_generic_file_gets_secret_scan(tmp_path: Path) -> None:
    f = tmp_path / "notes.txt"
    f.write_text("my key: AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    findings = audit_config(f)
    assert any(f2.rule_id == "AM-2001" for f2 in findings)


def test_single_file_mode_matches_dir_mode_for_mcp() -> None:
    single = audit_config(BAD_CONFIG / ".mcp.json")
    full = [
        f
        for f in audit_config(BAD_CONFIG)
        if f.location.uri.endswith(".mcp.json")
    ]
    assert ids_of(single) == ids_of(full)
