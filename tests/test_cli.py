from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from conftest import BAD_CONFIG, BENIGN, GOOD_CONFIG, MALICIOUS, ROOT


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "agentmortem", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT,
        timeout=120,
    )


def test_version() -> None:
    result = run_cli("--version")
    assert result.returncode == 0
    assert "agentmortem 0.1.0" in result.stdout


def test_malicious_transcript_fails_medium_gate() -> None:
    result = run_cli("scan", str(MALICIOUS), "--format", "json", "--fail-on", "medium")
    assert result.returncode == 1
    report = json.loads(result.stdout)
    rule_ids = {f["rule_id"] for f in report["findings"]}
    assert "AM-3001" in rule_ids
    assert report["summary"]["max_severity"] == "critical"


def test_benign_transcript_passes() -> None:
    result = run_cli("scan", str(BENIGN))
    assert result.returncode == 0
    assert "No findings" in result.stdout


def test_bad_config_dir_fails() -> None:
    result = run_cli("scan", str(BAD_CONFIG))
    assert result.returncode == 1
    assert "AM-4002" in result.stdout


def test_good_config_dir_passes() -> None:
    result = run_cli("scan", str(GOOD_CONFIG))
    assert result.returncode == 0
    assert "No findings" in result.stdout


def test_fail_on_off_never_fails() -> None:
    result = run_cli("scan", str(MALICIOUS), "--fail-on", "off")
    assert result.returncode == 0


def test_fail_on_critical_gate() -> None:
    result = run_cli("scan", str(MALICIOUS), "--fail-on", "critical")
    assert result.returncode == 1
    result = run_cli("scan", str(BENIGN), "--fail-on", "critical")
    assert result.returncode == 0


def test_sarif_output_valid() -> None:
    result = run_cli("scan", str(MALICIOUS), "--format", "sarif")
    assert result.returncode == 1
    doc = json.loads(result.stdout)
    assert doc["version"] == "2.1.0"
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "AgentMortem"
    assert driver["rules"]
    results = doc["runs"][0]["results"]
    assert results
    levels = {r["level"] for r in results}
    assert levels <= {"none", "note", "warning", "error"}
    assert all("ruleId" in r and "locations" in r for r in results)


def test_json_output_written_to_file(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    result = run_cli("scan", str(MALICIOUS), "--format", "json", "-o", str(out))
    assert result.returncode == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["tool"] == "agentmortem"
    assert data["findings"]


def test_nonexistent_path_errors() -> None:
    result = run_cli("scan", str(Path("/definitely/not/here.jsonl")))
    assert result.returncode == 2
    assert "not found" in result.stderr


def test_transcript_dir_scan() -> None:
    result = run_cli(
        "scan",
        str(ROOT / "examples" / "transcripts"),
        "--mode", "transcript",
        "--format", "json",
    )
    # Contains the malicious fixture, so the medium gate fails.
    assert result.returncode == 1
    data = json.loads(result.stdout)
    assert data["stats"]["files"] == 2


def test_missing_mode_transcript_on_config_errors_gracefully() -> None:
    result = run_cli("scan", str(BAD_CONFIG / "AGENTS.md"), "--mode", "transcript")
    assert result.returncode == 2
    assert "error" in result.stderr.lower()
