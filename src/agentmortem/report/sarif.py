"""SARIF 2.1.0 report output (GitHub code scanning compatible)."""

from __future__ import annotations

import json

from agentmortem.models import Finding, Report, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_INFORMATION_URI = "https://github.com/something995/New-idea"


def render_sarif(report: Report) -> str:
    rules: dict[str, Finding] = {}
    for f in report.findings:
        rules.setdefault(f.rule_id, f)

    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
        "Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentMortem",
                        "version": report.version,
                        "informationUri": _INFORMATION_URI,
                        "rules": [
                            {
                                "id": f.rule_id,
                                "name": f"agentmortem.{f.rule_id.lower()}",
                                "shortDescription": {"text": f.title},
                                "fullDescription": {"text": f.message or f.title},
                                "help": {"text": f.recommendation or ""},
                                "defaultConfiguration": {
                                    "level": _SARIF_LEVEL[f.severity]
                                },
                                "properties": {"category": f.category},
                            }
                            for f in rules.values()
                        ],
                    }
                },
                "results": [
                    _sarif_result(f) for f in report.findings
                ],
            }
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _sarif_result(f: Finding) -> dict:
    result: dict = {
        "ruleId": f.rule_id,
        "level": _SARIF_LEVEL[f.severity],
        "message": {
            "text": f"{f.title}: {f.message}"
            if f.message and f.message != f.title
            else f.title
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location.uri},
                    "region": {
                        "startLine": f.location.line or 1,
                        "startColumn": 1,
                    },
                }
            }
        ],
    }
    if f.location.message_index is not None:
        result["properties"] = {"messageIndex": f.location.message_index}
    if f.snippet:
        result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
            "text": f.snippet
        }
    return result
