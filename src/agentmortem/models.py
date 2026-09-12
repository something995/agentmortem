"""Core data models shared across AgentHound."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Finding severity, ordered from least to most severe."""

    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Location:
    """Where a finding occurred."""

    uri: str
    line: int | None = None
    message_index: int | None = None

    @property
    def display(self) -> str:
        parts = [self.uri]
        if self.line is not None:
            parts.append(f"line {self.line}")
        if self.message_index is not None:
            parts.append(f"message #{self.message_index}")
        return " · ".join(parts)


@dataclass
class Finding:
    """A single security finding."""

    rule_id: str
    category: str
    severity: Severity
    title: str
    message: str
    location: Location
    snippet: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity.label,
            "title": self.title,
            "message": self.message,
            "location": {
                "uri": self.location.uri,
                "line": self.location.line,
                "message_index": self.location.message_index,
            },
            "snippet": self.snippet,
            "recommendation": self.recommendation,
        }


@dataclass
class Report:
    """The result of scanning a target."""

    tool: str = "agentmortem"
    version: str = "0.1.0"
    target: str = ""
    mode: str = ""
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def count_by_severity(self) -> dict[str, int]:
        out = {s.label: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "version": self.version,
            "target": self.target,
            "mode": self.mode,
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": self.count_by_severity(),
                "max_severity": self.max_severity.label if self.max_severity else None,
            },
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.findings],
        }
