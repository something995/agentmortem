"""Transcript scanning engine."""

from __future__ import annotations

from pathlib import Path

from agentmortem.capability.analyzer import analyze_capabilities
from agentmortem.models import Finding, Location
from agentmortem.rules import TEXT_RULES
from agentmortem.secrets.detector import detect_secrets
from agentmortem.transcript.parsers import Message, parse_transcript
from agentmortem.util import make_snippet, short


def scan_transcript(messages: list[Message], uri: str) -> tuple[list[Finding], dict]:
    """Scan normalized transcript messages.

    Returns ``(findings, stats)``.
    """
    findings: list[Finding] = []
    spans_by_index: dict[int, list[tuple[int, int, str]]] = {}

    for msg in messages:
        text = msg.scan_text()
        loc = Location(uri=uri, line=msg.line, message_index=msg.index)

        secret_findings, spans = detect_secrets(text, loc)
        spans_by_index[msg.index] = spans
        findings.extend(secret_findings)

        for rule in TEXT_RULES:
            if rule.roles and msg.role not in rule.roles:
                continue
            for m in rule.pattern.finditer(text):
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        category=rule.category,
                        severity=rule.severity,
                        title=rule.title,
                        message=f"{rule.description} (match: \"{short(m.group(0))}\")",
                        location=loc,
                        snippet=make_snippet(text, m.start(), m.end(), spans),
                        recommendation=rule.recommendation,
                    )
                )

    findings.extend(analyze_capabilities(messages, uri, spans_by_index))

    findings.sort(
        key=lambda f: (
            f.location.message_index if f.location.message_index is not None else -1,
            f.location.line if f.location.line is not None else -1,
            -int(f.severity),
            f.rule_id,
        )
    )
    stats = {"messages": len(messages), "files": 1}
    return findings, stats


def scan_transcript_file(path: Path) -> tuple[list[Finding], dict]:
    """Convenience wrapper that parses *path* first."""
    messages = parse_transcript(path)
    findings, stats = scan_transcript(messages, str(path))
    return findings, stats
