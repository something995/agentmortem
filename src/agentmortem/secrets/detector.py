"""Detect credentials and high-entropy tokens in text.

All patterns are deterministic regex/entropy heuristics — no models, no
network. Matched secret *values* are never echoed into reports verbatim:
snippets are redacted with ``[REDACTED-<TYPE>]`` placeholders.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from agentmortem.models import Finding, Location, Severity

# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    secret_type: str
    severity: Severity
    title: str
    pattern: re.Pattern[str]
    recommendation: str
    group: int = 0  # capture group holding the secret value (0 = whole match)


SECRET_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "AM-2001",
        "aws-access-key-id",
        Severity.HIGH,
        "AWS access key ID",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "Rotate the access key in IAM, audit CloudTrail for usage, and purge the "
        "value from the transcript and any log stores that captured it.",
    ),
    SecretRule(
        "AM-2002",
        "github-token",
        Severity.HIGH,
        "GitHub token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,})\b"),
        "Revoke the token in GitHub settings, review recent repository activity, "
        "and rotate any secrets it could reach.",
    ),
    SecretRule(
        "AM-2003",
        "openai-api-key",
        Severity.HIGH,
        "OpenAI API key",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
        "Revoke the key in the OpenAI dashboard and check usage/billing for "
        "unauthorized consumption.",
    ),
    SecretRule(
        "AM-2004",
        "private-key-block",
        Severity.CRITICAL,
        "PEM private key block",
        re.compile(r"-----BEGIN[ A-Z0-9]*PRIVATE KEY-----"),
        "Treat the key as compromised: rotate the keypair immediately, check for "
        "unauthorized use (commits, SSH sessions, API calls), and remove the key "
        "from the transcript and all copies.",
    ),
    SecretRule(
        "AM-2005",
        "jwt",
        Severity.MEDIUM,
        "JSON Web Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"),
        "Inspect the token's claims. If it grants access, revoke/rotate the "
        "underlying session or signing key.",
    ),
    SecretRule(
        "AM-2006",
        "connection-string",
        Severity.HIGH,
        "Database connection string with embedded credentials",
        re.compile(
            r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql|sqlserver)"
            r"://[^\s:@/]+:[^\s@/]+@[^\s]+"
        ),
        "Rotate the database credentials, restrict network access to the "
        "database, and move the connection string to a secret manager.",
    ),
    SecretRule(
        "AM-2007",
        "slack-token",
        Severity.HIGH,
        "Slack token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "Revoke the token in the Slack app dashboard and audit the app's "
        "permission usage.",
    ),
    SecretRule(
        "AM-2008",
        "telegram-bot-token",
        Severity.HIGH,
        "Telegram bot token",
        re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
        "Revoke the bot token via BotFather and audit messages sent by the bot.",
    ),
    SecretRule(
        "AM-2009",
        "google-api-key",
        Severity.HIGH,
        "Google API key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "Restrict or rotate the key in Google Cloud Console and review API usage "
        "billing.",
    ),
    SecretRule(
        "AM-2010",
        "stripe-key",
        Severity.HIGH,
        "Stripe API key",
        re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b"),
        "Roll the key in the Stripe dashboard. For live keys, treat all "
        "transactions in the exposure window as at risk.",
    ),
    SecretRule(
        "AM-2011",
        "credential-assignment",
        Severity.MEDIUM,
        "Credential-looking value in an assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|apikey|client[_-]?secret|access[_-]?token|auth[_-]?token"
            r"|private[_-]?key|secret|password|passwd)\b\s*[:=]\s*['\"]?"
            r"([A-Za-z0-9+/=_\-]{12,})"
        ),
        group=1,
        recommendation=(
            "Verify whether the value is a real credential. If so, rotate it and "
            "stop embedding credentials in prompts, tool output, or logs."
        ),
    ),
)

# ---------------------------------------------------------------------------
# High-entropy fallback
# ---------------------------------------------------------------------------

GENERIC_TOKEN_RE = re.compile(r"[A-Za-z0-9+=_-]{28,}")
_HEX_DIGEST_RE = re.compile(r"[0-9a-fA-F]{40,}")
_ENTROPY_THRESHOLD = 4.3
_MAX_TOKEN_LEN = 200


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _overlaps(spans: list[tuple[int, int]], start: int, end: int) -> bool:
    return any(start < e and end > s for s, e in spans)


def redact_spans(text: str, spans: list[tuple[int, int, str]]) -> str:
    """Replace *spans* (absolute offsets) with ``[REDACTED-<TYPE>]`` markers."""
    out: list[str] = []
    last = 0
    for start, end, label in sorted(spans):
        if start < last:
            continue
        out.append(text[last:start])
        out.append(f"[REDACTED-{label.upper()}]")
        last = end
    out.append(text[last:])
    return "".join(out)


def _context_snippet(text: str, start: int, end: int, spans: list[tuple[int, int, str]]) -> str:
    a = max(0, start - 60)
    b = min(len(text), end + 60)
    # Redact on the raw window first: offsets refer to the original text, and
    # flattening newlines beforehand would shift every later span.
    local = [
        (max(s, a) - a, min(e, b) - a, t)
        for s, e, t in spans
        if e > a and s < b
    ]
    chunk = redact_spans(text[a:b], local)
    chunk = chunk.replace("\n", "\\n").replace("\t", "\\t")
    if len(chunk) > 180:
        chunk = chunk[:177] + "..."
    return chunk


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_secrets(text: str, loc: Location) -> tuple[list[Finding], list[tuple[int, int, str]]]:
    """Scan *text* for secrets.

    Returns ``(findings, spans)`` where ``spans`` are absolute
    ``(start, end, type)`` offsets of every detected secret. Callers use the
    spans to redact context snippets from *other* findings on the same text.
    """
    hits: list[tuple[int, int, str, SecretRule | None]] = []
    for rule in SECRET_RULES:
        for m in rule.pattern.finditer(text):
            if rule.group:
                start, end = m.start(rule.group), m.end(rule.group)
            else:
                start, end = m.start(), m.end()
            if end <= start or _overlaps([h[:2] for h in hits], start, end):
                continue
            hits.append((start, end, rule.secret_type, rule))

    for m in GENERIC_TOKEN_RE.finditer(text):
        token = m.group(0)
        if len(token) > _MAX_TOKEN_LEN or "/" in token:
            continue
        if not (re.search(r"\d", token) and re.search(r"[A-Za-z]", token)):
            continue
        if _HEX_DIGEST_RE.fullmatch(token):
            continue
        if shannon_entropy(token) < _ENTROPY_THRESHOLD:
            continue
        if _overlaps([h[:2] for h in hits], m.start(), m.end()):
            continue
        hits.append((m.start(), m.end(), "high-entropy-token", None))

    spans = [(start, end, sec_type) for start, end, sec_type, _ in hits]
    findings: list[Finding] = []
    for start, end, sec_type, rule in sorted(hits):
        if rule is not None:
            severity, rule_id, title, recommendation = (
                rule.severity,
                rule.rule_id,
                rule.title,
                rule.recommendation,
            )
        else:
            severity, rule_id = Severity.LOW, "AM-2012"
            title = "Possible high-entropy secret"
            recommendation = (
                "If this value is a credential, rotate it and move it to a secret "
                "manager. Low-entropy noise is expected in some corpora — treat as "
                "low confidence."
            )
        findings.append(
            Finding(
                rule_id=rule_id,
                category="secret",
                severity=severity,
                title=title,
                message=f"Potential {sec_type} detected in content.",
                location=loc,
                snippet=_context_snippet(text, start, end, spans),
                recommendation=recommendation,
            )
        )
    return findings, spans


def detect_secrets_in_file(path_str: str, read_lines: list[str]) -> list[Finding]:
    """Line-oriented secret scan for config files (accurate line numbers)."""
    findings: list[Finding] = []
    for lineno, line in enumerate(read_lines, start=1):
        line_findings, _ = detect_secrets(line, Location(uri=path_str, line=lineno))
        findings.extend(line_findings)
    return findings
