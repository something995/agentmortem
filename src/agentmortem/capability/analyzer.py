"""Capability risk analysis for transcripts.

Detects dangerous *sequences* of tool usage — the read→send exfiltration
chain in particular — plus risky individual commands (pipe-to-shell,
destructive commands, credential access, privilege escalation, sensitive
writes, outbound exfil destinations).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from agentmortem.data import EXFIL_HOST_RE
from agentmortem.models import Finding, Location, Severity
from agentmortem.transcript.parsers import Message, ToolCall
from agentmortem.util import make_snippet

# ---------------------------------------------------------------------------
# Heuristics
# ---------------------------------------------------------------------------

SHELL_TOOL_NAMES = {
    "bash",
    "shell",
    "exec",
    "execute",
    "execute_command",
    "execute_code",
    "run_command",
    "terminal",
    "run",
    "code_execution",
    "shell_command",
    "system",
    "command",
    "process",
}

COMMAND_ARG_KEYS = ("command", "cmd", "script", "input", "code")

READ_TOOLS = {
    "read",
    "read_file",
    "view",
    "view_file",
    "open",
    "cat",
    "file_read",
    "fs_read",
    "show_file",
}

SEND_TOOL_NAMES = {
    "http_post",
    "http_request",
    "http",
    "web_request",
    "fetch",
    "upload",
    "api_call",
    "post",
}

SEND_TOOL_NAMES_WEAK = {"send", "send_message", "request"}

READ_CMD_RE = re.compile(r"\b(?:cat|less|more|head|tail|cp|rsync|tar)\b", re.IGNORECASE)

SENSITIVE_PATH_RE = re.compile(
    r"(?:"
    r"\.env(?:\.\w+)?"
    r"|\.aws/credentials"
    r"|\.aws/secret_access_key"
    r"|\.netrc"
    r"|\.pgpass"
    r"|id_(?:rsa|ed25519|ecdsa|dsa)(?:\.pub)?"
    r"|\.ssh/(?:id_\w+|authorized_keys|config)"
    r"|/etc/shadow"
    r"|/etc/sudoers"
    r"|credentials\.json"
    r"|service[-_]\w+\.json"
    r"|\.npmrc"
    r"|\.docker/config\.json"
    r"|\b\.gnupg"
    r")(?![\w.])",
    re.IGNORECASE,
)

CORE_CREDENTIAL_RE = re.compile(
    r"(?:"
    r"\.env(?:\.\w+)?"
    r"|\.aws/credentials"
    r"|id_(?:rsa|ed25519|ecdsa)"
    r"|\.ssh/(?:id_\w+|authorized_keys)"
    r"|/etc/shadow"
    r"|credentials\.json"
    r"|\b\.gnupg"
    r")",
    re.IGNORECASE,
)

PIPE_TO_SHELL_RE = re.compile(
    r"(?i)\b(?:curl|wget)\b[^\n|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"
)

DESTRUCTIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+(?:/|~|\$HOME)(?:/\s*)?(?:\s|$)"),
    re.compile(r"\bmkfs(?:\.\w+)?\b"),
    re.compile(r"\bdd\s+if=\S+\s+of=/dev/"),
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
    re.compile(r"\bshred\s+(?:-\w+\s+)*\S*/dev/"),
)

PRIV_ESC_RE = re.compile(r"(?i)\bsudo\b|\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx)\b")

WRITE_VERB_RE = re.compile(r"(?i)\b(?:tee|cp|mv|echo|printf)\b|>>?")

SENSITIVE_TARGET_RE = re.compile(
    r"(?i)(?:/etc/(?:passwd|shadow|sudoers|crontab|cron\.d/[\w.-]+)"
    r"|/var/spool/cron/[\w.-]+"
    r"|\.ssh/authorized_keys"
    r"|/etc/ld\.so\.preload)"
)

SEND_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"(?i)\bcurl\b[^\n|;&]*"
        r"(?:\s-d\b|\s--data\b|\s--data-[a-z]+\b|\s-F\b|\s--form\b|\s-T\b"
        r"|\s--upload-file\b|\s-X\s*(?:POST|PUT)\b)"
    ),
    re.compile(r"(?i)\bcurl\b[^\n|;&]*(?:\$\(|`)"),
    re.compile(r"(?i)\bwget\b[^\n|;&]*--post"),
    re.compile(r"(?i)\brequests\.(?:post|put)\s*\("),
    re.compile(r"(?i)\bhttpx\.(?:post|put)\s*\("),
    re.compile(r"(?i)\burlopen\s*\([^)]*method\s*=\s*['\"](?:POST|PUT)['\"]"),
    re.compile(
        r"(?i)\bfetch\s*\(\s*['\"][^'\"]*['\"]\s*,\s*\{[^}]*\bmethod\s*:\s*['\"](?:POST|PUT)['\"]"
    ),
    re.compile(r"(?i)\bsession\.post\s*\("),
)

CHAIN_WINDOW = 25  # messages between a sensitive read and a send


@dataclass(frozen=True)
class _PatternRule:
    rule_id: str
    severity: Severity
    title: str
    description: str
    recommendation: str
    pattern: re.Pattern[str]


_SHELL_PATTERN_RULES: tuple[_PatternRule, ...] = (
    _PatternRule(
        "AM-3002",
        Severity.HIGH,
        "Pipe-to-shell execution",
        "A downloaded payload is piped directly into a shell interpreter.",
        "Prefer downloading, verifying (checksum/signature), and then running. "
        "Pipe-to-shell is the most common malware delivery primitive.",
        PIPE_TO_SHELL_RE,
    ),
    _PatternRule(
        "AM-3003",
        Severity.CRITICAL,
        "Destructive command",
        "A command was detected that can irreversibly destroy data or the host.",
        "Verify this was intended. If it came from tool output or a user request "
        "you do not recognize, treat the session as compromised.",
        DESTRUCTIVE_PATTERNS[0],  # placeholder, handled specially below
    ),
    _PatternRule(
        "AM-3005",
        Severity.LOW,
        "Privilege escalation / broad permissions",
        "The command escalates privileges or widens file permissions.",
        "Context-dependent: fine in a sandbox, concerning in a shared or "
        "production environment.",
        PRIV_ESC_RE,
    ),
    _PatternRule(
        "AM-3007",
        Severity.MEDIUM,
        "Outbound exfiltration destination",
        "A command or tool call references a known exfiltration drop-point, C2, "
        "or public paste host.",
        "Verify whether data was actually transmitted to this endpoint.",
        EXFIL_HOST_RE,
    ),
)


def _commands_for(tc: ToolCall) -> list[str]:
    """Extract command-like strings from a tool call."""
    out: list[str] = []
    for key in COMMAND_ARG_KEYS:
        value = tc.args.get(key)
        if isinstance(value, str) and value.strip():
            out.append(value)
    if not out and tc.name.lower() in SHELL_TOOL_NAMES:
        out.append(tc.text())
    # de-duplicate identical strings (e.g. `command` and `input` aliases)
    seen: set[str] = set()
    deduped: list[str] = []
    for cmd in out:
        if cmd not in seen:
            seen.add(cmd)
            deduped.append(cmd)
    return deduped


def _is_sensitive_read(tc: ToolCall) -> bool:
    if tc.name.lower() in READ_TOOLS and SENSITIVE_PATH_RE.search(tc.text()):
        return True
    for cmd in _commands_for(tc):
        if READ_CMD_RE.search(cmd) and SENSITIVE_PATH_RE.search(cmd):
            return True
    return False


def _is_send(tc: ToolCall) -> bool:
    name = tc.name.lower()
    if name in SEND_TOOL_NAMES:
        return True
    if name in SEND_TOOL_NAMES_WEAK:
        if re.search(r"\burl\b", tc.text(), re.IGNORECASE) or re.search(
            r"https?://", tc.text(), re.IGNORECASE
        ):
            return True
        return False
    for cmd in _commands_for(tc):
        if any(p.search(cmd) for p in SEND_PATTERNS):
            return True
    return False


def _shell_rule_findings(
    text: str,
    loc: Location,
    redactions: list[tuple[int, int, str]],
    seen: set[tuple[str, int | None]],
) -> list[Finding]:
    """Run all shell/capability rules against a single text (prose or command)."""
    out: list[Finding] = []

    def add(rule_id: str, severity: Severity, title: str, description: str,
            recommendation: str, start: int, end: int, source: str) -> None:
        if (rule_id, loc.message_index) in seen:
            return
        seen.add((rule_id, loc.message_index))
        out.append(
            Finding(
                rule_id=rule_id,
                category="capability",
                severity=severity,
                title=title,
                message=description,
                location=loc,
                snippet=make_snippet(source, start, end, redactions),
                recommendation=recommendation,
            )
        )

    for rule in _SHELL_PATTERN_RULES:
        if rule.rule_id == "AM-3003":
            for pat in DESTRUCTIVE_PATTERNS:
                m = pat.search(text)
                if m:
                    add(
                        rule.rule_id,
                        rule.severity,
                        rule.title,
                        rule.description,
                        rule.recommendation,
                        m.start(),
                        m.end(),
                        text,
                    )
                    break
            continue
        m = rule.pattern.search(text)
        if m:
            add(
                rule.rule_id,
                rule.severity,
                rule.title,
                rule.description,
                rule.recommendation,
                m.start(),
                m.end(),
                text,
            )

    m_path = SENSITIVE_PATH_RE.search(text)
    if m_path and READ_CMD_RE.search(text):
        add(
            "AM-3004",
            Severity.MEDIUM,
            "Credential file access",
            "A command reads or copies a credential-bearing file.",
            "Legitimate in some workflows, but combined with outbound network "
            "calls it becomes an exfiltration chain. Review the rest of the "
            "session.",
            m_path.start(),
            m_path.end(),
            text,
        )

    m_target = SENSITIVE_TARGET_RE.search(text)
    if m_target and WRITE_VERB_RE.search(text):
        add(
            "AM-3006",
            Severity.HIGH,
            "Write to sensitive system path",
            "A command writes to a sensitive system location (password files, "
            "cron, SSH keys, preload libraries).",
            "Verify the write was intended. Unauthorized writes here persist "
            "across sessions and reboots.",
            m_target.start(),
            m_target.end(),
            text,
        )

    return out


def analyze_capabilities(
    messages: list[Message],
    uri: str,
    spans_by_index: dict[int, list[tuple[int, int, str]]] | None = None,
) -> list[Finding]:
    """Analyze tool-call sequences for capability risks."""
    findings: list[Finding] = []
    seen: set[tuple[str, int | None]] = set()
    reads: list[tuple[int, ToolCall]] = []
    sends: list[tuple[int, ToolCall]] = []
    spans_by_index = spans_by_index or {}

    for i, msg in enumerate(messages):
        loc = Location(uri=uri, line=msg.line, message_index=i)
        redactions = spans_by_index.get(i, [])

        if msg.text.strip():
            findings.extend(_shell_rule_findings(msg.text, loc, redactions, seen))

        for tc in msg.tool_calls:
            for cmd in _commands_for(tc):
                findings.extend(_shell_rule_findings(cmd, loc, redactions, seen))

            m = EXFIL_HOST_RE.search(tc.text())
            if m and ("AM-3007", i) not in seen:
                seen.add(("AM-3007", i))
                findings.append(
                    Finding(
                        "AM-3007",
                        "capability",
                        Severity.MEDIUM,
                        "Outbound exfiltration destination",
                        f"Tool call {tc.name!r} references a known exfiltration "
                        "drop-point, C2, or public paste host.",
                        loc,
                        make_snippet(tc.text(), m.start(), m.end(), redactions),
                        "Verify whether data was actually transmitted to this endpoint.",
                    )
                )

            if _is_sensitive_read(tc):
                reads.append((i, tc))
            if _is_send(tc):
                sends.append((i, tc))

    # Exfiltration chain: sensitive read followed (within window) by a send.
    for send_idx, send_tc in sends:
        prior = [r for r in reads if r[0] < send_idx and send_idx - r[0] <= CHAIN_WINDOW]
        if not prior:
            continue
        read_idx, _read_tc = prior[-1]
        dest_text = send_tc.text() + " " + " ".join(_commands_for(send_tc))
        redactions = spans_by_index.get(send_idx, [])
        cmd_text = " ".join(_commands_for(send_tc)) or send_tc.text()
        m = re.search(r"\S+", cmd_text)
        start = m.start() if m else 0
        end = min(len(cmd_text), (m.end() if m else 0) + 80)
        if EXFIL_HOST_RE.search(dest_text):
            severity = Severity.CRITICAL
            description = (
                f"Sensitive file read in message #{read_idx} was followed by "
                f"outbound transmission to a known exfiltration endpoint in "
                f"message #{send_idx}."
            )
        else:
            severity = Severity.HIGH
            description = (
                f"Sensitive file read in message #{read_idx} was followed by "
                f"outbound transmission in message #{send_idx} — potential "
                f"data exfiltration chain."
            )
        findings.append(
            Finding(
                rule_id="AM-3001",
                category="capability",
                severity=severity,
                title="Data exfiltration chain",
                message=description,
                location=Location(uri=uri, line=messages[send_idx].line, message_index=send_idx),
                snippet=make_snippet(cmd_text, start, end, redactions),
                recommendation=(
                    "Break the read→send path: least-privilege tool access, "
                    "egress allowlists, and human approval for outbound "
                    "transmissions after sensitive reads."
                ),
            )
        )

    return findings
