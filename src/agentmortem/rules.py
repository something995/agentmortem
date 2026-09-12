"""Static rule definitions: prompt-injection patterns (text-level).

Rule IDs:
    AM-10xx  prompt-injection / malicious-content patterns
    AM-20xx  secret leakage (see ``secrets.detector``)
    AM-30xx  capability / shell risk (see ``capability.analyzer``)
    AM-40xx  agent configuration risk (see ``config.auditor``)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from agentmortem.data import EXFIL_HOST_RE
from agentmortem.models import Severity


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    severity: Severity
    title: str
    description: str
    pattern: re.Pattern[str]
    recommendation: str = ""
    roles: tuple[str, ...] | None = None  # None = scan every role


INJECTION_RULES: tuple[Rule, ...] = (
    Rule(
        "AM-1001",
        "injection",
        Severity.MEDIUM,
        "Instruction override attempt",
        "Text tries to make the model discard its system/developer instructions.",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget|override|discard|abandon|stop\s+following)"
            r"\s+(?:all\s+|any\s+|your\s+|the\s+)?(?:previous|prior|above|earlier|initial"
            r"|original|system|developer|hard-?coded)\s+(?:and\s+)?(?:instructions?|prompts?"
            r"|rules?|directives?|guidelines?|constraints?|formatting|output)\b"
        ),
        "Review the surrounding conversation. If the agent acted on these "
        "instructions, treat the session as compromised and rotate credentials.",
    ),
    Rule(
        "AM-1002",
        "injection",
        Severity.MEDIUM,
        "Role-play / jailbreak attempt",
        "Text tries to switch the model into an unrestricted persona or mode.",
        re.compile(
            r"(?i)(?:\byou\s+are\s+now\s+(?:in\s+)?(?:daniel|dan|jailbreak|developer|debug"
            r"|admin|superuser|god)\s+mode\b"
            r"|\b(?:pretend|imagine)\s+(?:you\s+)?(?:are\s+)?(?:an?\s+)?(?:AI\s+|assistant\s+)?"
            r"(?:that\s+|with\s+|have\s+|got\s+)?(?:no|zero|without\s+any|not\s+any)\s+(?:rules?"
            r"|restrictions?|limitations?|safety\s+(?:rules?|filters?|measures?)|filters?"
            r"|ethics|guidelines)\b"
            r"|\bdo\s+anything\s+now\b"
            r"|\b(?:enable|activate|unlock|turn\s+on)\s+(?:developer|debug|jailbreak|admin"
            r"|god|sudo)\s+mode\b"
            r"|\bDAN\s+mode\b)"
        ),
        "Confirm the model did not follow the persona switch. Jailbreak attempts "
        "inside tool output indicate an indirect-injection source.",
    ),
    Rule(
        "AM-1003",
        "injection",
        Severity.MEDIUM,
        "System prompt exfiltration attempt",
        "Text asks the model to reveal its system/developer prompt or instructions.",
        re.compile(
            r"(?i)(?:\b(?:reveal|print|show|display|repeat|recite|output|dump|send|leak"
            r"|extract|share)\s+(?:me\s+)?(?:your|the|its|their|full|entire|original|initial"
            r"|hidden|secret|system|developer)?\s*(?:system|developer|initial|original"
            r"|hidden|secret|base|core)?\s*(?:prompts?|instructions?)\b"
            r"|\bwhat\s+are\s+your\s+(?:system|initial|original|hidden|secret|full)\s+(?:prompt"
            r"|instructions)\b"
            r"|\b(?:your|the)\s+(?:system|initial|hidden)\s+(?:prompt|instructions)\s+(?:is|are"
            r"|was)\b)"
        ),
        "Check whether the model actually emitted its system prompt. Prompt "
        "disclosure is a common precursor to targeted attacks.",
    ),
    Rule(
        "AM-1004",
        "injection",
        Severity.MEDIUM,
        "Base64 payload smuggling",
        "Text carries an explicit base64-encoded payload, a common smuggling "
        "channel for hidden instructions.",
        re.compile(r"(?i)\bbase64\s*[:=]?\s*[A-Za-z0-9+/]{40,}={0,2}"),
        "Decode the payload and inspect its contents for hidden instructions or "
        "commands before trusting it.",
    ),
    Rule(
        "AM-1005",
        "injection",
        Severity.LOW,
        "Long encoded blob",
        "A long base64-like blob in user input may hide instructions or payloads.",
        re.compile(r"\b[A-Za-z0-9+/]{80,}={0,2}\b"),
        "Decode the blob and review its contents. Long unexplained encoded blobs "
        "in user or tool output are a weak exfil/smuggling signal.",
        roles=("user", "tool"),
    ),
    Rule(
        "AM-1006",
        "injection",
        Severity.MEDIUM,
        "Invisible Unicode characters",
        "Zero-width or bidirectional control characters were used to smuggle or "
        "obfuscate content (steganographic injection).",
        re.compile(
            "[\u200b\u200c\u200d\u2060\ufeff\u061c\u180e\u202a\u202b\u202c\u202d\u202e"
            "\u2066\u2067\u2068\u2069]"
        ),
        "Render the text with control characters made visible. Content hidden in "
        "invisible characters should not reach the model.",
    ),
    Rule(
        "AM-1007",
        "injection",
        Severity.MEDIUM,
        "Instruction hidden in HTML comment",
        "An HTML comment contains instruction-like text aimed at the model.",
        re.compile(
            r"(?is)<!--.{0,300}?(?:ignore|instruction|system\s+prompt|secret|hidden|do\s+not"
            r"|exfiltrate|send).{0,300}?-->"
        ),
        "Strip markup before it reaches the model. Instructions inside comments "
        "are invisible to humans but readable by LLMs.",
    ),
    Rule(
        "AM-1008",
        "injection",
        Severity.MEDIUM,
        "Data exfiltration destination",
        "A known exfiltration drop-point, C2, or public paste host appears in the "
        "conversation.",
        EXFIL_HOST_RE,
        "Verify whether data was actually sent to this endpoint. If so, treat "
        "any data in the session as leaked.",
    ),
)

#: Rules the transcript engine applies to every message's full scan text.
TEXT_RULES: tuple[Rule, ...] = INJECTION_RULES
