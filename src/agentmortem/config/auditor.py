"""Agent configuration auditing (allowlists, MCP configs, instruction files)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agentmortem.capability.analyzer import PIPE_TO_SHELL_RE
from agentmortem.data import EXFIL_HOST_RE
from agentmortem.models import Finding, Location, Severity
from agentmortem.secrets.detector import detect_secrets, detect_secrets_in_file

INSTRUCTION_NAMES = {
    "agents.md",
    "claude.md",
    ".cursorrules",
    ".windsurfrules",
    "gemini.md",
    "copilot-instructions.md",
}

MCP_NAMES = {".mcp.json", "mcp.json", "claude_desktop_config.json"}

SETTINGS_NAMES = {"settings.json", "settings.local.json"}

AUTO_APPROVE_KEYS = ("autoApprove", "auto_approve", "alwaysAllow", "enableAllTools", "yoloMode")

_WILDCARD_TOOL_RE = re.compile(r"^(\w+)\(\*\)$")
_BROAD_PREFIX_RE = re.compile(
    r"^Bash\((?:curl|wget|nc|ssh|scp|python\d?|node|bash|sh)\b.*\*$"
)

_INSTRUCTION_MARKERS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction-override",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|your\s+)?"
            r"(?:previous|prior|above|earlier|initial|original|system)\s+"
            r"(?:and\s+)?(?:instructions?|prompts?|rules?|directives?)"
        ),
    ),
    (
        "credential-exfil-instruction",
        re.compile(
            r"(?i)\b(?:exfiltrate|send|post|upload|forward)\b.{0,60}"
            r"\b(?:credentials?|secrets?|\.env|api\s*keys?|tokens?|keys?)\b"
        ),
    ),
    (
        "concealment-instruction",
        re.compile(
            r"(?i)\b(?:do\s+not|never|don't)\s+(?:tell|inform|notify|mention|reveal)"
            r".{0,40}\b(?:user|human|owner)\b"
        ),
    ),
    (
        "auto-execution-instruction",
        re.compile(
            r"(?i)\balways\s+(?:run|execute|perform)\b.{0,40}\bwithout\s+(?:asking|confirmation|user)"
        ),
    ),
    (
        "security-bypass-instruction",
        re.compile(
            r"(?i)\b(?:disable|bypass|turn\s+off|skip)\s+(?:security|telemetry|safety"
            r"|guards?|permissions?|verification)\b"
        ),
    ),
)


def _classify(name: str, path: Path) -> str:
    lower = name.lower()
    if lower in MCP_NAMES:
        return "mcp"
    if lower in SETTINGS_NAMES and ".claude" in {p.lower() for p in path.parts}:
        return "settings"
    if lower in INSTRUCTION_NAMES or (
        ".cursor" in {p.lower() for p in path.parts} and "rules" in {p.lower() for p in path.parts}
    ):
        return "instruction"
    return "generic"


#: Hidden directories we still descend into (agent config lives there).
_KNOWN_HIDDEN_DIRS = {".claude", ".cursor", ".github"}


def _discover(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(
            p.startswith(".") and p not in _KNOWN_HIDDEN_DIRS for p in rel_parts[:-1]
        ):
            continue
        files.append(path)
    keep: list[Path] = []
    for f in files:
        if _classify(f.name, f) != "generic" or f.suffix.lower() in {
            ".json",
            ".md",
            ".mdc",
            ".txt",
            ".toml",
            ".yaml",
            ".yml",
        }:
            keep.append(f)
    return keep


def _audit_settings(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    loc = Location(uri=str(path))
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        findings.append(
            Finding(
                "AM-4009",
                "config",
                Severity.INFO,
                "Config file could not be parsed",
                f"JSON parse error: {exc.msg} (line {exc.lineno}).",
                loc,
                "",
                "Fix the syntax so the allowlist can be audited.",
            )
        )
        findings.extend(detect_secrets_in_file(str(path), text.splitlines()))
        return findings

    if not isinstance(data, dict):
        return findings

    allow = data.get("permissions", {})
    if isinstance(allow, dict):
        entries = allow.get("allow", [])
        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, str):
                    continue
                line_no = _line_of(text, entry)
                eloc = Location(uri=str(path), line=line_no)
                if entry == "Bash(*)":
                    findings.append(
                        Finding(
                            "AM-4001",
                            "config",
                            Severity.HIGH,
                            "Unrestricted shell access granted",
                            "The allowlist contains Bash(*): the agent may run any shell "
                            "command without approval.",
                            eloc,
                            entry,
                            "Replace the wildcard with explicit command prefixes the "
                            "agent actually needs.",
                        )
                    )
                elif _WILDCARD_TOOL_RE.fullmatch(entry):
                    tool = _WILDCARD_TOOL_RE.fullmatch(entry).group(1)  # type: ignore[union-attr]
                    findings.append(
                        Finding(
                            "AM-4001",
                            "config",
                            Severity.MEDIUM,
                            "Wildcard tool allowlist",
                            f"Allowlist grants {tool}(*) — every {tool} operation is "
                            "pre-approved.",
                            eloc,
                            entry,
                            "Scope the allowlist to specific operations.",
                        )
                    )
                elif _BROAD_PREFIX_RE.match(entry):
                    findings.append(
                        Finding(
                            "AM-4001",
                            "config",
                            Severity.MEDIUM,
                            "Broad network/interpreter allowlist prefix",
                            f"Allowlist prefix {entry!r} can reach arbitrary URLs, hosts, "
                            "or scripts.",
                            eloc,
                            entry,
                            "Pin the prefix to the specific host or script the agent "
                            "needs.",
                        )
                    )

    if data.get("dangerouslySkipPermissions") is True or "--dangerously-skip-permissions" in text:
        line_no = _line_of(text, "dangerouslySkipPermissions") or _line_of(
            text, "dangerously-skip-permissions"
        )
        findings.append(
            Finding(
                "AM-4002",
                "config",
                Severity.CRITICAL,
                "All permission prompts disabled",
                "The agent is configured to skip permission confirmation entirely — "
                "any tool action (shell, file write, network) executes unattended.",
                Location(uri=str(path), line=line_no),
                "",
                "Remove the flag. Unattended full-privilege agents are the primary "
                "vector for prompt-injection-driven damage.",
            )
        )

    env = data.get("env", {})
    if isinstance(env, dict):
        for key, value in env.items():
            if not isinstance(value, str) or not value:
                continue
            hits, _ = detect_secrets(value, Location(uri=str(path)))
            for hit in hits:
                findings.append(
                    Finding(
                        "AM-4004",
                        "config",
                        Severity.HIGH,
                        "Secret in agent config environment",
                        f"Env entry {key!r} holds a value that looks like a "
                        f"{hit.title.lower()} ({hit.rule_id}).",
                        Location(uri=str(path), line=_line_of(text, str(key))),
                        hit.snippet,
                        hit.recommendation,
                    )
                )

    for key in AUTO_APPROVE_KEYS:
        if data.get(key) in (True, "true", "1"):
            findings.append(
                Finding(
                    "AM-4006",
                    "config",
                    Severity.MEDIUM,
                    "Auto-approval enabled",
                    f"Config key {key!r} enables automatic approval of agent actions.",
                    Location(uri=str(path), line=_line_of(text, key)),
                    "",
                    "Prefer explicit per-action approval, especially for shell and "
                    "network tools.",
                )
            )

    return findings


def _audit_mcp(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        findings.append(
            Finding(
                "AM-4009",
                "config",
                Severity.INFO,
                "Config file could not be parsed",
                f"JSON parse error: {exc.msg} (line {exc.lineno}).",
                Location(uri=str(path)),
                "",
                "Fix the syntax so the MCP config can be audited.",
            )
        )
        findings.extend(detect_secrets_in_file(str(path), text.splitlines()))
        return findings

    servers: dict[str, Any] = {}
    if isinstance(data, dict):
        if isinstance(data.get("mcpServers"), dict):
            servers = data["mcpServers"]
        else:
            servers = {k: v for k, v in data.items() if isinstance(v, dict)}

    for name, cfg in servers.items():
        line_no = _line_of(text, f'"{name}"')

        url = cfg.get("url") if isinstance(cfg, dict) else None
        if isinstance(url, str) and url:
            parsed = urlsplit(url)
            host = (parsed.hostname or "").lower()
            if parsed.scheme == "http" and host not in {"localhost", "127.0.0.1", "[::1]"}:
                findings.append(
                    Finding(
                        "AM-4003",
                        "config",
                        Severity.MEDIUM,
                        "MCP endpoint uses insecure transport",
                        f"MCP server {name!r} is reached over plain HTTP — tool "
                        "descriptions and results are exposed to network observers.",
                        Location(uri=str(path), line=line_no),
                        url,
                        "Use a TLS (https) endpoint or a local stdio server.",
                    )
                )
            if EXFIL_HOST_RE.search(url):
                findings.append(
                    Finding(
                        "AM-4003",
                        "config",
                        Severity.HIGH,
                        "MCP endpoint on suspicious host",
                        f"MCP server {name!r} points to a known exfiltration/suspicious "
                        "host.",
                        Location(uri=str(path), line=line_no),
                        url,
                        "Verify this endpoint is legitimate and operated by a trusted "
                        "party before connecting.",
                    )
                )
            elif re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
                findings.append(
                    Finding(
                        "AM-4003",
                        "config",
                        Severity.LOW,
                        "MCP endpoint is a raw IP address",
                        f"MCP server {name!r} uses an unregistered IP ({host}) — "
                        "common in ad-hoc or malicious setups.",
                        Location(uri=str(path), line=line_no),
                        url,
                        "Prefer named, verifiable hosts.",
                    )
                )

        if isinstance(cfg, dict):
            parts: list[str] = []
            if isinstance(cfg.get("command"), str):
                parts.append(cfg["command"])
            args = cfg.get("args", [])
            if isinstance(args, list):
                parts.extend(str(a) for a in args if isinstance(a, (str, int, float, bool)))
            joined = " ".join(parts)
            if joined:
                m = PIPE_TO_SHELL_RE.search(joined)
                if m:
                    findings.append(
                        Finding(
                            "AM-3002",
                            "capability",
                            Severity.HIGH,
                            "Pipe-to-shell in MCP launch command",
                            f"MCP server {name!r} launches a payload piped into a shell.",
                            Location(uri=str(path), line=line_no),
                            joined,
                            "Download and verify the payload before executing it.",
                        )
                    )
                m = EXFIL_HOST_RE.search(joined)
                if m:
                    findings.append(
                        Finding(
                            "AM-3007",
                            "capability",
                            Severity.MEDIUM,
                            "Outbound exfiltration destination",
                            f"MCP server {name!r} launch command references a known "
                            "exfiltration/suspicious host.",
                            Location(uri=str(path), line=line_no),
                            joined,
                            "Verify the command and its network endpoints.",
                        )
                    )

            env = cfg.get("env", {})
            if isinstance(env, dict):
                for key, value in env.items():
                    if not isinstance(value, str) or not value:
                        continue
                    hits, _ = detect_secrets(value, Location(uri=str(path)))
                    for hit in hits:
                        findings.append(
                            Finding(
                                "AM-4004",
                                "config",
                                Severity.HIGH,
                                "Secret in MCP server environment",
                                f"Env entry {key!r} of server {name!r} holds a value "
                                f"that looks like a {hit.title.lower()} ({hit.rule_id}).",
                                Location(uri=str(path), line=line_no),
                                hit.snippet,
                                hit.recommendation,
                            )
                        )

    return findings


def _audit_instruction(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        loc = Location(uri=str(path), line=lineno)
        for label, pattern in _INSTRUCTION_MARKERS:
            m = pattern.search(line)
            if m:
                findings.append(
                    Finding(
                        "AM-4005",
                        "config",
                        Severity.MEDIUM,
                        "Instruction file contains injection-like text",
                        f"Agent instruction file contains text that reads like a "
                        f"prompt-injection ({label}).",
                        loc,
                        line.strip()[:160],
                        "Review whether this instruction is intentional. Instruction "
                        "files are agent system context — attacker-controlled text "
                        "there has persistent influence.",
                    )
                )
        m = EXFIL_HOST_RE.search(line)
        if m:
            findings.append(
                Finding(
                    "AM-1008",
                    "injection",
                    Severity.MEDIUM,
                    "Data exfiltration destination",
                    "Agent instruction file references a known exfiltration/suspicious "
                    "host.",
                    loc,
                    line.strip()[:160],
                    "Verify the endpoint before the agent acts on these instructions.",
                )
            )
    findings.extend(detect_secrets_in_file(str(path), lines))
    return findings


def _line_of(text: str, needle: str) -> int | None:
    if not needle:
        return None
    for i, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return i
    return None


def audit_config(path: Path) -> list[Finding]:
    """Audit a single config file or a directory of agent configuration."""
    if not path.exists():
        raise FileNotFoundError(path)

    if path.is_dir():
        files = _discover(path)
        if not files:
            return []
        findings: list[Finding] = []
        for f in files:
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            kind = _classify(f.name, f)
            if kind == "mcp":
                findings.extend(_audit_mcp(f, text))
            elif kind == "settings":
                findings.extend(_audit_settings(f, text))
            elif kind == "instruction":
                findings.extend(_audit_instruction(f, text))
            else:
                findings.extend(detect_secrets_in_file(str(f), text.splitlines()))
        return findings

    text = path.read_text(encoding="utf-8", errors="replace")
    kind = _classify(path.name, path)
    if kind == "mcp":
        return _audit_mcp(path, text)
    if kind == "settings":
        return _audit_settings(path, text)
    if kind == "instruction":
        return _audit_instruction(path, text)
    return detect_secrets_in_file(str(path), text.splitlines())
