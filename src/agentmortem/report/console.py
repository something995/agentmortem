"""Human-readable console output."""

from __future__ import annotations

from agentmortem.models import Report, Severity

_RESET = "\033[0m"
_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "\033[1;35m",  # bold magenta
    Severity.HIGH: "\033[1;31m",  # bold red
    Severity.MEDIUM: "\033[1;33m",  # bold yellow
    Severity.LOW: "\033[1;36m",  # bold cyan
    Severity.INFO: "\033[0;37m",  # gray
}


def _paint(text: str, severity: Severity, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_STYLES[severity]}{text}{_RESET}"


def render_text(report: Report, use_color: bool = True) -> str:
    lines: list[str] = []
    lines.append(f"AgentMortem v{report.version} — {report.mode} scan of {report.target}")
    if report.stats.get("messages"):
        lines.append(f"  {report.stats['messages']} messages scanned")
    elif report.stats.get("files"):
        lines.append(f"  {report.stats['files']} files scanned")
    lines.append("")

    if not report.findings:
        lines.append("  ✓ No findings.")
        return "\n".join(lines)

    counts = report.count_by_severity()
    parts = [f"{counts[s.label]} {s.label}" for s in (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ) if counts[s.label]]
    lines.append(f"  {len(report.findings)} findings: " + " · ".join(parts))
    lines.append("")

    for f in report.findings:
        sev = _paint(f.severity.label.upper().ljust(8) + " ", f.severity, use_color)
        lines.append(f"  {sev}{f.rule_id}  {f.title}")
        lines.append(f"             {f.location.display}")
        if f.snippet:
            lines.append(f'             │ {f.snippet}')
        if f.recommendation:
            lines.append(f"             → {f.recommendation}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
