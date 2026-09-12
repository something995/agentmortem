"""AgentMortem command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agentmortem import __version__
from agentmortem.config.auditor import audit_config
from agentmortem.models import Report, Severity
from agentmortem.report.console import render_text
from agentmortem.report.json_report import render_json
from agentmortem.report.sarif import render_sarif
from agentmortem.transcript.engine import scan_transcript_file
from agentmortem.transcript.parsers import TranscriptError

_TRANSCRIPT_SUFFIXES = {".json", ".jsonl", ".ndjson"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentmortem",
        description=(
            "Post-mortem forensics for AI agent sessions: prompt injection, "
            "secret leakage, and risky capability sequences. Deterministic and "
            "offline — no LLMs, no network calls."
        ),
    )
    parser.add_argument("--version", action="version", version=f"agentmortem {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser(
        "scan",
        help="Scan a transcript file, a directory of transcripts, or agent config",
    )
    scan.add_argument("path", help="File or directory to scan")
    scan.add_argument(
        "--mode",
        choices=["auto", "transcript", "config"],
        default="auto",
        help="Target type (default: auto-detect)",
    )
    scan.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Report format (default: text)",
    )
    scan.add_argument(
        "-o",
        "--output",
        help="Write the report to a file instead of stdout",
    )
    scan.add_argument(
        "--fail-on",
        choices=["off", "info", "low", "medium", "high", "critical"],
        default="medium",
        help="Exit non-zero when findings reach this severity (default: medium)",
    )
    scan.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in text output",
    )
    return parser


def _resolve_mode(path: Path, mode: str) -> str:
    if mode != "auto":
        return mode
    if path.is_dir():
        return "config"
    try:
        from agentmortem.transcript.parsers import parse_transcript

        parse_transcript(path)
        return "transcript"
    except TranscriptError:
        return "config"


def _scan_transcript_target(path: Path) -> tuple[list, dict]:
    if path.is_dir():
        files = sorted(
            p
            for p in path.rglob("*")
            if p.is_file() and p.suffix.lower() in _TRANSCRIPT_SUFFIXES
        )
        if not files:
            raise TranscriptError(f"no .json/.jsonl transcript files found under {path}")
        findings = []
        stats = {"messages": 0, "files": 0}
        for f in files:
            f_findings, f_stats = scan_transcript_file(f)
            findings.extend(f_findings)
            stats["messages"] += f_stats.get("messages", 0)
            stats["files"] += 1
        return findings, stats
    findings, stats = scan_transcript_file(path)
    return findings, stats


def _run_scan(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists():
        print(f"agentmortem: error: path not found: {path}", file=sys.stderr)
        return 2

    mode = _resolve_mode(path, args.mode)
    try:
        if mode == "transcript":
            findings, stats = _scan_transcript_target(path)
        else:
            findings = audit_config(path)
            stats = {"files": 1 if path.is_file() else len(
                [p for p in path.rglob("*") if p.is_file()]
            )}
    except TranscriptError as exc:
        print(f"agentmortem: error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"agentmortem: error: {exc}", file=sys.stderr)
        return 2

    report = Report(
        version=__version__,
        target=str(path),
        mode=mode,
        findings=findings,
        stats=stats,
    )

    if args.format == "json":
        rendered = render_json(report)
    elif args.format == "sarif":
        rendered = render_sarif(report)
    else:
        rendered = render_text(report, use_color=sys.stdout.isatty() and not args.no_color)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered, encoding="utf-8")
        print(f"agentmortem: report written to {out}")
    else:
        sys.stdout.write(rendered)

    if args.fail_on == "off":
        return 0
    threshold = Severity[args.fail_on.upper()]
    if report.max_severity is not None and report.max_severity >= threshold:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
