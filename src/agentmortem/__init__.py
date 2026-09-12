"""AgentMortem — post-mortem forensics for AI agent sessions.

Deterministic, offline scanning of agent transcripts and configuration
files for prompt-injection attempts, secret leakage, and risky capability
sequences. No LLMs, no network calls, no telemetry.
"""

from __future__ import annotations

__version__ = "0.1.0"

from agentmortem.config.auditor import audit_config
from agentmortem.models import Finding, Location, Report, Severity
from agentmortem.transcript.engine import scan_transcript
from agentmortem.transcript.parsers import (
    Message,
    ToolCall,
    TranscriptError,
    parse_transcript,
)

__all__ = [
    "__version__",
    "Finding",
    "Location",
    "Message",
    "Report",
    "Severity",
    "ToolCall",
    "TranscriptError",
    "audit_config",
    "parse_transcript",
    "scan_transcript",
]
