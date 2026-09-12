"""Small shared helpers (snippet building, text shortening)."""

from __future__ import annotations

from agentmortem.secrets.detector import redact_spans

SNIPPET_CONTEXT = 60
SNIPPET_MAX = 180


def make_snippet(
    text: str,
    start: int,
    end: int,
    redactions: list[tuple[int, int, str]] | None = None,
) -> str:
    """Build a short, single-line context snippet around ``[start, end)``."""
    a = max(0, start - SNIPPET_CONTEXT)
    b = min(len(text), end + SNIPPET_CONTEXT)
    # Redact on the raw window first: offsets refer to the original text, and
    # flattening newlines beforehand would shift every later span.
    local = [
        (max(s, a) - a, min(e, b) - a, t)
        for s, e, t in (redactions or [])
        if e > a and s < b
    ]
    chunk = redact_spans(text[a:b], local) if local else text[a:b]
    chunk = chunk.replace("\n", "\\n").replace("\t", "\\t")
    if len(chunk) > SNIPPET_MAX:
        chunk = chunk[: SNIPPET_MAX - 3] + "..."
    return chunk


def short(match_text: str, limit: int = 120) -> str:
    flat = match_text.replace("\n", "\\n")
    return flat[:limit] + ("..." if len(flat) > limit else "")
