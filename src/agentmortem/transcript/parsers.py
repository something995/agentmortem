"""Transcript parsing.

Normalizes the two common agent session formats into a common
:class:`Message` sequence:

* **JSONL event logs** (Claude Code style): one JSON object per line with a
  ``type`` and a nested ``message``.
* **JSON chat logs** (OpenAI style): a JSON array of ``{"role", "content"}``
  messages, or an object with a ``messages`` key.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class TranscriptError(ValueError):
    """Raised when a file cannot be interpreted as an agent transcript."""


@dataclass(frozen=True)
class ToolCall:
    """A single tool invocation made by the agent."""

    name: str
    args: dict[str, Any]

    def text(self) -> str:
        return json.dumps(self.args, ensure_ascii=False, sort_keys=True, default=str)


@dataclass
class Message:
    """A normalized message in a transcript."""

    index: int
    role: str  # system | user | assistant | tool
    text: str
    line: int | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)

    def scan_text(self) -> str:
        """Text + tool-call payload, joined for content scanning."""
        parts = [self.text]
        for tc in self.tool_calls:
            parts.append(tc.name)
            parts.append(tc.text())
        return "\n".join(p for p in parts if p)


_VALID_ROLES = {"system", "user", "assistant", "tool"}


def _looks_like_jsonl(lines: list[str]) -> bool:
    non_empty = [ln for ln in lines if ln.strip()]
    if not non_empty:
        return False
    return all(ln.lstrip().startswith("{") for ln in non_empty)


def _normalize(obj: Any, line: int | None, index: int) -> Message | None:
    """Convert one raw JSON object into a :class:`Message` (or skip it)."""
    if not isinstance(obj, dict):
        return None
    msg = obj.get("message") if isinstance(obj.get("message"), dict) else obj
    role = str(msg.get("role") or obj.get("type") or "").lower()
    if role not in _VALID_ROLES:
        return None  # e.g. "result", "summary" events

    content = msg.get("content", obj.get("content"))
    text_parts: list[str] = []
    tool_calls: list[ToolCall] = []

    # Claude Code style: tool results arrive as user-role messages whose content
    # consists solely of tool_result blocks. Reclassify them as tool output.
    is_pure_tool_result = False
    if isinstance(content, list):
        block_types = [str(b.get("type", "")) for b in content if isinstance(b, dict)]
        is_pure_tool_result = bool(block_types) and all(
            t == "tool_result" for t in block_types
        )

    if isinstance(content, str):
        text_parts.append(content)
    elif isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                text_parts.append(str(block))
                continue
            btype = str(block.get("type", ""))
            if btype == "text":
                text_parts.append(str(block.get("text", "")))
            elif btype == "tool_use":
                tool_calls.append(
                    ToolCall(str(block.get("name", "unknown")), block.get("input") or {})
                )
            elif btype == "tool_result":
                c = block.get("content")
                if isinstance(c, str):
                    text_parts.append(c)
                elif isinstance(c, list):
                    text_parts.append(
                        " ".join(
                            str(b.get("text", "")) for b in c if isinstance(b, dict)
                        )
                    )
            else:
                if block.get("text") is not None:
                    text_parts.append(str(block.get("text")))

    for tc in (msg.get("tool_calls") or obj.get("tool_calls") or []):
        if not isinstance(tc, dict):
            continue
        fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
        name = str(fn.get("name") or tc.get("name") or "unknown")
        args = fn.get("arguments", tc.get("args", tc.get("input")))
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {"raw": args}
        if not isinstance(args, dict):
            args = {"value": args}
        tool_calls.append(ToolCall(name, args))

    if is_pure_tool_result and role == "user":
        role = "tool"

    if role == "tool":
        tool_name = obj.get("name") or msg.get("name")
        if tool_name:
            text_parts.insert(0, f"[tool: {tool_name}]")

    return Message(
        index=index,
        role=role,
        text="\n".join(p for p in text_parts if p),
        line=line,
        tool_calls=tool_calls,
    )


def parse_transcript(path: Path) -> list[Message]:
    """Parse a transcript file (JSONL or JSON) into normalized messages."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    if not raw.strip():
        return []

    lines = raw.splitlines()
    non_empty = [ln for ln in lines if ln.strip()]
    suffix_jsonl = path.suffix.lower() in {".jsonl", ".ndjson"}
    multi_line_objects = _looks_like_jsonl(lines) and len(non_empty) > 1

    if suffix_jsonl or multi_line_objects:
        messages: list[Message] = []
        for lineno, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise TranscriptError(f"{path}: line {lineno}: invalid JSON ({exc.msg})") from exc
            msg = _normalize(obj, lineno, len(messages))
            if msg is not None:
                messages.append(msg)
        if messages:
            return messages
        if suffix_jsonl:
            raise TranscriptError(f"{path}: no message objects found (not a transcript?)")
        # A single-line object file may still be whole-file JSON; fall through.

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TranscriptError(f"{path}: not valid JSON ({exc.msg})") from exc

    if isinstance(data, dict):
        data = data.get("messages", [data])
    if not isinstance(data, list):
        raise TranscriptError(f"{path}: expected a JSON array of messages")

    messages = []
    for i, item in enumerate(data):
        msg = _normalize(item, None, i)
        if msg is not None:
            messages.append(msg)
    if not messages:
        raise TranscriptError(f"{path}: no message objects found (not a transcript?)")
    return messages
