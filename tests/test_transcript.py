from __future__ import annotations

from pathlib import Path

import pytest
from conftest import BENIGN, MALICIOUS

from agentmortem.transcript.engine import scan_transcript
from agentmortem.transcript.parsers import TranscriptError, parse_transcript


def test_parse_jsonl_transcript() -> None:
    messages = parse_transcript(MALICIOUS)
    assert len(messages) == 6
    assert [m.role for m in messages] == [
        "user",
        "assistant",
        "tool",
        "user",
        "assistant",
        "tool",
    ]
    assert messages[1].tool_calls[0].name == "bash"
    assert messages[1].tool_calls[0].args["command"].startswith("cat .env")
    assert messages[2].line == 3


def test_parse_openai_style_json(tmp_path: Path) -> None:
    p = tmp_path / "chat.json"
    p.write_text(
        __import__("json").dumps(
            [
                {"role": "user", "content": "hi"},
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "function": {"name": "bash", "arguments": '{"command": "ls"}'}
                        }
                    ],
                },
                {"role": "tool", "content": "ok"},
            ]
        ),
        encoding="utf-8",
    )
    messages = parse_transcript(p)
    assert len(messages) == 3
    assert messages[1].tool_calls[0].name == "bash"
    assert messages[1].tool_calls[0].args == {"command": "ls"}


def test_parse_messages_object_form(tmp_path: Path) -> None:
    p = tmp_path / "chat.json"
    p.write_text('{"messages": [{"role": "user", "content": "hello"}]}', encoding="utf-8")
    messages = parse_transcript(p)
    assert len(messages) == 1
    assert messages[0].text == "hello"


def test_parse_invalid_json_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.jsonl"
    p.write_text('{"type": "user",\n', encoding="utf-8")
    with pytest.raises(TranscriptError):
        parse_transcript(p)


def test_parse_non_message_object_raises(tmp_path: Path) -> None:
    p = tmp_path / "config.json"
    p.write_text('{"foo": "bar"}', encoding="utf-8")
    with pytest.raises(TranscriptError):
        parse_transcript(p)


def test_empty_file_parses_to_empty(tmp_path: Path) -> None:
    p = tmp_path / "empty.jsonl"
    p.write_text("", encoding="utf-8")
    assert parse_transcript(p) == []


def test_malicious_transcript_flags_expected_rules() -> None:
    messages = parse_transcript(MALICIOUS)
    findings, stats = scan_transcript(messages, str(MALICIOUS))
    ids = {f.rule_id for f in findings}
    expected = {
        "AM-1001",  # instruction override in user message
        "AM-1008",  # exfil host in user message
        "AM-2001",  # AWS key in tool output
        "AM-2003",  # OpenAI key in tool output
        "AM-2006",  # connection string in tool output
        "AM-3001",  # read -> send exfil chain
        "AM-3004",  # cat .env credential access
        "AM-3007",  # exfil host in command
    }
    assert expected <= ids, f"missing: {expected - ids}"
    assert stats == {"messages": 6, "files": 1}


def test_exfil_chain_is_critical_when_destination_known() -> None:
    messages = parse_transcript(MALICIOUS)
    findings, _ = scan_transcript(messages, str(MALICIOUS))
    chain = [f for f in findings if f.rule_id == "AM-3001"]
    assert chain
    assert all(f.severity.name == "CRITICAL" for f in chain)


def test_benign_transcript_is_clean() -> None:
    messages = parse_transcript(BENIGN)
    findings, _ = scan_transcript(messages, str(BENIGN))
    assert findings == []
