from __future__ import annotations

import pytest

from agentmortem.models import Location
from agentmortem.secrets.detector import detect_secrets, shannon_entropy

LOC = Location(uri="t.jsonl", line=1, message_index=0)


@pytest.mark.parametrize(
    ("value", "rule_id"),
    [
        ("AKIAIOSFODNN7EXAMPLE", "AM-2001"),
        ("ghp_abcdefghijklmnopqrstuvwxyz0123456789", "AM-2002"),
        ("github_pat_11ABCDEFGH0123456789abcd", "AM-2002"),
        ("sk-proj-Ab12Cd34Ef56Gh78Ij90KlMnOpQrStUvWx", "AM-2003"),
        ("sk-AbCdEfGhIjKlMnOpQrStUvWxYz012345", "AM-2003"),
        ("-----BEGIN RSA PRIVATE KEY-----", "AM-2004"),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", "AM-2004"),
        (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "AM-2005",
        ),
        ("postgres://deploy:S3cr3tP@ss@db.internal:5432/app", "AM-2006"),
        ("mongodb+srv://admin:hunter22@cluster0.example.net/db", "AM-2006"),
        # Short synthetic value: matches AM-2007 but is deliberately shorter
        # than real tokens so GitHub push-protection doesn't flag the fixture.
        ("xoxb-123456789012-AbCd", "AM-2007"),
        ("123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw1", "AM-2008"),
        ("AIzaA1b2C3d4E5f6G7h8I9j0KlMnOpQrStUvWXy", "AM-2009"),
        # Short synthetic value: matches AM-2010 but is deliberately shorter
        # than real keys so GitHub push-protection doesn't flag the fixture.
        ("sk_live_4eC39HqLyj", "AM-2010"),
        ('api_key = "abcd1234efgh5678ijkl"', "AM-2011"),
        ("client_secret: Zx9vW4mKp2Lq7RtYb3Nc8HjD5FsGa6E", "AM-2011"),
    ],
)
def test_known_secret_detected(value: str, rule_id: str) -> None:
    findings, _ = detect_secrets(f"context {value} context", LOC)
    ids = [f.rule_id for f in findings]
    assert rule_id in ids, f"expected {rule_id} in {ids}"


def test_high_entropy_token_detected() -> None:
    token = "aB3dF6gH9jK2mN5pQ8rS1tU4vW7xY0zA3cE6fG"
    assert shannon_entropy(token) >= 4.3
    findings, _ = detect_secrets(f"token: {token} end", LOC)
    assert any(f.rule_id == "AM-2012" for f in findings)


def test_sha256_hex_digest_not_flagged() -> None:
    digest = "3f6b4c9a1d2e5f7083a4b6c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2"
    findings, _ = detect_secrets(f"commit {digest} merged", LOC)
    assert not any(f.rule_id == "AM-2012" for f in findings)


def test_url_path_fragments_not_flagged() -> None:
    findings, _ = detect_secrets(
        "see com/verylongorganization/someverylongrepositoryname in the docs", LOC
    )
    assert not any(f.rule_id == "AM-2012" for f in findings)


def test_benign_text_has_no_secrets() -> None:
    findings, spans = detect_secrets(
        "The quick brown fox jumped over the lazy dog. npm install completed.", LOC
    )
    assert findings == []
    assert spans == []


def test_snippet_redacts_secret_value() -> None:
    findings, _ = detect_secrets("key is AKIAIOSFODNN7EXAMPLE ok", LOC)
    assert findings
    snippet = findings[0].snippet
    assert "AKIAIOSFODNN7EXAMPLE" not in snippet
    assert "[REDACTED-AWS-ACCESS-KEY-ID]" in snippet


def test_snippet_offsets_across_newlines() -> None:
    # Regression: redaction spans must not shift when the window contains
    # newlines (markers were previously placed one char early per preceding
    # newline).
    text = (
        "DATABASE_URL=postgres://deploy:S3cr3tP@ss@db.internal:5432/app\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "OPENAI_API_KEY=sk-proj-Ab12Cd34Ef56Gh78Ij90KlMnOpQrStUvWx"
    )
    findings, _ = detect_secrets(text, LOC)
    expected = (
        "[REDACTED-CONNECTION-STRING]\\nAWS_ACCESS_KEY_ID="
        "[REDACTED-AWS-ACCESS-KEY-ID]\\nOPENAI_API_KEY="
        "[REDACTED-OPENAI-API-KEY]"
    )
    aws = next(f for f in findings if f.rule_id == "AM-2001")
    openai = next(f for f in findings if f.rule_id == "AM-2003")
    assert aws.snippet == expected
    assert openai.snippet == expected
    for f in findings:
        assert "AKIAIOSFODNN7EXAMPLE" not in f.snippet
        assert "sk-proj-" not in f.snippet


def test_assignment_not_double_reported_over_specific_rule() -> None:
    # The OpenAI key rule (AM-2003) should win; AM-2011 overlaps the same span.
    findings, _ = detect_secrets("OPENAI_API_KEY=sk-proj-Ab12Cd34Ef56Gh78Ij90KlMnOpQrStUvWx", LOC)
    ids = [f.rule_id for f in findings]
    assert "AM-2003" in ids
    assert "AM-2011" not in ids
