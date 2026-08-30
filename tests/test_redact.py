from __future__ import annotations

import pytest

from gesicht.report.redact import redact, redact_findings_evidence


@pytest.mark.parametrize(
    "text,tag",
    [
        ("key AKIAIOSFODNN7EXAMPLE here", "AWS-KEY"),
        ("AIzaSyD1234567890abcdefghijklmnopqrstuvw here", "GCP-KEY"),
        ("token xoxb-123456789012-abcdefabcdef", "SLACK-TOKEN"),
        ("ghp_0123456789abcdefghijklmnopqrstuvwxyz", "GITHUB-TOKEN"),
        ("Authorization: Bearer abcdef0123456789abcdef", "BEARER"),
        ("visit https://user:s3cret@internal.acme.com/x", "BASIC-AUTH-URL"),
        ("contact jane.doe@example.com now", "EMAIL"),
        ("ssn 123-45-6789 leaked", "SSN"),
        ("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF-1234", "JWT"),
        ('config: api_key = "abcdef1234567890xyz"', "API-KEY-KV"),
    ],
)
def test_redacts_secret_types(text, tag):
    out, fired = redact(text)
    assert tag in fired
    assert f"[REDACTED-{tag}]" in out


def test_credit_card_luhn_gate():
    good, fired = redact("card 4242 4242 4242 4242 on file")  # valid Luhn
    assert "CREDIT-CARD" in fired and "[REDACTED-CREDIT-CARD]" in good
    bad, fired2 = redact("order id 1234 5678 9012 3456 shipped")  # fails Luhn
    assert "CREDIT-CARD" not in fired2


def test_private_key_block():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEabc\n-----END RSA PRIVATE KEY-----"
    out, fired = redact(text)
    assert fired == ["PRIVATE-KEY"] and "BEGIN RSA" not in out


def test_disabled_passthrough():
    text = "AKIAIOSFODNN7EXAMPLE"
    assert redact(text, enabled=False) == (text, [])


def test_evidence_reading(tmp_path):
    (tmp_path / "loot").mkdir()
    (tmp_path / "loot" / "resp.txt").write_text("Set-Cookie: sid=x\ntoken: abcdef1234567890xyz")
    (tmp_path / "loot" / "img.bin").write_bytes(b"\x89PNG\x00\x01\x02\x03")
    items = redact_findings_evidence(
        ["loot/resp.txt", "loot/img.bin", "loot/missing.txt"], tmp_path
    )
    by_path = {i["path"]: i for i in items}
    assert by_path["loot/resp.txt"]["kind"] == "text"
    assert "API-KEY-KV" in by_path["loot/resp.txt"]["redacted"]
    assert by_path["loot/img.bin"]["kind"] == "binary"
    assert "not found" in by_path["loot/missing.txt"]["note"]
