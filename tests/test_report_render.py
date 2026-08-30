from __future__ import annotations

import pytest

from gesicht.core.errors import UsageError
from gesicht.core.models import Finding, FindingStatus
from gesicht.report.cvss import build_cvss31_interactive
from gesicht.report.render import render_report


def _finding(**kw) -> Finding:
    base = dict(
        number=1, slug="idor", title="IDOR in invoice download",
        target="https://api.acme.com/invoice/1002", program="acme",
        vuln_class="CWE-639", weakness="Authorization Bypass",
        severity="high", status=FindingStatus.CONFIRMED,
        summary="Any user can read any invoice.",
        steps_to_reproduce="1. log in\n2. GET /invoice/1002",
        impact="Full PII disclosure.", remediation="Check ownership.",
        references=["https://cwe.mitre.org/data/definitions/639.html"],
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        cvss_score=6.5,
    )
    base.update(kw)
    return Finding(**base)


def test_h1_report_has_all_sections():
    rep = render_report(_finding())
    for h in ("# IDOR in invoice download", "## Summary", "## Steps to Reproduce",
              "## Impact", "## Remediation", "## Supporting Material / References"):
        assert h in rep.text
    assert "CVSS 3.1 6.5" in rep.text
    assert "CWE-639" in rep.text
    assert rep.redacted == []


def test_missing_fields_become_todo():
    rep = render_report(_finding(poc="", impact="", remediation=""))
    assert rep.text.count("_TODO") >= 2


def test_secret_in_finding_body_is_redacted():
    rep = render_report(_finding(poc="Authorization: Bearer abcdef0123456789abcdef0"))
    assert "[REDACTED-BEARER]" in rep.text
    assert "BEARER" in rep.redacted


def test_no_redact_option():
    rep = render_report(
        _finding(poc="token AKIAIOSFODNN7EXAMPLE"), do_redact=False
    )
    assert "AKIAIOSFODNN7EXAMPLE" in rep.text and rep.redacted == []


def test_unknown_template_raises():
    with pytest.raises(UsageError):
        render_report(_finding(), template="does-not-exist")


def test_workspace_template_override(make_ws):
    ws = make_ws("acme.com")
    tdir = ws.reports_dir / "templates"
    tdir.mkdir(parents=True)
    (tdir / "h1_report.md.j2").write_text("CUSTOM {{ f.title }} / {{ severity_label }}")
    rep = render_report(_finding(), workspace=ws)
    assert rep.text == "CUSTOM IDOR in invoice download / High"


def test_evidence_embedded_and_redacted(make_ws):
    ws = make_ws("acme.com")
    (ws.root / "loot").mkdir(exist_ok=True)
    (ws.root / "loot" / "resp.txt").write_text("HTTP/1.1 200\nx-api-key: supersecretvalue123")
    rep = render_report(_finding(evidence=["loot/resp.txt"]), workspace=ws)
    assert "loot/resp.txt" in rep.text
    assert "[REDACTED-API-KEY-KV]" in rep.text
    assert "API-KEY-KV" in rep.redacted


def test_cvss_wizard_builds_vector():
    answers = iter(["N", "L", "N", "N", "U", "H", "N", "N"])
    vector = build_cvss31_interactive(prompt=lambda *a, **k: next(answers))
    assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
