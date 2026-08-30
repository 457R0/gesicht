from __future__ import annotations

from gesicht.core.findings import (
    FindingStore,
    draft_from_vuln,
    normalize_severity,
    parse_finding,
    render_finding,
    weakness_for_tags,
)
from gesicht.core.models import Finding, FindingStatus, VulnHit


def test_render_parse_roundtrip():
    f = Finding(
        number=3, slug="idor-invoices", title="IDOR in invoice download",
        target="https://api.acme.com", program="acme", vuln_class="CWE-639",
        severity="high", status=FindingStatus.CONFIRMED,
        summary="You can read any invoice.", steps_to_reproduce="1. do X\n2. do Y",
        poc="GET /invoice/1002", impact="PII exposure", remediation="check ownership",
        references=["https://cwe.mitre.org/data/definitions/639.html"],
        found_via="manual",
    )
    text = render_finding(f)
    g = parse_finding(text)
    assert g.number == 3
    assert g.title == f.title
    assert g.status == FindingStatus.CONFIRMED
    assert g.steps_to_reproduce == "1. do X\n2. do Y"
    assert g.poc == "GET /invoice/1002"
    assert g.references == ["https://cwe.mitre.org/data/definitions/639.html"]


def test_store_create_list_get(make_ws):
    ws = make_ws("acme.com")
    store = FindingStore(ws)
    assert store.list() == []
    f1 = store.create("First bug", severity="medium")
    f2 = store.create("Second bug", severity="high")
    assert f1.number == 1 and f2.number == 2
    assert [f.number for f in store.list()] == [1, 2]
    assert store.get("1").title == "First bug"
    assert store.get(f2.slug).number == 2
    assert store.path_for(f1).name == "0001-first-bug.md"


def test_store_indexes_into_db_and_fts(make_ws):
    ws = make_ws("acme.com")
    store = FindingStore(ws)
    f = store.create("SSRF in webhook", severity="high")
    f.summary = "The webhook fetches arbitrary internal URLs"
    store.save(f)

    from gesicht.core.store import Store
    assert Store(ws).summary()["findings"] == 1

    from gesicht.core import db as _db
    conn = _db.connect(ws.index_db)
    try:
        rows = conn.execute(
            "SELECT number FROM finding_fts WHERE finding_fts MATCH 'webhook'"
        ).fetchall()
    finally:
        conn.close()
    assert [r[0] for r in rows] == [1]


def test_normalize_severity_and_weakness():
    assert normalize_severity("Informational") == "info"
    assert normalize_severity("important") == "high"
    cwe, weakness = weakness_for_tags(["cve", "rce"])
    assert cwe == "CWE-94"
    assert "Code Injection" in weakness


def test_draft_from_vuln():
    hit = VulnHit(
        scanner="nuclei", signature="apache-struts-rce", name="Struts RCE",
        severity="critical", url="https://a.acme.com/struts", host="a.acme.com",
        cve=["CVE-2017-5638"], cvss_score=9.8, tags=["rce", "cve"],
        description="Remote code execution in Apache Struts",
    )
    f = draft_from_vuln(hit, program="acme")
    assert f.severity == "critical"
    assert f.vuln_class == "CWE-94"  # from the 'rce' tag
    assert f.found_via == "nuclei"
    assert f.source_key == hit.id
    assert "struts" in f.steps_to_reproduce.lower()
    assert f.status == FindingStatus.DRAFT


def test_store_dedup_by_source_key(make_ws):
    ws = make_ws("acme.com")
    store = FindingStore(ws)
    hit = VulnHit(scanner="nuclei", signature="x", name="X", severity="high",
                  url="https://a.acme.com/x")
    d = draft_from_vuln(hit, program="acme")
    d.number = store.next_number()
    store.save(d, touch=False)
    assert store.has_source_key(hit.id) is True
    assert store.has_source_key("nope") is False
