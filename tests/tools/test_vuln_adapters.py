from __future__ import annotations

import json

from gesicht.tools.adapters.sqlmap import SqlmapAdapter
from gesicht.tools.adapters.vuln import NiktoAdapter, NucleiAdapter, WpscanAdapter
from gesicht.tools.base import Task


def mktask(ws, tmp_path, targets, **opts):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return Task(targets=list(targets), workspace=ws, outdir=out, options=opts)


NUCLEI_LINE = json.dumps({
    "template-id": "CVE-2021-44228",
    "info": {
        "name": "Apache Log4j RCE", "severity": "critical",
        "tags": ["cve", "rce", "log4j"],
        "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        "classification": {
            "cve-id": ["CVE-2021-44228"], "cwe-id": ["CWE-502"],
            "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "cvss-score": 10.0,
        },
    },
    "type": "http", "host": "https://a.acme.com",
    "matched-at": "https://a.acme.com/api", "extracted-results": ["${jndi:ldap://x}"],
})


def test_nuclei_parse(make_ws, tmp_path):
    ws = make_ws("acme.com")
    t = mktask(ws, tmp_path, ["https://a.acme.com"])
    t.artifact("nuclei.jsonl").write_text(NUCLEI_LINE + "\ngarbage\n")
    hits = list(NucleiAdapter().parse(tmp_path / "raw.txt", t))
    assert len(hits) == 1
    h = hits[0]
    assert h.scanner == "nuclei" and h.severity == "critical"
    assert h.cwe == "CWE-502" and h.cve == ["CVE-2021-44228"]
    assert h.cvss_score == 10.0 and h.url.endswith("/api")
    assert h.host == "a.acme.com" and "rce" in h.tags


def test_nuclei_build_steps(make_ws, tmp_path):
    ws = make_ws("acme.com")
    t = mktask(ws, tmp_path, ["https://a.acme.com"], severity="high,critical", tags="rce")
    steps = NucleiAdapter().build_steps(t, "nuclei")
    assert steps[0][:2] == ["nuclei", "-l"]
    assert "-severity" in steps[0] and "high,critical" in steps[0]
    assert "-jsonl" in steps[0]


NIKTO_XML = """<?xml version="1.0" ?>
<niktoscan>
  <scandetails targethostname="a.acme.com" targetip="1.2.3.4">
    <item id="999966">
      <description>Server leaks inode via ETag</description>
      <uri>/</uri>
      <namelink>https://a.acme.com/</namelink>
    </item>
  </scandetails>
</niktoscan>
"""


def test_nikto_parse(make_ws, tmp_path):
    ws = make_ws("acme.com")
    t = mktask(ws, tmp_path, ["https://a.acme.com"])
    t.artifact("nikto-0.xml").write_text(NIKTO_XML)
    hits = list(NiktoAdapter().parse(tmp_path / "raw.txt", t))
    assert hits[0].scanner == "nikto" and hits[0].severity == "low"
    assert "ETag" in hits[0].name


WPSCAN_JSON = json.dumps({
    "target_url": "https://blog.acme.com/",
    "version": {
        "number": "5.8",
        "vulnerabilities": [
            {"title": "WP 5.8 - XSS", "fixed_in": "5.8.1",
             "references": {"cve": ["2021-1234"], "url": ["https://x"]}}
        ],
    },
    "interesting_findings": [
        {"type": "backup_file", "url": "https://blog.acme.com/wp-config.php.bak",
         "to_s": "wp-config backup found"},
        {"type": "headers", "url": "https://blog.acme.com/"},
    ],
})


def test_wpscan_parse(make_ws, tmp_path):
    ws = make_ws("acme.com")
    t = mktask(ws, tmp_path, ["https://blog.acme.com/"])
    t.artifact("wpscan-0.json").write_text(WPSCAN_JSON)
    hits = list(WpscanAdapter().parse(tmp_path / "raw.txt", t))
    names = {h.name for h in hits}
    assert "WP 5.8 - XSS" in names
    assert any("backup" in n for n in names)
    assert not any(h.signature == "headers" for h in hits)  # boring finding skipped
    xss = next(h for h in hits if h.name == "WP 5.8 - XSS")
    assert xss.cve == ["CVE-2021-1234"]


SQLMAP_OUT = """
[*] starting
GET parameter 'id' is vulnerable.
sqlmap identified the following injection point(s):
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 1=1
---
back-end DBMS: MySQL >= 5.6
"""


def test_sqlmap_parse(make_ws, tmp_path):
    ws = make_ws("acme.com")
    raw = tmp_path / "raw.txt"
    raw.write_text(SQLMAP_OUT)
    t = mktask(ws, tmp_path, ["https://a.acme.com/item?id=1"])
    hits = list(SqlmapAdapter().parse(raw, t))
    assert len(hits) == 1
    h = hits[0]
    assert h.scanner == "sqlmap" and h.severity == "high" and h.cwe == "CWE-89"
    assert "MySQL" in h.description
    assert "id" in h.name


def test_sqlmap_exploit_flag_adds_dump(make_ws, tmp_path):
    ws = make_ws("acme.com")
    t = mktask(ws, tmp_path, ["https://a.acme.com/?id=1"], exploit=True)
    steps = SqlmapAdapter().build_steps(t, "sqlmap")
    assert "--dbs" in steps[0]
    t2 = mktask(ws, tmp_path, ["https://a.acme.com/?id=1"])
    assert "--dbs" not in SqlmapAdapter().build_steps(t2, "sqlmap")[0]


def test_sqlmap_is_extra_confirm():
    assert SqlmapAdapter().extra_confirm is True
