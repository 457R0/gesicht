from __future__ import annotations

import json

from gesicht.core.models import Service
from gesicht.tools.adapters.content import FeroxbusterAdapter, FfufAdapter, GobusterAdapter
from gesicht.tools.adapters.fingerprint import Wafw00fAdapter, WhatwebAdapter
from gesicht.tools.adapters.httpx_pd import HttpxAdapter
from gesicht.tools.adapters.katana import KatanaAdapter
from gesicht.tools.adapters.pd_recon import DnsxAdapter, NaabuAdapter, SubfinderAdapter
from gesicht.tools.base import Task


def mktask(ws, tmp_path, targets, **opts):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return Task(targets=list(targets), workspace=ws, outdir=out, options=opts)


def test_httpx_parses_jsonl(make_ws, tmp_path):
    ws = make_ws("acme.com")
    t = mktask(ws, tmp_path, ["acme.com"])
    t.artifact("httpx.jsonl").write_text(
        json.dumps({"url": "https://acme.com", "host": "acme.com", "status_code": 200,
                    "title": "Home", "tech": ["nginx"], "content_length": 12})
        + "\n" + "not json\n"
    )
    eps = list(HttpxAdapter().parse(tmp_path / "raw.txt", t))
    assert len(eps) == 1 and eps[0].status == 200 and eps[0].tech == ["nginx"]


def test_httpx_build_steps_writes_input(make_ws, tmp_path):
    ws = make_ws("acme.com")
    t = mktask(ws, tmp_path, ["a.acme.com", "b.acme.com"])
    steps = HttpxAdapter().build_steps(t, "/usr/bin/httpx-toolkit")
    assert len(steps) == 1 and "-json" in steps[0]
    assert t.artifact("httpx-input.txt").read_text().split() == ["a.acme.com", "b.acme.com"]


def test_ffuf_one_step_per_target_and_parse(make_ws, tmp_path):
    ws = make_ws("acme.com")
    t = mktask(
        ws, tmp_path, ["https://a.acme.com", "https://b.acme.com"],
        wordlist=str(tmp_path / "wl"),
    )
    (tmp_path / "wl").write_text("admin\nlogin\n")
    steps = FfufAdapter().build_steps(t, "ffuf")
    assert len(steps) == 2
    assert steps[0][steps[0].index("-u") + 1] == "https://a.acme.com/FUZZ"

    t.artifact("ffuf-0.json").write_text(
        json.dumps({"results": [{"url": "https://a.acme.com/admin", "status": 200, "length": 5}]})
    )
    eps = list(FfufAdapter().parse(tmp_path / "raw.txt", t))
    assert eps[0].url.endswith("/admin") and eps[0].status == 200


def test_feroxbuster_parses_ndjson(make_ws, tmp_path):
    ws = make_ws("acme.com")
    t = mktask(ws, tmp_path, ["https://a.acme.com"], wordlist=str(tmp_path / "wl"))
    (tmp_path / "wl").write_text("x\n")
    t.artifact("ferox-0.json").write_text(
        json.dumps({"type": "response", "url": "https://a.acme.com/x", "status": 301,
                    "content_length": 0}) + "\n"
        + json.dumps({"type": "statistics"}) + "\n"
    )
    eps = list(FeroxbusterAdapter().parse(tmp_path / "raw.txt", t))
    assert len(eps) == 1 and eps[0].status == 301


def test_gobuster_parses_text(make_ws, tmp_path):
    ws = make_ws("acme.com")
    t = mktask(ws, tmp_path, ["https://a.acme.com"], wordlist=str(tmp_path / "wl"))
    (tmp_path / "wl").write_text("x\n")
    t.artifact("gobuster-0.txt").write_text(
        "/admin                (Status: 200) [Size: 1234]\n"
        "/secret               (Status: 403) [Size: 9]\n"
        "junk line\n"
    )
    eps = list(GobusterAdapter().parse(tmp_path / "raw.txt", t))
    assert {e.url for e in eps} == {"https://a.acme.com/admin", "https://a.acme.com/secret"}
    assert {e.status for e in eps} == {200, 403}


def test_katana_parses_jsonl(make_ws, tmp_path):
    ws = make_ws("acme.com")
    t = mktask(ws, tmp_path, ["https://a.acme.com"])
    t.artifact("katana.jsonl").write_text(
        json.dumps({"request": {"method": "GET", "endpoint": "https://a.acme.com/x"},
                    "response": {"status_code": 200, "content_length": 10}}) + "\n"
    )
    eps = list(KatanaAdapter().parse(tmp_path / "raw.txt", t))
    assert eps[0].url == "https://a.acme.com/x" and eps[0].host == "a.acme.com"


def test_subfinder_parses_hosts(make_ws, tmp_path):
    ws = make_ws("acme.com")
    t = mktask(ws, tmp_path, ["acme.com"])
    t.artifact("subfinder.txt").write_text("a.acme.com\nb.acme.com\na.acme.com\n")
    hosts = list(SubfinderAdapter().parse(tmp_path / "raw.txt", t))
    assert sorted(h.hostname for h in hosts) == ["a.acme.com", "b.acme.com"]


def test_naabu_parses_jsonl(make_ws, tmp_path):
    ws = make_ws("acme.com")
    t = mktask(ws, tmp_path, ["a.acme.com"])
    t.artifact("naabu.jsonl").write_text(
        json.dumps({"host": "a.acme.com", "ip": "1.2.3.4", "port": 443}) + "\n"
    )
    svcs = list(NaabuAdapter().parse(tmp_path / "raw.txt", t))
    assert isinstance(svcs[0], Service) and svcs[0].port == 443


def test_dnsx_parses_jsonl(make_ws, tmp_path):
    ws = make_ws("acme.com")
    t = mktask(ws, tmp_path, ["a.acme.com"])
    t.artifact("dnsx.jsonl").write_text(
        json.dumps({"host": "a.acme.com", "a": ["1.1.1.1", "1.1.1.1"], "cname": ["cdn.x"]}) + "\n"
    )
    hosts = list(DnsxAdapter().parse(tmp_path / "raw.txt", t))
    assert hosts[0].ips == ["1.1.1.1"] and hosts[0].cnames == ["cdn.x"]


def test_whatweb_parses_json(make_ws, tmp_path):
    ws = make_ws("acme.com")
    t = mktask(ws, tmp_path, ["https://a.acme.com"])
    t.artifact("whatweb.json").write_text(
        json.dumps([{"target": "https://a.acme.com", "http_status": 200,
                     "plugins": {"nginx": {}, "Title": {"string": ["Hi"]}}}])
    )
    eps = list(WhatwebAdapter().parse(tmp_path / "raw.txt", t))
    assert eps[0].title == "Hi" and "nginx" in eps[0].tech


def test_wafw00f_tags_host(make_ws, tmp_path):
    ws = make_ws("acme.com")
    t = mktask(ws, tmp_path, ["https://a.acme.com"])
    t.artifact("wafw00f.json").write_text(
        json.dumps([{"url": "https://a.acme.com", "detected": True, "firewall": "Cloudflare"}])
    )
    hosts = list(Wafw00fAdapter().parse(tmp_path / "raw.txt", t))
    assert hosts[0].tags == ["waf:Cloudflare"]
