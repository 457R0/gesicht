from __future__ import annotations

from gesicht.core.models import Endpoint, Param
from gesicht.tools.base import Task
from gesicht.tools.internal import crawler as crawler_mod
from gesicht.tools.internal import parambrute as pb_mod
from gesicht.tools.internal.crawler import CrawlerAdapter
from gesicht.tools.internal.parambrute import ParamBruteAdapter


def mktask(ws, tmp_path, targets, **opts):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return Task(targets=list(targets), workspace=ws, outdir=out, options=opts)


def test_crawler_stays_on_registrable_domain(make_ws, tmp_path, monkeypatch):
    ws = make_ws("acme.com")
    pages = {
        "https://acme.com/": (200, '<a href="/about">a</a><a href="https://evil.com/x">e</a>'
                              '<a href="https://sub.acme.com/deep">s</a>', 60),
        "https://acme.com/about": (200, "<html>done</html>", 15),
        "https://sub.acme.com/deep": (200, "leaf", 4),
    }
    monkeypatch.setattr(crawler_mod, "_fetch", lambda url, to: pages.get(url, (None, "", 0)))

    t = mktask(ws, tmp_path, ["https://acme.com/"], depth=2)
    eps = list(CrawlerAdapter().execute(t, tmp_path / "raw.txt"))
    urls = {e.url for e in eps}
    assert "https://acme.com/about" in urls
    assert "https://sub.acme.com/deep" in urls  # same registrable domain
    assert not any("evil.com" in u for u in urls)  # off-domain excluded
    assert all(isinstance(e, Endpoint) for e in eps)


def test_crawler_respects_page_cap(make_ws, tmp_path, monkeypatch):
    ws = make_ws("acme.com")

    def fake_fetch(url, to):
        n = url.rstrip("/").rsplit("/", 1)[-1] or "0"
        nxt = int(n) + 1 if n.isdigit() else 1
        return 200, f'<a href="https://acme.com/{nxt}">x</a>', 30

    monkeypatch.setattr(crawler_mod, "_fetch", fake_fetch)
    t = mktask(ws, tmp_path, ["https://acme.com/0"], depth=99, max_pages=5)
    eps = list(CrawlerAdapter().execute(t, tmp_path / "raw.txt"))
    assert len(eps) <= 5


def test_parambrute_flags_reflected_and_length_shift(make_ws, tmp_path, monkeypatch):
    ws = make_ws("acme.com")
    (tmp_path / "wl").write_text("id\ndebug\nnope\n")

    def fake_get(url, timeout):
        if "id=" in url:
            return 200, "base" + "x" * 100  # big length shift
        if "debug=" in url:
            return 200, "reflected gesichtw00t1234 here"  # reflection
        if "nope=" in url:
            return 200, "base"  # unchanged
        return 200, "base"  # baseline

    monkeypatch.setattr(pb_mod, "_get", fake_get)
    t = mktask(ws, tmp_path, ["https://acme.com/page"], wordlist=str(tmp_path / "wl"))
    recs = list(ParamBruteAdapter().execute(t, tmp_path / "raw.txt"))
    params = [r for r in recs if isinstance(r, Param)]
    found = {p.name: p for p in params}
    assert set(found) == {"id", "debug"}
    assert found["debug"].reflected is True
    assert found["id"].reflected is False


def test_parambrute_skips_unreachable(make_ws, tmp_path, monkeypatch):
    ws = make_ws("acme.com")
    (tmp_path / "wl").write_text("id\n")
    monkeypatch.setattr(pb_mod, "_get", lambda u, t: (None, ""))
    t = mktask(ws, tmp_path, ["https://down.acme.com/"], wordlist=str(tmp_path / "wl"))
    recs = list(ParamBruteAdapter().execute(t, tmp_path / "raw.txt"))
    assert recs == []
