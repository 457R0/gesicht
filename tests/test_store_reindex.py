from __future__ import annotations

from gesicht.core.models import Endpoint, Host, Param, ParamLoc, Service
from gesicht.core.store import Store


def test_add_records_routes_by_type_and_dedupes(make_ws):
    ws = make_ws("acme.com")
    store = Store(ws)
    ep = Endpoint(url="https://acme.com/a", host="acme.com")
    store.add_records(
        [
            Host(hostname="a.acme.com"),
            Host(hostname="a.acme.com"),  # dup
            Service(host="a.acme.com", ip="1.1.1.1", port=443),
            ep,
            Param(endpoint_id=ep.id, name="q", location=ParamLoc.QUERY),
        ]
    )
    s = store.summary()
    assert s == {
        "hosts": 1, "services": 1, "urls": 1, "params": 1,
        "vulns": 0, "findings": 0, "runs": 0,
    }
    txt = (ws.root / "parsed" / "hosts.txt").read_text().split()
    assert txt == ["a.acme.com"]


def test_reindex_rebuilds_identical_counts(make_ws):
    ws = make_ws("acme.com")
    store = Store(ws)
    store.add_records(
        [
            Host(hostname="a.acme.com"),
            Host(hostname="b.acme.com"),
            Service(host="a.acme.com", ip="1.1.1.1", port=80),
        ]
    )
    before = store.summary()
    assert before["hosts"] == 2

    ws.index_db.unlink()
    counts = store.reindex()
    assert counts["hosts"] == 2 and counts["services"] == 1
    assert store.summary()["hosts"] == before["hosts"]
    assert store.summary()["services"] == before["services"]


def test_reindex_replays_tool_runs(make_ws):
    from gesicht.core.models import Activity, ToolRun

    ws = make_ws("acme.com")
    store = Store(ws)
    store.record_run(
        ToolRun(tool="amass", argv=["amass"], targets=["acme.com"], activity=Activity.PASSIVE)
    )
    ws.index_db.unlink()
    counts = store.reindex()
    assert counts["runs"] == 1
    assert store.summary()["runs"] == 1
