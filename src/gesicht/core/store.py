"""Repository layer: flat files are the source of truth, SQLite is a derived index.

Write path for a normalized record:
  1. append JSON line to ``parsed/<stream>.ndjson`` (append-only, immutable history)
  2. refresh the greppable projection ``parsed/<stream>.txt`` (sorted, de-duped)
  3. upsert the row into ``.gesicht/index.db``

``parsed/`` sits next to hg's folders. Nothing here mutates the raw tool output
under ``recon/`` / ``scans/`` / ``content/``.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import fields

from . import db as _db
from .models import (
    Activity,
    Endpoint,
    Host,
    Param,
    ParamLoc,
    Service,
    ToolRun,
    VulnHit,
    to_dict,
)
from .workspace import Workspace

# stream name -> (dataclass, table, projection key -> str)
_STREAMS = {
    "hosts": (Host, "host", lambda h: h["hostname"]),
    "services": (Service, "service", lambda s: f"{s['host']}\t{s['ip']}:{s['port']}/{s['proto']}"),
    "urls": (Endpoint, "endpoint", lambda e: e["url"]),
    "params": (Param, "param", lambda p: f"{p['endpoint_id']}\t{p['location']}\t{p['name']}"),
    "vulns": (
        VulnHit,
        "vuln",
        lambda v: f"{v['severity']}\t{v['scanner']}\t{v['name']}\t{v['url'] or v['host']}",
    ),
}
_TYPE_TO_STREAM = {
    Host: "hosts", Service: "services", Endpoint: "urls",
    Param: "params", VulnHit: "vulns",
}


def stream_for(record: object) -> str | None:
    return _TYPE_TO_STREAM.get(type(record))


def _rebuild(cls, data: dict):
    names = {f.name for f in fields(cls)}
    kw = {k: v for k, v in data.items() if k in names}
    if cls is Param and "location" in kw:
        kw["location"] = ParamLoc(kw["location"])
    if cls is ToolRun and "activity" in kw:
        kw["activity"] = Activity(kw["activity"])
    return cls(**kw)


class Store:
    def __init__(self, ws: Workspace) -> None:
        self.ws = ws
        self.parsed = ws.root / "parsed"

    # -- connection ---------------------------------------------------------- #
    def conn(self) -> sqlite3.Connection:
        return _db.connect(self.ws.index_db)

    # -- generic record write --------------------------------------------- #
    def add(self, stream: str, records: Iterable[object]) -> int:
        if stream not in _STREAMS:
            raise KeyError(f"unknown stream: {stream}")
        _cls, table, projkey = _STREAMS[stream]
        records = list(records)
        if not records:
            return 0
        self.parsed.mkdir(parents=True, exist_ok=True)
        ndjson = self.parsed / f"{stream}.ndjson"
        rows = [to_dict(r) for r in records]

        with ndjson.open("a") as fh:
            for row in rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")

        self._refresh_projection(stream, projkey)

        conn = self.conn()
        try:
            with conn:
                for rec, row in zip(records, rows, strict=True):
                    self._upsert(conn, table, rec, row)
        finally:
            conn.close()
        return len(rows)

    def add_records(self, records: Iterable[object]) -> dict[str, int]:
        """Route a mixed batch of model instances to their streams."""
        buckets: dict[str, list[object]] = {}
        for rec in records:
            s = stream_for(rec)
            if s is None:
                continue
            buckets.setdefault(s, []).append(rec)
        return {s: self.add(s, recs) for s, recs in buckets.items()}

    def _refresh_projection(self, stream: str, projkey) -> None:
        ndjson = self.parsed / f"{stream}.ndjson"
        seen: set[str] = set()
        for line in ndjson.read_text().splitlines():
            if line.strip():
                seen.add(projkey(json.loads(line)))
        txt = self.parsed / f"{stream}.txt"
        tmp = txt.with_suffix(".txt.tmp")
        tmp.write_text("\n".join(sorted(seen)) + ("\n" if seen else ""))
        tmp.replace(txt)

    @staticmethod
    def _upsert(conn: sqlite3.Connection, table: str, rec: object, row: dict) -> None:
        table_cols = _table_columns(conn, table)
        pk = "number" if table == "finding" else "id"
        cols: list[str] = []
        vals: list[object] = []
        for f in fields(rec):
            if f.name not in table_cols:
                continue
            cols.append(f.name)
            v = row[f.name]
            vals.append(json.dumps(v) if isinstance(v, (list, dict)) else v)
        # a computed ``id`` property is not a dataclass field - add it explicitly
        if pk == "id" and "id" not in cols and hasattr(rec, "id"):
            cols.append("id")
            vals.append(rec.id)  # type: ignore[attr-defined]

        placeholders = ", ".join("?" for _ in cols)
        updates = ", ".join(f"{c}=excluded.{c}" for c in cols if c != pk)
        sql = f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders})"
        sql += f" ON CONFLICT({pk}) DO UPDATE SET {updates}" if updates else ""
        conn.execute(sql, vals)

    # -- tool runs --------------------------------------------------------- #
    def record_run(self, run: ToolRun) -> None:
        (self.ws.runs_dir).mkdir(parents=True, exist_ok=True)
        stamp = run.started_at.replace(":", "").replace("-", "")
        path = self.ws.runs_dir / f"{stamp}__{run.tool}.json"
        path.write_text(json.dumps(to_dict(run), indent=2, sort_keys=True))
        conn = self.conn()
        try:
            row = to_dict(run)
            cols = [f.name for f in fields(run)] + ["id"]
            row["id"] = run.id
            with conn:
                conn.execute(
                    f"INSERT OR REPLACE INTO tool_run ({', '.join(cols)}) "
                    f"VALUES ({', '.join('?' for _ in cols)})",
                    [json.dumps(row[c]) if isinstance(row[c], list) else row[c] for c in cols],
                )
        finally:
            conn.close()

    # -- read side (used by `gesicht status`) ------------------------------- #
    def summary(self) -> dict[str, int]:
        out = {
            "hosts": 0, "services": 0, "urls": 0, "params": 0,
            "vulns": 0, "findings": 0, "runs": 0,
        }
        if not self.ws.index_db.exists():
            return out
        conn = self.conn()
        try:
            for table, key in (
                ("host", "hosts"), ("service", "services"), ("endpoint", "urls"),
                ("param", "params"), ("vuln", "vulns"),
                ("finding", "findings"), ("tool_run", "runs"),
            ):
                out[key] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        finally:
            conn.close()
        return out

    # -- reindex --------------------------------------------------------- #
    def reindex(self) -> dict[str, int]:
        """Rebuild .gesicht/index.db from scratch out of parsed/*.ndjson + runs/."""
        conn = _db.fresh(self.ws.index_db)
        counts: dict[str, int] = {}
        try:
            with conn:
                for stream, (cls, table, _pk) in _STREAMS.items():
                    ndjson = self.parsed / f"{stream}.ndjson"
                    if not ndjson.is_file():
                        continue
                    n = 0
                    for line in ndjson.read_text().splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        data = json.loads(line)
                        rec = _rebuild(cls, data)
                        self._upsert(conn, table, rec, to_dict(rec))
                        n += 1
                    counts[stream] = n
                runs = sorted(self.ws.runs_dir.glob("*.json")) if self.ws.runs_dir.is_dir() else []
                for rp in runs:
                    data = json.loads(rp.read_text())
                    run = _rebuild(ToolRun, data)
                    cols = [f.name for f in fields(run)] + ["id"]
                    row = to_dict(run)
                    row["id"] = run.id
                    conn.execute(
                        f"INSERT OR REPLACE INTO tool_run ({', '.join(cols)}) "
                        f"VALUES ({', '.join('?' for _ in cols)})",
                        [json.dumps(row[c]) if isinstance(row[c], list) else row[c] for c in cols],
                    )
                counts["runs"] = len(runs)
        finally:
            conn.close()
        # refresh the greppable projections too
        for stream, (_cls, _t, pk) in _STREAMS.items():
            if (self.parsed / f"{stream}.ndjson").is_file():
                self._refresh_projection(stream, pk)
        # findings live as Markdown files, not ndjson - rebuild their rows too
        from .findings import FindingStore

        counts["findings"] = FindingStore(self.ws).reindex()
        return counts


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
