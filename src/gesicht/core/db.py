"""Derived SQLite index (``.gesicht/index.db``).

This database is a *cache*, never the source of truth. Everything in it can be
rebuilt from the plain-text/ndjson files in the workspace with ``gesicht reindex``.
If it is missing or corrupt, delete it and reindex.

Schema changes are applied by appending to ``MIGRATIONS`` - each entry runs once,
tracked by ``PRAGMA user_version``.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

MIGRATIONS: list[str] = [
    # v1 - core entities
    """
    CREATE TABLE host (
        id TEXT PRIMARY KEY,
        hostname TEXT NOT NULL UNIQUE,
        ips TEXT, cnames TEXT, sources TEXT,
        in_scope INTEGER, tags TEXT,
        first_seen TEXT, last_seen TEXT
    );
    CREATE TABLE service (
        id TEXT PRIMARY KEY,
        host TEXT, ip TEXT, port INTEGER, proto TEXT,
        name TEXT, product TEXT, version TEXT, banner TEXT, source TEXT
    );
    CREATE TABLE endpoint (
        id TEXT PRIMARY KEY,
        url TEXT NOT NULL, method TEXT, host TEXT, path_signature TEXT,
        status INTEGER, length INTEGER, content_type TEXT, title TEXT,
        tech TEXT, sources TEXT, screenshot_ref TEXT, in_scope INTEGER
    );
    CREATE TABLE param (
        id TEXT PRIMARY KEY,
        endpoint_id TEXT, name TEXT, location TEXT,
        example_value TEXT, reflected INTEGER, discovered_by TEXT
    );
    CREATE TABLE finding (
        number INTEGER PRIMARY KEY,
        slug TEXT, title TEXT, target TEXT, program TEXT,
        vuln_class TEXT, weakness TEXT, severity TEXT,
        cvss_vector TEXT, cvss_score REAL, status TEXT,
        found_via TEXT, h1_report_id TEXT, created TEXT, updated TEXT,
        path TEXT
    );
    CREATE TABLE tool_run (
        id TEXT PRIMARY KEY,
        tool TEXT, version TEXT, argv TEXT, targets TEXT, activity TEXT,
        scope_decision TEXT, fallback_for TEXT,
        started_at TEXT, ended_at TEXT, exit_code INTEGER,
        raw_stdout_path TEXT, raw_stderr_path TEXT, records_emitted INTEGER
    );
    CREATE INDEX ix_service_host ON service(host);
    CREATE INDEX ix_endpoint_host ON endpoint(host);
    CREATE INDEX ix_param_endpoint ON param(endpoint_id);
    """,
    # v2 - full-text search over finding bodies
    """
    CREATE VIRTUAL TABLE finding_fts USING fts5(number UNINDEXED, title, body);
    """,
    # v3 - raw scanner hits + finding dedup key
    """
    CREATE TABLE vuln (
        id TEXT PRIMARY KEY,
        scanner TEXT, signature TEXT, name TEXT, severity TEXT,
        url TEXT, host TEXT, cwe TEXT, cve TEXT, cvss_score REAL,
        cvss_vector TEXT, tags TEXT, description TEXT, extracted TEXT,
        reference TEXT, raw_ref TEXT, seen_at TEXT
    );
    CREATE INDEX ix_vuln_host ON vuln(host);
    CREATE INDEX ix_vuln_sev ON vuln(severity);
    ALTER TABLE finding ADD COLUMN source_key TEXT;
    """,
]


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    for version in range(current, len(MIGRATIONS)):
        conn.executescript(MIGRATIONS[version])
        conn.execute(f"PRAGMA user_version = {version + 1}")
    conn.commit()


def fresh(path: Path) -> sqlite3.Connection:
    """Drop any existing db and return a newly migrated connection."""
    if path.exists():
        path.unlink()
    for suffix in ("-wal", "-shm"):
        sidecar = path.with_name(path.name + suffix)
        if sidecar.exists():
            sidecar.unlink()
    return connect(path)
