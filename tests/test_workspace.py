from __future__ import annotations

import pytest

from gesicht.core import workspace as ws_mod
from gesicht.core.errors import WorkspaceNotFoundError


def test_create_builds_hg_layout_and_gesicht_dir(make_ws):
    ws = make_ws("acme.com")
    assert ws.slug == "acme.com"
    for d in ("recon/subdomains", "scans/nuclei", "content", "findings", "reports"):
        assert (ws.root / d).is_dir()
    for f in ("README.md", "scope.md", "notes.md"):
        assert (ws.root / f).is_file()
    assert ws.gesicht_dir.is_dir()
    assert (ws.gesicht_dir / "runs").is_dir()
    assert ws.violations_log.is_file()


def test_create_is_idempotent(make_ws):
    ws1 = make_ws("acme.com")
    (ws1.root / "notes.md").write_text("my notes")
    ws2 = make_ws("acme.com")
    assert ws1.root == ws2.root
    assert (ws2.root / "notes.md").read_text() == "my notes"  # not clobbered


def test_slug_matches_hg_rules(make_ws):
    ws = make_ws("Acme Web App")
    assert ws.slug == "Acme_Web_App"


def test_discover_walks_up_from_cwd(make_ws, monkeypatch):
    ws = make_ws("acme.com")
    nested = ws.root / "recon" / "urls"
    monkeypatch.chdir(nested)
    found = ws_mod.discover()
    assert found.root == ws.root


def test_discover_prefers_explicit_then_env(make_ws, monkeypatch):
    a = make_ws("a.com")
    b = make_ws("b.com")
    monkeypatch.chdir(a.root)
    monkeypatch.setenv("GESICHT_WORKSPACE", str(b.root))
    assert ws_mod.discover().root == b.root  # env beats cwd
    assert ws_mod.discover(explicit=str(a.root)).root == a.root  # explicit beats env


def test_discover_raises_when_nothing_found(workspaces_root, monkeypatch):
    monkeypatch.chdir(workspaces_root)
    with pytest.raises(WorkspaceNotFoundError):
        ws_mod.discover()


def test_list_workspaces(make_ws):
    make_ws("a.com")
    make_ws("b.com")
    slugs = {w.slug for w in ws_mod.list_workspaces()}
    assert slugs == {"a.com", "b.com"}


def test_lock_is_reentrant_across_context(make_ws):
    ws = make_ws("acme.com")
    with ws.lock():
        pass
    with ws.lock():  # second acquisition after release must not hang
        assert (ws.gesicht_dir / "lock").exists()
