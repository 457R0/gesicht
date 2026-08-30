from __future__ import annotations

import json

from typer.testing import CliRunner

from gesicht.cli import app

runner = CliRunner()


def _ws(root, monkeypatch):
    monkeypatch.chdir(root)
    runner.invoke(app, ["init", "acme.com"])
    monkeypatch.chdir(root / "acme.com")
    runner.invoke(app, ["scope", "add", "*.acme.com"])
    return root / "acme.com"


def _seed_hosts(ws, monkeypatch):
    monkeypatch.setattr(
        "gesicht.tools.internal.resolver.resolve", lambda h: (["1.2.3.4"], [])
    )
    runner.invoke(app, ["recon", "resolve", "a.acme.com", "b.acme.com"])


# -- gesicht q ------------------------------------------------------------------ #
def test_q_select(monkeypatch, workspaces_root):
    ws = _ws(workspaces_root, monkeypatch)
    _seed_hosts(ws, monkeypatch)
    r = runner.invoke(app, ["q", "select hostname from host order by hostname", "--json"])
    assert r.exit_code == 0, r.output
    assert json.loads(r.output.strip()) == [{"hostname": "a.acme.com"}, {"hostname": "b.acme.com"}]


def test_q_rejects_writes(monkeypatch, workspaces_root):
    ws = _ws(workspaces_root, monkeypatch)
    _seed_hosts(ws, monkeypatch)
    for bad in ("delete from host", "drop table host", "update host set hostname='x'"):
        r = runner.invoke(app, ["q", bad])
        assert r.exit_code == 1
        assert "read-only" in r.output


def test_q_tables(monkeypatch, workspaces_root):
    ws = _ws(workspaces_root, monkeypatch)
    _seed_hosts(ws, monkeypatch)
    r = runner.invoke(app, ["q", "--tables"])
    assert "host" in r.output and "finding" in r.output


def test_q_no_index(monkeypatch, workspaces_root):
    _ws(workspaces_root, monkeypatch)
    r = runner.invoke(app, ["q", "select 1"])
    assert r.exit_code == 1 and "no index" in r.output


# -- gesicht export ----------------------------------------------------------- #
def test_export_writes_file(monkeypatch, workspaces_root):
    ws = _ws(workspaces_root, monkeypatch)
    _seed_hosts(ws, monkeypatch)
    runner.invoke(app, ["finding", "new", "A bug", "-s", "low"])
    r = runner.invoke(app, ["export"])
    assert r.exit_code == 0, r.output
    exp = next((ws / "reports").glob("export-*.json"))
    data = json.loads(exp.read_text())
    assert data["program"] == "acme.com"
    assert len(data["host"]) == 2
    assert data["findings"][0]["title"] == "A bug"
    assert data["scope"]["rules"]


def test_export_stdout(monkeypatch, workspaces_root):
    _ws(workspaces_root, monkeypatch)
    r = runner.invoke(app, ["export", "--stdout"])
    assert r.exit_code == 0
    assert json.loads(r.output.strip())["program"] == "acme.com"


# -- gesicht notes ---------------------------------------------------------------- #
def test_notes_add_and_grep(monkeypatch, workspaces_root):
    ws = _ws(workspaces_root, monkeypatch)
    r = runner.invoke(app, ["notes", "add", "found an open", "redirect on /go", "-t", "idea"])
    assert r.exit_code == 0
    runner.invoke(app, ["notes", "add", "second note about auth"])
    md = (ws / "notes.md").read_text()
    assert "#idea" in md and "open redirect on /go" in md
    # both under one dated heading, newest first
    assert md.index("second note about auth") < md.index("open redirect on /go")

    r = runner.invoke(app, ["notes", "grep", "redirect"])
    assert "open redirect on /go" in r.output
    r = runner.invoke(app, ["notes", "grep", "nothing-here"])
    assert "no matches" in r.output


# -- gesicht config ------------------------------------------------------------- #
def test_config_set_get_unset(monkeypatch, workspaces_root):
    _ws(workspaces_root, monkeypatch)
    assert runner.invoke(app, ["config", "set", "h1_handle", "hunter"]).exit_code == 0
    assert runner.invoke(app, ["config", "get", "h1_handle"]).output.strip() == "hunter"
    assert runner.invoke(app, ["config", "set", "tool.subfinder", "/opt/sf"]).exit_code == 0
    assert runner.invoke(app, ["config", "get", "tool.subfinder"]).output.strip() == "/opt/sf"
    runner.invoke(app, ["config", "unset", "tool.subfinder"])
    assert runner.invoke(app, ["config", "get", "tool.subfinder"]).output.strip() == ""


def test_config_rejects_unknown_key(monkeypatch, workspaces_root):
    _ws(workspaces_root, monkeypatch)
    r = runner.invoke(app, ["config", "set", "bogus", "x"])
    assert r.exit_code == 1 and "unknown key" in r.output
