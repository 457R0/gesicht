from __future__ import annotations

from typer.testing import CliRunner

from gesicht.cli import app

runner = CliRunner()


def _init_with_scope(root, monkeypatch, rules=("*.acme.com",)):
    monkeypatch.chdir(root)
    assert runner.invoke(app, ["init", "acme.com"]).exit_code == 0
    monkeypatch.chdir(root / "acme.com")
    for r in rules:
        runner.invoke(app, ["scope", "add", r])


def test_recon_resolve_stores_hosts(workspaces_root, monkeypatch):
    _init_with_scope(workspaces_root, monkeypatch)
    # avoid real DNS
    monkeypatch.setattr(
        "gesicht.tools.internal.resolver.resolve",
        lambda host: (["93.184.216.34"], []) if "acme.com" in host else ([], []),
    )
    r = runner.invoke(app, ["recon", "resolve", "www.acme.com", "--json"])
    assert r.exit_code == 0, r.output
    assert '"hosts": 1' in r.output
    hosts_txt = workspaces_root / "acme.com" / "parsed" / "hosts.txt"
    assert hosts_txt.read_text().strip() == "www.acme.com"


def test_recon_resolve_blocks_out_of_scope(workspaces_root, monkeypatch):
    _init_with_scope(workspaces_root, monkeypatch)
    monkeypatch.setattr("gesicht.tools.internal.resolver.resolve", lambda h: (["1.2.3.4"], []))
    r = runner.invoke(app, ["recon", "resolve", "evil.com"])
    assert r.exit_code == 2
    log = (workspaces_root / "acme.com" / ".gesicht" / "violations.log").read_text()
    assert "evil.com" in log


def test_recon_subs_dry_run_shows_plan(workspaces_root, monkeypatch):
    _init_with_scope(workspaces_root, monkeypatch)
    r = runner.invoke(app, ["recon", "subs", "--dry-run", "--json"])
    assert r.exit_code == 0, r.output
    assert '"argv"' in r.output
    assert "acme.com" in r.output


def test_recon_subs_default_targets_from_scope(workspaces_root, monkeypatch):
    _init_with_scope(workspaces_root, monkeypatch)
    r = runner.invoke(app, ["recon", "subs", "--dry-run"])
    assert r.exit_code == 0
    assert "acme.com" in r.output  # derived the apex from *.acme.com


def test_tools_list_runs(workspaces_root, monkeypatch):
    monkeypatch.chdir(workspaces_root)
    r = runner.invoke(app, ["tools", "list", "--json"])
    assert r.exit_code == 0
    assert '"name": "amass"' in r.output
    assert '"name": "resolver"' in r.output


def test_tools_doctor_runs(workspaces_root, monkeypatch):
    monkeypatch.chdir(workspaces_root)
    r = runner.invoke(app, ["tools", "doctor"])
    assert r.exit_code == 0
    assert "managed bin dir" in r.output


def test_reindex_roundtrip_via_cli(workspaces_root, monkeypatch):
    _init_with_scope(workspaces_root, monkeypatch)
    monkeypatch.setattr(
        "gesicht.tools.internal.resolver.resolve", lambda h: (["93.184.216.34"], [])
    )
    runner.invoke(app, ["recon", "resolve", "www.acme.com", "a.acme.com"])
    db = workspaces_root / "acme.com" / ".gesicht" / "index.db"
    db.unlink()
    r = runner.invoke(app, ["reindex", "--json"])
    assert r.exit_code == 0
    assert '"hosts": 2' in r.output
