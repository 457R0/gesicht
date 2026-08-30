from __future__ import annotations

from typer.testing import CliRunner

from gesicht.cli import app

runner = CliRunner()


def _setup(root, monkeypatch):
    monkeypatch.chdir(root)
    runner.invoke(app, ["init", "acme.com"])
    monkeypatch.chdir(root / "acme.com")
    runner.invoke(app, ["scope", "add", "*.acme.com"])
    runner.invoke(app, ["scope", "add", "acme.com"])


def test_probe_dry_run_falls_back_to_prober(workspaces_root, monkeypatch):
    _setup(workspaces_root, monkeypatch)
    # force httpx unavailable so the fallback chain is exercised deterministically
    monkeypatch.setattr("gesicht.tools.registry.find_binary", lambda *a, **k: None)
    r = runner.invoke(app, ["recon", "probe", "www.acme.com", "--dry-run"])
    assert r.exit_code == 0, r.output
    assert "prober" in r.output and "fallback for httpx" in r.output


def test_content_dry_run_shows_ffuf_command(workspaces_root, monkeypatch, tmp_path):
    _setup(workspaces_root, monkeypatch)
    wl = tmp_path / "wl.txt"
    wl.write_text("admin\n")
    r = runner.invoke(
        app,
        ["recon", "content", "https://www.acme.com", "--dry-run", "-W", str(wl), "--yes-active"],
    )
    assert r.exit_code == 0, r.output
    assert "FUZZ" in r.output and "ffuf" in r.output


def test_content_out_of_scope_blocked(workspaces_root, monkeypatch, tmp_path):
    _setup(workspaces_root, monkeypatch)
    wl = tmp_path / "wl.txt"
    wl.write_text("x\n")
    r = runner.invoke(
        app, ["recon", "content", "https://evil.com", "--dry-run", "-W", str(wl)]
    )
    assert r.exit_code == 2


def test_params_dry_run_falls_back(workspaces_root, monkeypatch):
    _setup(workspaces_root, monkeypatch)
    # force every external binary unavailable so the fallback chain is deterministic
    monkeypatch.setattr("gesicht.tools.registry.find_binary", lambda *a, **k: None)
    r = runner.invoke(app, ["recon", "params", "https://www.acme.com/p", "--dry-run"])
    assert r.exit_code == 0, r.output
    assert "parambrute" in r.output and "fallback for arjun" in r.output


def test_crawl_dry_run_falls_back_to_internal(workspaces_root, monkeypatch):
    _setup(workspaces_root, monkeypatch)
    monkeypatch.setattr("gesicht.tools.registry.find_binary", lambda *a, **k: None)
    r = runner.invoke(app, ["recon", "crawl", "https://www.acme.com", "--dry-run"])
    assert r.exit_code == 0, r.output
    assert "crawler" in r.output and "fallback for katana" in r.output


def test_recon_all_pipeline_dry_run(workspaces_root, monkeypatch):
    _setup(workspaces_root, monkeypatch)
    r = runner.invoke(app, ["recon", "all", "--dry-run", "--passive"])
    assert r.exit_code == 0, r.output
    assert "pipeline complete" in r.output


def test_recon_urls_passive(workspaces_root, monkeypatch):
    _setup(workspaces_root, monkeypatch)
    calls = {}
    def fake_fetch(domain, **k):
        calls["d"] = domain
        return ["https://a.acme.com/x?y=1"]

    monkeypatch.setattr("gesicht.tools.internal.cdx.fetch_urls", fake_fetch)
    r = runner.invoke(app, ["recon", "urls", "acme.com", "--json"])
    assert r.exit_code == 0, r.output
    assert '"urls": 1' in r.output
