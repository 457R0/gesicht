from __future__ import annotations

from typer.testing import CliRunner

from gesicht.cli import app

runner = CliRunner()


def test_init_then_status(workspaces_root, monkeypatch):
    monkeypatch.chdir(workspaces_root)
    r = runner.invoke(app, ["init", "example.com"])
    assert r.exit_code == 0, r.output
    assert (workspaces_root / "example.com" / ".gesicht").is_dir()

    monkeypatch.chdir(workspaces_root / "example.com")
    r = runner.invoke(app, ["status", "--json"])
    assert r.exit_code == 0, r.output
    assert '"slug": "example.com"' in r.output


def test_status_without_workspace_exits_1(workspaces_root, monkeypatch):
    monkeypatch.chdir(workspaces_root)
    r = runner.invoke(app, ["status"])
    assert r.exit_code == 1
    assert "no workspace" in r.output.lower()


def test_ls_marks_current(workspaces_root, monkeypatch):
    monkeypatch.chdir(workspaces_root)
    runner.invoke(app, ["init", "a.com"])
    runner.invoke(app, ["init", "b.com"])
    r = runner.invoke(app, ["ls"])
    assert r.exit_code == 0
    assert "a.com" in r.output and "b.com" in r.output
