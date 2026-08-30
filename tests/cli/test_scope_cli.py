from __future__ import annotations

from typer.testing import CliRunner

from gesicht.cli import app

runner = CliRunner()


def _init(root, monkeypatch, name="acme.com"):
    monkeypatch.chdir(root)
    assert runner.invoke(app, ["init", name]).exit_code == 0
    monkeypatch.chdir(root / name)


def test_add_list_check_roundtrip(workspaces_root, monkeypatch):
    _init(workspaces_root, monkeypatch)
    assert runner.invoke(app, ["scope", "add", "*.acme.com"]).exit_code == 0
    assert runner.invoke(app, ["scope", "add", "secret.acme.com", "--out"]).exit_code == 0

    r = runner.invoke(app, ["scope", "list", "--json"])
    assert r.exit_code == 0
    assert "*.acme.com" in r.output

    r = runner.invoke(app, ["scope", "check", "www.acme.com"])
    assert r.exit_code == 0 and "IN" in r.output

    r = runner.invoke(app, ["scope", "check", "secret.acme.com"])
    assert r.exit_code == 2 and "OUT" in r.output

    r = runner.invoke(app, ["scope", "check", "unrelated.io"])
    assert r.exit_code == 2 and "fail-closed" in r.output


def test_scope_cache_file_written(workspaces_root, monkeypatch):
    _init(workspaces_root, monkeypatch)
    runner.invoke(app, ["scope", "add", "*.acme.com"])
    cache = workspaces_root / "acme.com" / ".gesicht" / "scope.json"
    assert cache.is_file()
    assert "acme.com" in cache.read_text()


def test_lint_exits_1_on_error(workspaces_root, monkeypatch):
    _init(workspaces_root, monkeypatch)
    runner.invoke(app, ["scope", "add", "*.com"])
    r = runner.invoke(app, ["scope", "lint"])
    assert r.exit_code == 1
    assert "ERROR" in r.output


def test_import_from_file(workspaces_root, monkeypatch, tmp_path):
    _init(workspaces_root, monkeypatch)
    export = tmp_path / "scope.json"
    export.write_text(
        '{"data":[{"attributes":{"asset_identifier":"*.acme.com","asset_type":"WILDCARD",'
        '"eligible_for_submission":true}}]}'
    )
    r = runner.invoke(app, ["scope", "import", "--file", str(export)])
    assert r.exit_code == 0, r.output
    assert "imported 1 rule" in r.output
    assert "*.acme.com" in (workspaces_root / "acme.com" / "scope.md").read_text()


def test_import_rejects_multiple_sources(workspaces_root, monkeypatch):
    _init(workspaces_root, monkeypatch)
    r = runner.invoke(app, ["scope", "import", "--stdin", "--h1", "acme"])
    assert r.exit_code == 1
    assert "exactly one" in r.output
