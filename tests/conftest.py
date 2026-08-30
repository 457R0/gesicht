from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Point config/data dirs and the workspaces root at a throwaway location."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local/share"))
    root = tmp_path / "engagements"
    root.mkdir()
    monkeypatch.setenv("GESICHT_HOME", str(root))
    monkeypatch.delenv("GESICHT_WORKSPACE", raising=False)
    # `gesicht finding edit` opens $EDITOR - make it a harmless no-op in tests
    monkeypatch.setenv("EDITOR", "true")
    # the process-wide tool registry caches availability; reset between tests
    from gesicht.tools.registry import registry as _reg

    _reg.clear_cache()
    yield root


@pytest.fixture
def workspaces_root(isolated_home) -> Path:
    return isolated_home


@pytest.fixture
def make_ws(workspaces_root, monkeypatch):
    from gesicht.core import workspace as ws_mod

    def _make(target: str = "example.com", **kw):
        monkeypatch.chdir(workspaces_root)
        return ws_mod.create(target, **kw)

    return _make
