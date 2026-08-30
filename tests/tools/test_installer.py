from __future__ import annotations

from dataclasses import dataclass

from gesicht.tools import installer
from gesicht.tools.base import InstallSpec


@dataclass
class FakeProc:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


def test_plan_order_and_go_bootstrap():
    spec = InstallSpec(apt="p", pipx="p", go="mod@latest")
    with_go = installer.plan_methods(spec, have_go=True)
    assert [m.kind for m in with_go] == ["apt", "pipx", "go"]
    assert len(with_go[-1].commands) == 1  # just `go install`

    without_go = installer.plan_methods(spec, have_go=False)
    assert without_go[-1].commands[0][:3] == ["sudo", "apt-get", "install"]
    assert without_go[-1].commands[1][:2] == ["go", "install"]


def test_first_method_success_stops(monkeypatch):
    calls = []

    def runner(cmd, **kw):
        calls.append(cmd)
        return FakeProc(0)

    monkeypatch.setattr(installer, "find_binary", lambda b: "/managed/bin/tool")
    out = installer.install(
        "tool", InstallSpec(apt="tool", pipx="tool"),
        runner=runner, confirm=lambda n, c: True, have_go=True,
    )
    assert out.ok and out.method == "apt"
    assert len(calls) == 1  # pipx never tried


def test_falls_through_to_pipx_on_apt_failure(monkeypatch):
    def runner(cmd, **kw):
        if cmd[:2] == ["sudo", "apt-get"]:
            return FakeProc(100, stderr="E: package not found")
        return FakeProc(0)

    # apt fails at the runner (returncode 100) before find_binary is consulted;
    # after pipx runs, the binary is present.
    monkeypatch.setattr(installer, "find_binary", lambda b: "/managed/tool")
    out = installer.install(
        "tool", InstallSpec(apt="tool", pipx="tool"),
        runner=runner, confirm=lambda n, c: True, have_go=True,
    )
    assert out.ok and out.method == "pipx"


def test_no_spec_is_graceful():
    assert installer.install("x", None).ok is False
    assert "no known way" in installer.install("x", None).message


def test_declined_methods_are_reported(monkeypatch):
    monkeypatch.setattr(installer, "find_binary", lambda b: None)
    out = installer.install(
        "tool", InstallSpec(apt="tool"),
        runner=lambda *a, **k: FakeProc(0), confirm=lambda n, c: False, have_go=True,
    )
    assert not out.ok and "declined" in out.message
