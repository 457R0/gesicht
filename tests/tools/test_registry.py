from __future__ import annotations

import gesicht.tools.registry as reg_mod
from gesicht.tools.base import ToolAdapter
from gesicht.tools.registry import Registry


class Dummy(ToolAdapter):
    name = "dummy"
    binaries = ("dummybin",)
    min_version = "2.0.0"

    def build_command(self, task, binary):
        return [binary]

    def parse(self, raw_path, task):
        return iter(())


def test_availability_missing(monkeypatch):
    monkeypatch.setattr(reg_mod, "find_binary", lambda *a, **k: None)
    reg = Registry()
    reg.register(Dummy())
    av = reg.availability(Dummy())
    assert not av.ok and not av.installed


def test_availability_version_gate(monkeypatch):
    monkeypatch.setattr(reg_mod, "find_binary", lambda *a, **k: "/usr/bin/dummybin")
    monkeypatch.setattr(reg_mod, "probe", lambda p: ("1.5.0", "dummy v1.5.0"))
    reg = Registry()
    reg.register(Dummy())
    av = reg.availability(Dummy())
    assert av.installed and not av.ok and "need >= 2.0.0" in av.note


def test_availability_ok(monkeypatch):
    monkeypatch.setattr(reg_mod, "find_binary", lambda *a, **k: "/usr/bin/dummybin")
    monkeypatch.setattr(reg_mod, "probe", lambda p: ("2.4.0", "dummy v2.4.0"))
    reg = Registry()
    reg.register(Dummy())
    assert reg.availability(Dummy()).ok


def test_availability_broken_wrapper(monkeypatch):
    monkeypatch.setattr(reg_mod, "find_binary", lambda *a, **k: "/usr/bin/dummybin")
    monkeypatch.setattr(reg_mod, "probe", lambda p: (None, "sudo: a terminal is required"))
    reg = Registry()
    reg.register(Dummy())
    av = reg.availability(Dummy())
    assert av.installed and not av.ok and "unattended" in av.note


def test_internal_adapter_always_ok():
    from tests.tools.conftest import FakeInternal

    reg = Registry()
    reg.register(FakeInternal())
    av = reg.availability(FakeInternal())
    assert av.ok and av.version == "builtin"


def test_httpx_collision_rejects_python_lib(monkeypatch):
    from gesicht.tools.base import ToolAdapter as TA

    class Httpx(TA):
        name = "httpx"
        binaries = ("httpx",)

        def build_command(self, task, binary):
            return [binary]

        def parse(self, raw_path, task):
            return iter(())

    monkeypatch.setattr(reg_mod, "find_binary", lambda name, **k: "/usr/bin/httpx")
    monkeypatch.setattr(reg_mod, "looks_like_pd_httpx", lambda p: False)
    reg = Registry()
    reg.register(Httpx())
    assert reg.availability(Httpx()).path is None  # python httpx is not accepted


def test_version_compare():
    assert reg_mod._cmp_version("1.2.3", "1.2.10") < 0
    assert reg_mod._cmp_version("2.0", "1.9.9") > 0
    assert reg_mod._cmp_version("3.11.1", "3.11.1") == 0


def test_load_builtin_adapters_is_idempotent():
    reg_mod.load_builtin_adapters()
    n = len(reg_mod.registry.all())
    reg_mod.load_builtin_adapters()
    assert len(reg_mod.registry.all()) == n
    assert {"amass", "nmap", "resolver", "prober", "wayback"} <= {
        a.name for a in reg_mod.registry.all()
    }
