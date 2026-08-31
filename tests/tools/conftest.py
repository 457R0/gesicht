from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from gesicht.core.models import Activity, Host
from gesicht.tools.base import InstallSpec, Task, ToolAdapter
from gesicht.tools.registry import Registry


class FakeInternal(ToolAdapter):
    name = "fake_internal"
    category = "recon"
    activity = Activity.PASSIVE
    internal = True

    def execute(self, task: Task, raw_path: Path) -> Iterator[Host]:
        raw_path.write_text("fake raw\n")
        for t in task.targets:
            yield Host(hostname=f"sub.{t}", sources=["fake_internal"])


class FakeActiveInternal(FakeInternal):
    name = "fake_active"
    activity = Activity.ACTIVE


class FakeMissing(ToolAdapter):
    name = "fake_missing"
    binaries = ("gesicht-nonexistent-binary-xyz",)
    category = "recon"
    activity = Activity.PASSIVE
    fallbacks = ("fake_internal",)
    install = InstallSpec(apt="fakepkg", pipx="fakepkg", go="example.com/fakepkg@latest")

    def build_command(self, task, binary):  # pragma: no cover - never reached
        return [binary, *task.targets]

    def parse(self, raw_path, task):  # pragma: no cover
        return iter(())


class FakeEcho(ToolAdapter):
    """Exercises the real subprocess path with a harmless command."""

    name = "fake_echo"
    binaries = ("echo",)
    category = "recon"
    activity = Activity.PASSIVE

    def build_command(self, task: Task, binary: str) -> list[str]:
        return [binary, "hello", *task.targets]

    def parse(self, raw_path: Path, task: Task) -> Iterator[Host]:
        text = raw_path.read_text().strip()
        if text:
            yield Host(hostname="echoed.example.com", sources=["fake_echo"])


class FakeSleep(ToolAdapter):
    """A slow command, for exercising streaming/timeout behavior."""

    name = "fake_sleep"
    binaries = ("sh",)
    category = "recon"
    activity = Activity.PASSIVE

    def build_command(self, task: Task, binary: str) -> list[str]:
        return [binary, "-c", "sleep 1"]

    def parse(self, raw_path: Path, task: Task) -> Iterator[Host]:
        return iter(())


@pytest.fixture
def fake_registry() -> Registry:
    reg = Registry()
    for a in (FakeInternal(), FakeActiveInternal(), FakeMissing(), FakeEcho(), FakeSleep()):
        reg.register(a)
    return reg
