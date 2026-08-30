"""Auto-install a missing tool: apt -> pipx -> go, in that order.

Each method is offered as a group of shell commands the user confirms before
anything runs (apt and the Go bootstrap need sudo). Go tools install into
gesicht's managed bin dir so we never write to ``/usr``. On the first method that
makes the binary resolvable, we stop.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field

from ..core.config import MANAGED_BIN
from .base import InstallSpec
from .registry import find_binary

Runner = Callable[..., "subprocess.CompletedProcess"]
ConfirmFn = Callable[[str, list[list[str]]], bool]
LogFn = Callable[[str], None]


@dataclass(slots=True)
class Method:
    kind: str  # "apt" | "pipx" | "go"
    commands: list[list[str]]
    env: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class InstallOutcome:
    ok: bool
    method: str | None = None
    message: str = ""


def _default_confirm(name: str, commands: list[list[str]]) -> bool:
    return False


def plan_methods(spec: InstallSpec, *, have_go: bool) -> list[Method]:
    methods: list[Method] = []
    if spec.apt:
        methods.append(Method("apt", [["sudo", "apt-get", "install", "-y", spec.apt]]))
    if spec.pipx:
        methods.append(Method("pipx", [["pipx", "install", spec.pipx]]))
    if spec.go:
        cmds: list[list[str]] = []
        if not have_go:
            cmds.append(["sudo", "apt-get", "install", "-y", "golang-go"])
        cmds.append(["go", "install", spec.go])
        methods.append(Method("go", cmds, env={"GOBIN": str(MANAGED_BIN)}))
    return methods


def install(
    name: str,
    spec: InstallSpec | None,
    *,
    runner: Runner | None = None,
    confirm: ConfirmFn | None = None,
    log: LogFn | None = None,
    have_go: bool | None = None,
) -> InstallOutcome:
    if spec is None or not spec.methods():
        return InstallOutcome(False, message=f"no known way to install '{name}'")

    runner = runner or subprocess.run
    confirm = confirm or _default_confirm
    log = log or (lambda _m: None)
    if have_go is None:
        have_go = shutil.which("go") is not None
    MANAGED_BIN.mkdir(parents=True, exist_ok=True)

    target_binary = spec.binary or name
    errors: list[str] = []

    for method in plan_methods(spec, have_go=have_go):
        if not confirm(name, method.commands):
            errors.append(f"{method.kind}: declined")
            continue
        env = {**os.environ, **method.env} if method.env else None
        failed = False
        for cmd in method.commands:
            log(f"$ {' '.join(cmd)}")
            try:
                proc = runner(cmd, env=env, capture_output=True, text=True)
            except OSError as e:
                errors.append(f"{method.kind}: {e}")
                failed = True
                break
            if proc.returncode != 0:
                tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-1:] or [""]
                errors.append(f"{method.kind}: exit {proc.returncode} - {tail[0]}")
                failed = True
                break
        if failed:
            continue
        if find_binary(target_binary):
            return InstallOutcome(True, method=method.kind)
        errors.append(f"{method.kind}: ran, but '{target_binary}' still not on PATH")

    return InstallOutcome(False, message="; ".join(errors) or "all methods failed")
