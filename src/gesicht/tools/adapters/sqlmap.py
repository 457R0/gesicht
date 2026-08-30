"""sqlmap - SQL injection testing. ACTIVE and intrusive: double-confirmed by the
CLI, and data-extraction flags (--dump etc.) only run with ``exploit=True``."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from ...core.models import Activity, VulnHit
from ..base import InstallSpec, Task, ToolAdapter

_PARAM_RE = re.compile(r"^Parameter:\s*(?P<name>.+?)\s*\((?P<place>[^)]+)\)", re.M)
_TITLE_RE = re.compile(r"^\s*Title:\s*(?P<title>.+)$", re.M)
_TYPE_RE = re.compile(r"^\s*Type:\s*(?P<type>.+)$", re.M)
_DBMS_RE = re.compile(r"back-end DBMS:\s*(?P<dbms>.+)")


class SqlmapAdapter(ToolAdapter):
    name = "sqlmap"
    binaries = ("sqlmap",)
    category = "vuln"
    activity = Activity.ACTIVE
    extra_confirm = True
    install = InstallSpec(apt="sqlmap", pipx="sqlmap")

    def build_steps(self, task: Task, binary: str) -> list[list[str]]:
        outdir = task.artifact("sqlmap-out")
        outdir.mkdir(parents=True, exist_ok=True)
        steps = []
        for target in task.targets:
            argv = [
                binary, "-u", target, "--batch", "--disable-coloring",
                f"--output-dir={outdir}", "-v", "0",
                "--level", str(int(task.opt("level", 1))),
                "--risk", str(int(task.opt("risk", 1))),
            ]
            if task.opt("data"):
                argv += ["--data", str(task.opt("data"))]
            if task.opt("exploit"):
                # only when the operator has explicitly asked to extract data
                argv += ["--dbs", "--current-user", "--current-db"]
            argv += task.extra_args
            steps.append(argv)
        return steps

    def parse(self, raw_path: Path, task: Task) -> Iterator[VulnHit]:
        text = raw_path.read_text() if raw_path.is_file() else ""
        dbms = _DBMS_RE.search(text)
        dbms_s = dbms.group("dbms").strip() if dbms else None
        titles = [m.group("title").strip() for m in _TITLE_RE.finditer(text)]
        types = [m.group("type").strip() for m in _TYPE_RE.finditer(text)]

        targets = task.targets
        for m in _PARAM_RE.finditer(text):
            name = m.group("name")
            place = m.group("place")
            yield VulnHit(
                scanner="sqlmap",
                signature=f"sqli:{place}:{name}",
                name=f"SQL injection in parameter '{name}' ({place})",
                severity="high",
                url=targets[0] if targets else "",
                host="",
                cwe="CWE-89",
                tags=["sqli"],
                description=(f"back-end DBMS: {dbms_s}. " if dbms_s else "")
                + "; ".join(titles[:4]),
                extracted=titles + types,
                raw_ref=str(raw_path),
            )
