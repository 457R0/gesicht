"""Arjun - HTTP parameter discovery. ACTIVE. Falls back to the internal brute."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from ...core.models import Activity, Endpoint, Param, ParamLoc
from ..base import InstallSpec, Task, ToolAdapter


class ArjunAdapter(ToolAdapter):
    name = "arjun"
    binaries = ("arjun",)
    category = "params"
    activity = Activity.ACTIVE
    fallbacks = ("parambrute",)
    install = InstallSpec(apt="arjun", pipx="arjun")

    def build_steps(self, task: Task, binary: str) -> list[list[str]]:
        infile = task.artifact("arjun-urls.txt")
        infile.write_text("\n".join(task.targets) + "\n")
        out = task.artifact("arjun.json")
        argv = [binary, "-i", str(infile), "-oJ", str(out), "-m",
                task.opt("method", "GET")]
        if task.opt("wordlist"):
            argv += ["-w", str(task.opt("wordlist"))]
        if task.rate:
            argv += ["--rate-limit", str(int(task.rate))]
        argv += task.extra_args
        return [argv]

    def parse(self, raw_path: Path, task: Task) -> Iterator[Param | Endpoint]:
        out = task.artifact("arjun.json")
        if not out.is_file():
            return
        try:
            data = json.loads(out.read_text() or "{}")
        except json.JSONDecodeError:
            return
        for url, info in data.items():
            params = info.get("params") if isinstance(info, dict) else info
            if not params:
                continue
            ep = Endpoint(url=url, method=task.opt("method", "GET"), sources=["arjun"])
            yield ep
            for name in params:
                yield Param(
                    endpoint_id=ep.id,
                    name=name,
                    location=ParamLoc.QUERY,
                    discovered_by="arjun",
                )
