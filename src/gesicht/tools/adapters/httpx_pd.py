"""ProjectDiscovery httpx - probe which hosts answer over HTTP(S). ACTIVE.

On Kali the binary is ``httpx-toolkit`` (the apt package); ``httpx`` alone is
usually the Python library CLI, so the registry only accepts a candidate that
passes the pd-httpx banner check. Falls back to the internal prober.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from ...core.models import Activity, Endpoint
from ..base import InstallSpec, Task, ToolAdapter


class HttpxAdapter(ToolAdapter):
    name = "httpx"
    binaries = ("httpx-toolkit", "httpx")
    category = "recon"
    activity = Activity.ACTIVE
    fallbacks = ("prober",)
    install = InstallSpec(
        apt="httpx-toolkit",
        go="github.com/projectdiscovery/httpx/cmd/httpx@latest",
        binary="httpx-toolkit",
    )

    def build_steps(self, task: Task, binary: str) -> list[list[str]]:
        infile = task.artifact("httpx-input.txt")
        infile.write_text("\n".join(task.targets) + "\n")
        out = task.artifact("httpx.jsonl")
        argv = [
            binary, "-l", str(infile), "-json", "-o", str(out),
            "-silent", "-no-color", "-title", "-tech-detect",
            "-status-code", "-content-length", "-follow-redirects",
        ]
        if task.rate:
            argv += ["-rate-limit", str(int(task.rate))]
        argv += task.extra_args
        return [argv]

    def parse(self, raw_path: Path, task: Task) -> Iterator[Endpoint]:
        out = task.artifact("httpx.jsonl")
        text = out.read_text() if out.is_file() else raw_path.read_text()
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield Endpoint(
                url=r.get("url") or r.get("input", ""),
                host=r.get("host") or r.get("input", ""),
                status=r.get("status_code") or r.get("status-code"),
                length=r.get("content_length") or r.get("content-length"),
                title=r.get("title"),
                tech=r.get("tech") or r.get("technologies") or [],
                content_type=r.get("content_type"),
                sources=["httpx"],
            )
