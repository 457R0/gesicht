"""Katana - crawl a site for endpoints. ACTIVE. Falls back to the internal crawler."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlparse

from ...core.models import Activity, Endpoint
from ..base import InstallSpec, Task, ToolAdapter


class KatanaAdapter(ToolAdapter):
    name = "katana"
    binaries = ("katana",)
    category = "crawl"
    activity = Activity.ACTIVE
    fallbacks = ("crawler",)
    install = InstallSpec(go="github.com/projectdiscovery/katana/cmd/katana@latest")

    def build_steps(self, task: Task, binary: str) -> list[list[str]]:
        infile = task.artifact("katana-input.txt")
        infile.write_text("\n".join(_as_urls(task.targets)) + "\n")
        out = task.artifact("katana.jsonl")
        argv = [
            binary, "-list", str(infile), "-jsonl", "-o", str(out),
            "-silent", "-nc", "-d", str(int(task.opt("depth", 2))),
        ]
        if task.opt("passive_sources"):
            argv += ["-passive"]
        if task.rate:
            argv += ["-rate-limit", str(int(task.rate))]
        argv += task.extra_args
        return [argv]

    def parse(self, raw_path: Path, task: Task) -> Iterator[Endpoint]:
        out = task.artifact("katana.jsonl")
        text = out.read_text() if out.is_file() else raw_path.read_text()
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            req = r.get("request", {})
            url = req.get("endpoint") or req.get("url") or r.get("endpoint", "")
            if not url:
                continue
            resp = r.get("response", {}) or {}
            yield Endpoint(
                url=url,
                method=req.get("method", "GET"),
                host=urlparse(url).hostname or "",
                status=resp.get("status_code"),
                length=resp.get("content_length"),
                sources=["katana"],
            )


def _as_urls(targets: list[str]) -> list[str]:
    return [t if "://" in t else f"https://{t}" for t in targets]
