"""Tech fingerprinting: whatweb, wafw00f. Both make one request => ACTIVE."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlparse

from ...core.models import Activity, Endpoint, Host
from ..base import InstallSpec, Task, ToolAdapter


def _urls(task: Task) -> list[str]:
    return [t if "://" in t else f"https://{t}" for t in task.targets]


class WhatwebAdapter(ToolAdapter):
    name = "whatweb"
    binaries = ("whatweb",)
    category = "fingerprint"
    activity = Activity.ACTIVE
    install = InstallSpec(apt="whatweb")

    def build_steps(self, task: Task, binary: str) -> list[list[str]]:
        out = task.artifact("whatweb.json")
        aggression = str(int(task.opt("aggression", 1)))
        return [[binary, "-a", aggression, "--log-json", str(out), "--no-errors",
                 "--color=never", *_urls(task)]]

    def parse(self, raw_path: Path, task: Task) -> Iterator[Endpoint]:
        out = task.artifact("whatweb.json")
        if not out.is_file():
            return
        text = out.read_text().strip()
        records = []
        try:
            records = json.loads(text) if text.startswith("[") else [
                json.loads(ln) for ln in text.splitlines() if ln.strip()
            ]
        except json.JSONDecodeError:
            return
        for r in records:
            plugins = r.get("plugins", {})
            target = r.get("target", "")
            yield Endpoint(
                url=target,
                host=urlparse(target).hostname or "",
                status=(r.get("http_status") or None),
                title=_first(plugins.get("Title", {}).get("string")),
                tech=sorted(plugins.keys()),
                content_type=_first(plugins.get("Content-Type", {}).get("string")),
                sources=["whatweb"],
            )


class Wafw00fAdapter(ToolAdapter):
    name = "wafw00f"
    binaries = ("wafw00f",)
    category = "fingerprint"
    activity = Activity.ACTIVE
    install = InstallSpec(apt="wafw00f", pipx="wafw00f")

    def build_steps(self, task: Task, binary: str) -> list[list[str]]:
        out = task.artifact("wafw00f.json")
        return [[binary, "-f", "json", "-o", str(out), "-a", *_urls(task)]]

    def parse(self, raw_path: Path, task: Task) -> Iterator[Host]:
        out = task.artifact("wafw00f.json")
        if not out.is_file():
            return
        try:
            data = json.loads(out.read_text() or "[]")
        except json.JSONDecodeError:
            return
        for r in data if isinstance(data, list) else [data]:
            url = r.get("url", "")
            waf = r.get("firewall") or r.get("detected") or None
            host = urlparse(url).hostname or url
            tags = [f"waf:{waf}"] if waf and waf.lower() not in {"none", "generic"} else []
            yield Host(hostname=host, sources=["wafw00f"], tags=tags)


def _first(v):
    if isinstance(v, list):
        return v[0] if v else None
    return v
