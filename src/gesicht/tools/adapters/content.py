"""Content / directory discovery: ffuf, feroxbuster, gobuster. All ACTIVE.

Each takes one or more base URLs. One external invocation per base URL
(``build_steps``); results are read back from per-target artifact files.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

from ...core.models import Activity, Endpoint
from ..base import InstallSpec, Task, ToolAdapter
from ..wordlists import find_wordlist

_MATCH_CODES = "200,201,202,204,301,302,307,308,401,403,405,500"


def _base_urls(task: Task) -> list[str]:
    out = []
    for t in task.targets:
        u = t if "://" in t else f"https://{t}"
        out.append(u.rstrip("/"))
    return out


def _wordlist(task: Task) -> str:
    wl = find_wordlist("content", override=task.opt("wordlist"))
    if wl is None:
        raise FileNotFoundError(
            "no content wordlist found - install `seclists` or pass --wordlist"
        )
    return str(wl)


class FfufAdapter(ToolAdapter):
    name = "ffuf"
    binaries = ("ffuf",)
    category = "content"
    activity = Activity.ACTIVE
    install = InstallSpec(apt="ffuf", go="github.com/ffuf/ffuf/v2@latest")

    def build_steps(self, task: Task, binary: str) -> list[list[str]]:
        wl = _wordlist(task)
        steps = []
        for i, base in enumerate(_base_urls(task)):
            url = base if "FUZZ" in base else f"{base}/FUZZ"
            out = task.artifact(f"ffuf-{i}.json")
            argv = [
                binary, "-u", url, "-w", wl, "-of", "json", "-o", str(out),
                "-s", "-mc", _MATCH_CODES, "-t", str(int(task.opt("threads", 40))),
            ]
            if task.rate:
                argv += ["-rate", str(int(task.rate))]
            argv += task.extra_args
            steps.append(argv)
        return steps

    def parse(self, raw_path: Path, task: Task) -> Iterator[Endpoint]:
        for f in sorted(task.outdir.glob("ffuf-*.json")):
            try:
                data = json.loads(f.read_text() or "{}")
            except json.JSONDecodeError:
                continue
            for r in data.get("results", []):
                yield Endpoint(
                    url=r.get("url", ""),
                    status=r.get("status"),
                    length=r.get("length"),
                    content_type=r.get("content-type"),
                    sources=["ffuf"],
                )


class FeroxbusterAdapter(ToolAdapter):
    name = "feroxbuster"
    binaries = ("feroxbuster",)
    category = "content"
    activity = Activity.ACTIVE
    install = InstallSpec(apt="feroxbuster")

    def build_steps(self, task: Task, binary: str) -> list[list[str]]:
        wl = _wordlist(task)
        steps = []
        for i, base in enumerate(_base_urls(task)):
            out = task.artifact(f"ferox-{i}.json")
            argv = [
                binary, "-u", base, "-w", wl, "--json", "--silent", "-k",
                "-o", str(out), "-s", *(_MATCH_CODES.split(",")),
            ]
            if task.rate:
                argv += ["--rate-limit", str(int(task.rate))]
            argv += task.extra_args
            steps.append(argv)
        return steps

    def parse(self, raw_path: Path, task: Task) -> Iterator[Endpoint]:
        for f in sorted(task.outdir.glob("ferox-*.json")):
            for line in f.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("type") != "response":
                    continue
                yield Endpoint(
                    url=rec.get("url", ""),
                    status=rec.get("status"),
                    length=rec.get("content_length"),
                    content_type=rec.get("content_type"),
                    sources=["feroxbuster"],
                )


_GOBUSTER_LINE = re.compile(
    r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d+)\)(?:\s+\[Size:\s*(?P<size>\d+)\])?"
)


class GobusterAdapter(ToolAdapter):
    name = "gobuster"
    binaries = ("gobuster",)
    category = "content"
    activity = Activity.ACTIVE
    install = InstallSpec(apt="gobuster", go="github.com/OJ/gobuster/v3@latest")

    def build_steps(self, task: Task, binary: str) -> list[list[str]]:
        wl = _wordlist(task)
        steps = []
        for i, base in enumerate(_base_urls(task)):
            out = task.artifact(f"gobuster-{i}.txt")
            argv = [
                binary, "dir", "-u", base, "-w", wl, "-q", "--no-color",
                "-o", str(out), "-t", str(int(task.opt("threads", 40))), "-k",
            ]
            argv += task.extra_args
            steps.append(argv)
        return steps

    def parse(self, raw_path: Path, task: Task) -> Iterator[Endpoint]:
        base_by_index = _base_urls(task)
        for i, f in enumerate(sorted(task.outdir.glob("gobuster-*.txt"))):
            base = base_by_index[i] if i < len(base_by_index) else ""
            for line in f.read_text().splitlines():
                m = _GOBUSTER_LINE.match(line.strip())
                if not m:
                    continue
                yield Endpoint(
                    url=f"{base}{m.group('path')}",
                    status=int(m.group("status")),
                    length=int(m.group("size")) if m.group("size") else None,
                    sources=["gobuster"],
                )
