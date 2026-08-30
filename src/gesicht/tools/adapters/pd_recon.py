"""ProjectDiscovery recon trio: subfinder, naabu, dnsx.

None ship on Kali by default but all are in the apt repo, so the auto-installer
handles them. Until then each has a fallback.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from ...core.models import Activity, Host, Service
from ..base import InstallSpec, Task, ToolAdapter


class SubfinderAdapter(ToolAdapter):
    name = "subfinder"
    binaries = ("subfinder",)
    category = "recon"
    activity = Activity.PASSIVE
    fallbacks = ("wayback",)
    install = InstallSpec(
        apt="subfinder", go="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    )

    def build_steps(self, task: Task, binary: str) -> list[list[str]]:
        infile = task.artifact("subfinder-domains.txt")
        infile.write_text("\n".join(task.targets) + "\n")
        out = task.artifact("subfinder.txt")
        return [[binary, "-dL", str(infile), "-silent", "-o", str(out), *task.extra_args]]

    def parse(self, raw_path: Path, task: Task) -> Iterator[Host]:
        out = task.artifact("subfinder.txt")
        text = out.read_text() if out.is_file() else raw_path.read_text()
        seen: set[str] = set()
        for line in text.splitlines():
            h = line.strip().lower().rstrip(".")
            if h and h not in seen and "." in h:
                seen.add(h)
                yield Host(hostname=h, sources=["subfinder"])


class NaabuAdapter(ToolAdapter):
    name = "naabu"
    binaries = ("naabu",)
    category = "portscan"
    activity = Activity.ACTIVE
    fallbacks = ("nmap",)
    install = InstallSpec(
        apt="naabu", go="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    )

    def build_steps(self, task: Task, binary: str) -> list[list[str]]:
        infile = task.artifact("naabu-hosts.txt")
        infile.write_text("\n".join(task.targets) + "\n")
        out = task.artifact("naabu.jsonl")
        argv = [binary, "-list", str(infile), "-json", "-o", str(out), "-silent"]
        if task.opt("ports"):
            argv += ["-p", str(task.opt("ports"))]
        elif task.opt("top_ports"):
            argv += ["-top-ports", str(int(task.opt("top_ports")))]
        if task.rate:
            argv += ["-rate", str(int(task.rate))]
        return [argv + task.extra_args]

    def parse(self, raw_path: Path, task: Task) -> Iterator[Service]:
        out = task.artifact("naabu.jsonl")
        text = out.read_text() if out.is_file() else raw_path.read_text()
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield Service(
                host=r.get("host") or r.get("ip", ""),
                ip=r.get("ip", ""),
                port=int(r.get("port", 0)),
                proto=r.get("protocol", "tcp"),
                source="naabu",
            )


class DnsxAdapter(ToolAdapter):
    name = "dnsx"
    binaries = ("dnsx",)
    category = "dns"
    activity = Activity.PASSIVE
    fallbacks = ("resolver",)
    install = InstallSpec(
        apt="dnsx", go="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    )

    def build_steps(self, task: Task, binary: str) -> list[list[str]]:
        infile = task.artifact("dnsx-hosts.txt")
        infile.write_text("\n".join(task.targets) + "\n")
        out = task.artifact("dnsx.jsonl")
        return [[binary, "-l", str(infile), "-json", "-o", str(out),
                 "-silent", "-a", "-cname", "-resp", *task.extra_args]]

    def parse(self, raw_path: Path, task: Task) -> Iterator[Host]:
        out = task.artifact("dnsx.jsonl")
        text = out.read_text() if out.is_file() else raw_path.read_text()
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            yield Host(
                hostname=(r.get("host") or "").lower().rstrip("."),
                ips=sorted(set(r.get("a", []))),
                cnames=r.get("cname", []),
                sources=["dnsx"],
            )
