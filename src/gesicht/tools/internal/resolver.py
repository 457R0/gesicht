"""Stdlib DNS resolution - the fallback for ``dnsx`` and the ``recon resolve`` step."""

from __future__ import annotations

import json
import socket
from collections.abc import Iterator
from pathlib import Path

from ...core.models import Activity, Host
from ..base import Task, ToolAdapter


def resolve(host: str) -> tuple[list[str], list[str]]:
    """Return (ip_addresses, cname_chain) for ``host``. Never raises."""
    ips: set[str] = set()
    cnames: list[str] = []
    try:
        name, aliases, addrs = socket.gethostbyname_ex(host)
        cnames = [a for a in aliases if a != host]
        ips.update(addrs)
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(host, None):
            ips.add(info[4][0])
    except OSError:
        pass
    return sorted(ips), cnames


class ResolverAdapter(ToolAdapter):
    name = "resolver"
    category = "dns"
    activity = Activity.PASSIVE
    internal = True

    def execute(self, task: Task, raw_path: Path) -> Iterator[Host]:
        lines: list[str] = []
        for host in task.targets:
            ips, cnames = resolve(host)
            lines.append(json.dumps({"host": host, "ips": ips, "cnames": cnames}))
            if ips or cnames:
                yield Host(
                    hostname=host,
                    ips=ips,
                    cnames=cnames,
                    sources=["resolver"],
                )
        raw_path.write_text("\n".join(lines) + ("\n" if lines else ""))
