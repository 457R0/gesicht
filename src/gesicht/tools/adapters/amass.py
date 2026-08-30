"""OWASP Amass - passive subdomain enumeration.

We only ever run ``amass enum -passive`` (no packets to the target). Output
handling differs sharply by major version:

* **v5**: ``enum`` writes to a graph DB under ``-dir``; names are then dumped
  with ``amass subs -names -d <domain> -dir <dir>``. Two steps.
* **v3/v4**: ``enum -passive -o <file>`` writes a plaintext name list. One step.

We detect the major version once and pick the right shape. ``parse`` reads the
resulting ``amass-names.txt`` either way.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterator
from pathlib import Path

from ...core.models import Activity, Host
from ..base import InstallSpec, Task, ToolAdapter

_HOSTLINE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9-]+)+$")
_VER = re.compile(r"v?(\d+)\.\d+")


class AmassAdapter(ToolAdapter):
    name = "amass"
    binaries = ("amass",)
    category = "recon"
    activity = Activity.PASSIVE
    fallbacks = ("subfinder", "wayback")  # then CDX-derived hostnames
    install = InstallSpec(apt="amass", go="github.com/owasp-amass/amass/v4/...@master")
    setup_hint = (
        "Kali's amass wrapper needs libpostal data once: "
        "`sudo libpostal_data download all /var/lib/libpostal`"
    )

    def _major(self, binary: str) -> int:
        try:
            out = subprocess.run(
                [binary, "-version"], capture_output=True, text=True, timeout=8
            )
            m = _VER.search(f"{out.stdout}\n{out.stderr}")
            if m:
                return int(m.group(1))
        except (OSError, subprocess.TimeoutExpired):
            pass
        return 4  # assume the pre-v5 single-step layout

    def build_steps(self, task: Task, binary: str) -> list[list[str]]:
        names = task.artifact("amass-names.txt")
        workdir = task.artifact("amass-db")
        domains = ",".join(task.targets)
        major = self._major(binary)

        if major >= 5:
            workdir.mkdir(parents=True, exist_ok=True)
            enum = [binary, "enum", "-passive", "-nocolor", "-silent",
                    "-dir", str(workdir), "-d", domains]
            if task.opt("timeout_min"):
                enum += ["-timeout", str(int(task.opt("timeout_min")))]
            enum += task.extra_args
            dump = [binary, "subs", "-names", "-nocolor", "-dir", str(workdir),
                    "-d", domains, "-o", str(names)]
            return [enum, dump]

        argv = [binary, "enum", "-passive", "-nocolor", "-o", str(names), "-d", domains]
        if task.opt("timeout_min"):
            argv += ["-timeout", str(int(task.opt("timeout_min")))]
        return [argv + task.extra_args]

    def build_command(self, task: Task, binary: str) -> list[str]:
        return self.build_steps(task, binary)[-1]

    def parse(self, raw_path: Path, task: Task) -> Iterator[Host]:
        names_file = task.artifact("amass-names.txt")
        text = ""
        if names_file.is_file():
            text = names_file.read_text()
        if not text.strip() and raw_path.is_file():
            text = raw_path.read_text()  # v5 `subs -names` also prints to stdout
        seen: set[str] = set()
        for line in text.splitlines():
            host = line.strip().lower().rstrip(".")
            if not host or host in seen or not _HOSTLINE.match(host):
                continue
            seen.add(host)
            yield Host(hostname=host, sources=["amass"])
