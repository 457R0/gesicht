"""Nmap - service/port discovery. ACTIVE: it sends packets to the target."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path

from ...core.models import Activity, Host, Service
from ..base import InstallSpec, Task, ToolAdapter


class NmapAdapter(ToolAdapter):
    name = "nmap"
    binaries = ("nmap",)
    category = "portscan"
    activity = Activity.ACTIVE
    install = InstallSpec(apt="nmap")

    def build_command(self, task: Task, binary: str) -> list[str]:
        xml = task.artifact("nmap.xml")
        argv = [binary, "-sV", "--open", "-oX", str(xml), "-T3", "-Pn"]
        ports = task.opt("ports")
        if ports:
            argv += ["-p", str(ports)]
        elif task.opt("top_ports"):
            argv += ["--top-ports", str(int(task.opt("top_ports")))]
        if task.rate:
            argv += ["--max-rate", str(int(task.rate * 60))]  # rps -> approx packets/min cap
        argv += task.extra_args
        argv += list(task.targets)
        return argv

    def parse(self, raw_path: Path, task: Task) -> Iterator[Host | Service]:
        xml = task.artifact("nmap.xml")
        if not xml.is_file():
            return
        try:
            root = ET.parse(xml).getroot()
        except ET.ParseError:
            return
        for host_el in root.findall("host"):
            state = host_el.find("status")
            if state is not None and state.get("state") not in {"up", None}:
                continue
            ip = ""
            for addr in host_el.findall("address"):
                if addr.get("addrtype") in {"ipv4", "ipv6"}:
                    ip = addr.get("addr", "")
            hostnames = [
                h.get("name", "")
                for h in host_el.findall("hostnames/hostname")
                if h.get("name")
            ]
            primary = hostnames[0] if hostnames else ip
            if primary:
                yield Host(hostname=primary, ips=[ip] if ip else [], sources=["nmap"])

            for port_el in host_el.findall("ports/port"):
                st = port_el.find("state")
                if st is None or st.get("state") != "open":
                    continue
                svc = port_el.find("service")
                yield Service(
                    host=primary or ip,
                    ip=ip,
                    port=int(port_el.get("portid", "0")),
                    proto=port_el.get("protocol", "tcp"),
                    name=(svc.get("name") if svc is not None else None),
                    product=(svc.get("product") if svc is not None else None),
                    version=(svc.get("version") if svc is not None else None),
                    source="nmap",
                )
