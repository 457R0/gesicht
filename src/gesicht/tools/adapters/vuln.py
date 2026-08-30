"""Vulnerability scanners: nuclei (primary), nikto, wpscan. All ACTIVE."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlparse

from ...core.ids import entity_id
from ...core.models import Activity, VulnHit
from ..base import InstallSpec, Task, ToolAdapter


def _host(u: str) -> str:
    return urlparse(u).hostname or u


class NucleiAdapter(ToolAdapter):
    name = "nuclei"
    binaries = ("nuclei",)
    category = "vuln"
    activity = Activity.ACTIVE
    install = InstallSpec(
        apt="nuclei", go="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    )

    def build_steps(self, task: Task, binary: str) -> list[list[str]]:
        infile = task.artifact("nuclei-input.txt")
        infile.write_text("\n".join(task.targets) + "\n")
        out = task.artifact("nuclei.jsonl")
        argv = [
            binary, "-l", str(infile), "-jsonl", "-o", str(out),
            "-silent", "-nc", "-disable-update-check",
        ]
        if task.opt("severity"):
            argv += ["-severity", str(task.opt("severity"))]
        if task.opt("tags"):
            argv += ["-tags", str(task.opt("tags"))]
        if task.opt("templates"):
            argv += ["-t", str(task.opt("templates"))]
        if task.rate:
            argv += ["-rate-limit", str(int(task.rate))]
        argv += task.extra_args
        return [argv]

    def health_check(self, av) -> list[str]:  # noqa: ANN001
        home = Path.home()
        for p in (home / ".local/nuclei-templates", home / "nuclei-templates"):
            if p.is_dir():
                return []
        return ["nuclei templates not found - run `nuclei -update-templates`"]

    def parse(self, raw_path: Path, task: Task) -> Iterator[VulnHit]:
        out = task.artifact("nuclei.jsonl")
        text = out.read_text() if out.is_file() else raw_path.read_text()
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = r.get("info", {}) or {}
            cls = info.get("classification") or {}
            matched = r.get("matched-at") or r.get("matched") or r.get("host", "")
            yield VulnHit(
                scanner="nuclei",
                signature=r.get("template-id", "unknown"),
                name=info.get("name", r.get("template-id", "nuclei hit")),
                severity=(info.get("severity") or "info"),
                url=matched,
                host=_host(matched or r.get("host", "")),
                cwe=_first(cls.get("cwe-id")),
                cve=list(cls.get("cve-id") or []),
                cvss_score=cls.get("cvss-score"),
                cvss_vector=cls.get("cvss-metrics"),
                tags=list(info.get("tags") or []),
                description=(info.get("description") or "").strip(),
                extracted=list(r.get("extracted-results") or []),
                reference=list(info.get("reference") or []),
                raw_ref=str(out),
            )


class NiktoAdapter(ToolAdapter):
    name = "nikto"
    binaries = ("nikto",)
    category = "vuln"
    activity = Activity.ACTIVE
    install = InstallSpec(apt="nikto")

    def build_steps(self, task: Task, binary: str) -> list[list[str]]:
        steps = []
        for i, target in enumerate(task.targets):
            out = task.artifact(f"nikto-{i}.xml")
            argv = [binary, "-h", target, "-Format", "xml", "-output", str(out),
                    "-nointeractive", "-ask", "no"]
            if task.opt("maxtime"):
                argv += ["-maxtime", str(task.opt("maxtime"))]
            argv += task.extra_args
            steps.append(argv)
        return steps

    def parse(self, raw_path: Path, task: Task) -> Iterator[VulnHit]:
        for f in sorted(task.outdir.glob("nikto-*.xml")):
            try:
                root = ET.parse(f).getroot()
            except ET.ParseError:
                continue
            for scan in root.iter("scandetails"):
                target_host = scan.get("targethostname") or scan.get("targetip") or ""
                for item in scan.iter("item"):
                    desc = (item.findtext("description") or "").strip()
                    uri = (item.findtext("uri") or "").strip()
                    link = (item.findtext("namelink") or "").strip()
                    yield VulnHit(
                        scanner="nikto",
                        signature=item.get("id") or entity_id("nikto", desc)[:10],
                        name=desc[:120] or "nikto finding",
                        severity="low",
                        url=link or f"{target_host}{uri}",
                        host=target_host,
                        description=desc,
                        tags=["misconfig"],
                        raw_ref=str(f),
                    )


class WpscanAdapter(ToolAdapter):
    name = "wpscan"
    binaries = ("wpscan",)
    category = "vuln"
    activity = Activity.ACTIVE
    install = InstallSpec(apt="wpscan")
    setup_hint = "set WPSCAN_API_TOKEN for vulnerability data (free at wpscan.com)"

    def build_steps(self, task: Task, binary: str) -> list[list[str]]:
        import os

        steps = []
        for i, target in enumerate(task.targets):
            out = task.artifact(f"wpscan-{i}.json")
            argv = [
                binary, "--url", target, "--format", "json", "--output", str(out),
                "--no-banner", "--disable-tls-checks",
            ]
            token = os.environ.get("WPSCAN_API_TOKEN")
            if token:
                argv += ["--api-token", token]
            argv += task.extra_args
            steps.append(argv)
        return steps

    def parse(self, raw_path: Path, task: Task) -> Iterator[VulnHit]:
        for f in sorted(task.outdir.glob("wpscan-*.json")):
            try:
                data = json.loads(f.read_text() or "{}")
            except json.JSONDecodeError:
                continue
            target = data.get("target_url") or data.get("target_ip") or ""
            yield from _wpscan_vulns(data, target, str(f))


def _wpscan_vulns(data: dict, target: str, ref: str) -> Iterator[VulnHit]:
    buckets: list[dict] = []
    for key in ("version", "main_theme"):
        if isinstance(data.get(key), dict):
            buckets.append(data[key])
    for plug in (data.get("plugins") or {}).values():
        if isinstance(plug, dict):
            buckets.append(plug)
    for b in buckets:
        for v in b.get("vulnerabilities") or []:
            refs = v.get("references") or {}
            yield VulnHit(
                scanner="wpscan",
                signature=str(v.get("title", "wp vuln"))[:80],
                name=v.get("title", "WordPress vulnerability"),
                severity="medium",
                url=target,
                host=_host(target),
                cve=[f"CVE-{c}" for c in refs.get("cve", [])],
                reference=list(refs.get("url", [])),
                description=f"Fixed in {v.get('fixed_in') or 'unknown'}",
                tags=["cve"],
                raw_ref=ref,
            )
    for itm in data.get("interesting_findings") or []:
        if itm.get("type") in {"headers", "robots_txt", "readme"}:
            continue
        yield VulnHit(
            scanner="wpscan",
            signature=itm.get("type", "finding"),
            name=itm.get("to_s") or itm.get("type", "interesting finding"),
            severity="info",
            url=itm.get("url", target),
            host=_host(target),
            tags=["exposure"],
            raw_ref=ref,
        )


def _first(v):
    if isinstance(v, list):
        v = v[0] if v else None
    return v.upper() if isinstance(v, str) and v.lower().startswith("cwe-") else v
