"""A small HTTP prober - the fallback for ProjectDiscovery httpx.

Given hosts or URLs, records which answer over http/https, with status, title,
content type/length, and the Server header. Uses only the stdlib.
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlparse

from ...core.models import Activity, Endpoint
from ..base import Task, ToolAdapter

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
_UA = "gesicht-prober/0.1"


def _probe_url(url: str, *, timeout: float = 10.0) -> Endpoint | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310
            body = resp.read(65536)
            status = resp.status
            headers = {k.lower(): v for k, v in resp.headers.items()}
            final_url = resp.geturl()
    except urllib.error.HTTPError as e:
        status = e.code
        body = b""
        headers = {k.lower(): v for k, v in (e.headers or {}).items()}
        final_url = url
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, ConnectionError, OSError):
        return None

    title = None
    m = _TITLE_RE.search(body)
    if m:
        title = m.group(1).decode("utf-8", "replace").strip()[:200]

    length = headers.get("content-length")
    tech = [t for t in (headers.get("server"), headers.get("x-powered-by")) if t]
    return Endpoint(
        url=final_url,
        method="GET",
        host=urlparse(final_url).hostname or "",
        status=status,
        length=int(length) if length and length.isdigit() else len(body),
        content_type=(headers.get("content-type") or "").split(";")[0] or None,
        title=title,
        tech=tech,
        sources=["prober"],
    )


def probe_host(host: str, **kw) -> Endpoint | None:
    if "://" in host:
        return _probe_url(host, **kw)
    for scheme in ("https", "http"):
        ep = _probe_url(f"{scheme}://{host}", **kw)
        if ep is not None:
            return ep
    return None


class ProberAdapter(ToolAdapter):
    name = "prober"
    category = "recon"
    activity = Activity.ACTIVE  # it makes a request to the target
    internal = True

    def execute(self, task: Task, raw_path: Path) -> Iterator[Endpoint]:
        lines: list[str] = []
        for target in task.targets:
            ep = probe_host(target, timeout=task.timeout or 10.0)
            if ep is None:
                lines.append(json.dumps({"target": target, "alive": False}))
                continue
            lines.append(
                json.dumps(
                    {
                        "target": target,
                        "alive": True,
                        "url": ep.url,
                        "status": ep.status,
                        "title": ep.title,
                        "tech": ep.tech,
                    }
                )
            )
            yield ep
        raw_path.write_text("\n".join(lines) + ("\n" if lines else ""))
