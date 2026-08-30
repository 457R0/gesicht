"""A bounded, same-site BFS crawler - the fallback for katana / hakrawler.

Deliberately small: fetch a page, pull ``href``/``src`` links, stay on the same
registrable domain, respect a depth and page-count cap. ACTIVE (it requests the
target).
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urljoin, urlparse

from publicsuffix2 import get_sld

from ...core.models import Activity, Endpoint
from ..base import Task, ToolAdapter

_LINK_RE = re.compile(r"""(?:href|src)\s*=\s*["']?([^"'\s>]+)""", re.I)
_UA = "gesicht-crawler/0.1"


def _fetch(url: str, timeout: float) -> tuple[int | None, str, int]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310
            body = resp.read(300_000).decode("utf-8", "replace")
            return resp.status, body, len(body)
    except urllib.error.HTTPError as e:
        return e.code, "", 0
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, ConnectionError, OSError):
        return None, "", 0


class CrawlerAdapter(ToolAdapter):
    name = "crawler"
    category = "crawl"
    activity = Activity.ACTIVE
    internal = True

    def execute(self, task: Task, raw_path: Path) -> Iterator[Endpoint]:
        depth_cap = int(task.opt("depth", 2))
        page_cap = int(task.opt("max_pages", 200))
        timeout = task.timeout or 10.0

        starts = [t if "://" in t else f"https://{t}" for t in task.targets]
        allowed = {get_sld(urlparse(u).hostname or "") for u in starts}
        seen: set[str] = set()
        queue: deque[tuple[str, int]] = deque((u, 0) for u in starts)
        lines: list[str] = []

        while queue and len(seen) < page_cap:
            url, depth = queue.popleft()
            url, _frag, _ = url.partition("#")
            if url in seen:
                continue
            seen.add(url)
            status, body, length = _fetch(url, timeout)
            lines.append(json.dumps({"url": url, "status": status, "depth": depth}))
            if status is None:
                continue
            yield Endpoint(
                url=url,
                host=urlparse(url).hostname or "",
                status=status,
                length=length,
                sources=["crawler"],
            )
            if depth >= depth_cap or not body:
                continue
            for raw in _LINK_RE.findall(body):
                nxt = urljoin(url, raw)
                if not nxt.startswith(("http://", "https://")):
                    continue
                if get_sld(urlparse(nxt).hostname or "") not in allowed:
                    continue
                if nxt not in seen:
                    queue.append((nxt, depth + 1))

        raw_path.write_text("\n".join(lines) + ("\n" if lines else ""))
