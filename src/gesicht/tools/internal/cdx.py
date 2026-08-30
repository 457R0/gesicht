"""web.archive.org CDX client - passive URL/host discovery.

This is the fallback for ``gau`` / ``waybackurls`` (URLs) and contributes host
names to the ``subfinder`` fallback. It queries archive.org, never the target,
so it is a PASSIVE source.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import quote, urlparse

from ...core.models import Activity, Endpoint, Host
from ..base import Task, ToolAdapter

_CDX = (
    "http://web.archive.org/cdx/search/cdx"
    "?url={pattern}&output=text&fl=original&collapse=urlkey&limit={limit}"
)


def fetch_urls(domain: str, *, limit: int = 5000, timeout: float = 30.0) -> list[str]:
    pattern = quote(f"*.{domain}/*", safe="")
    url = _CDX.format(pattern=pattern, limit=limit)
    req = urllib.request.Request(url, headers={"User-Agent": "gesicht-cdx/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            text = resp.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError, OSError):
        return []
    return [line.strip() for line in text.splitlines() if line.strip()]


class CdxAdapter(ToolAdapter):
    name = "wayback"
    category = "crawl"
    activity = Activity.PASSIVE
    internal = True

    def execute(self, task: Task, raw_path: Path) -> Iterator[Endpoint | Host]:
        want_hosts = bool(task.opt("emit_hosts"))
        limit = int(task.opt("limit", 5000))
        all_urls: list[str] = []
        seen_hosts: set[str] = set()
        for domain in task.targets:
            urls = fetch_urls(domain, limit=limit, timeout=task.timeout or 30.0)
            all_urls.extend(urls)
            for u in urls:
                host = (urlparse(u).hostname or "").lower()
                if host and host not in seen_hosts:
                    seen_hosts.add(host)
                    if want_hosts:
                        yield Host(hostname=host, sources=["wayback"])
                if not want_hosts:
                    yield Endpoint(url=u, host=host, sources=["wayback"])
        raw_path.write_text("\n".join(all_urls) + ("\n" if all_urls else ""))
