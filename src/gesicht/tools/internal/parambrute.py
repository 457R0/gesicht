"""Wordlist parameter brute-force - the fallback for arjun / paramspider.

For each URL: take a baseline, then try each candidate name with a unique canary
value. A name is "discovered" if the canary is reflected in the response or the
response length shifts materially from the baseline. ACTIVE.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlencode, urlparse

from ...core.models import Activity, Endpoint, Param, ParamLoc
from ..base import Task, ToolAdapter
from ..wordlists import find_wordlist

_UA = "gesicht-parambrute/0.1"
_CANARY = "gesichtw00t1234"
_LEN_DELTA = 48  # bytes of change that counts as "the param did something"


def _get(url: str, timeout: float) -> tuple[int | None, str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310
            return resp.status, resp.read(200_000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, ConnectionError, OSError):
        return None, ""


def _with_param(url: str, name: str, value: str) -> str:
    sep = "&" if urlparse(url).query else "?"
    return f"{url}{sep}{urlencode({name: value})}"


class ParamBruteAdapter(ToolAdapter):
    name = "parambrute"
    category = "params"
    activity = Activity.ACTIVE
    internal = True

    def execute(self, task: Task, raw_path: Path) -> Iterator[Param | Endpoint]:
        timeout = task.timeout or 10.0
        wl = find_wordlist("params", override=task.opt("wordlist"))
        names = [
            n.strip() for n in (wl.read_text().splitlines() if wl else []) if n.strip()
        ]
        cap = int(task.opt("max_params", 120))
        names = names[:cap]
        log: list[dict] = []

        for target in task.targets:
            url = target if "://" in target else f"https://{target}"
            base_status, base_body = _get(url, timeout)
            if base_status is None:
                log.append({"url": url, "reachable": False})
                continue
            base_len = len(base_body)
            ep = Endpoint(
                url=url, host=urlparse(url).hostname or "", status=base_status,
                length=base_len, sources=["parambrute"],
            )
            yield ep
            found: list[str] = []
            for name in names:
                status, body = _get(_with_param(url, name, _CANARY), timeout)
                if status is None:
                    continue
                reflected = _CANARY in body
                shifted = abs(len(body) - base_len) >= _LEN_DELTA or status != base_status
                if reflected or shifted:
                    found.append(name)
                    yield Param(
                        endpoint_id=ep.id,
                        name=name,
                        location=ParamLoc.QUERY,
                        example_value=_CANARY,
                        reflected=reflected,
                        discovered_by="parambrute",
                    )
            log.append({"url": url, "tested": len(names), "found": found})

        raw_path.write_text("\n".join(json.dumps(x) for x in log) + ("\n" if log else ""))
