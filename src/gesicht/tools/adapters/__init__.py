"""External-tool adapters."""

from __future__ import annotations

from ..registry import Registry
from .amass import AmassAdapter
from .arjun import ArjunAdapter
from .content import FeroxbusterAdapter, FfufAdapter, GobusterAdapter
from .fingerprint import Wafw00fAdapter, WhatwebAdapter
from .httpx_pd import HttpxAdapter
from .katana import KatanaAdapter
from .nmap import NmapAdapter
from .pd_recon import DnsxAdapter, NaabuAdapter, SubfinderAdapter
from .sqlmap import SqlmapAdapter
from .vuln import NiktoAdapter, NucleiAdapter, WpscanAdapter


def register_adapters(reg: Registry) -> None:
    for adapter in (
        AmassAdapter(),
        SubfinderAdapter(),
        NmapAdapter(),
        NaabuAdapter(),
        DnsxAdapter(),
        HttpxAdapter(),
        FfufAdapter(),
        FeroxbusterAdapter(),
        GobusterAdapter(),
        KatanaAdapter(),
        ArjunAdapter(),
        WhatwebAdapter(),
        Wafw00fAdapter(),
        NucleiAdapter(),
        NiktoAdapter(),
        WpscanAdapter(),
        SqlmapAdapter(),
    ):
        reg.register(adapter)
