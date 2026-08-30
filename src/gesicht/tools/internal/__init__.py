"""Pure-Python fallbacks used when an external tool is missing."""

from __future__ import annotations

from ..registry import Registry
from .cdx import CdxAdapter
from .crawler import CrawlerAdapter
from .parambrute import ParamBruteAdapter
from .prober import ProberAdapter
from .resolver import ResolverAdapter


def register_adapters(reg: Registry) -> None:
    for adapter in (
        ResolverAdapter(),
        ProberAdapter(),
        CdxAdapter(),
        CrawlerAdapter(),
        ParamBruteAdapter(),
    ):
        reg.register(adapter)
