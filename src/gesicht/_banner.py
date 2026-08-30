"""The ASCII wordmark shown when ``gesicht`` is run with no command."""

from __future__ import annotations

BANNER = r"""
 _______  _______  _______  ___   _______  __   __  _______
|       ||       ||       ||   | |       ||  | |  ||       |
|    ___||    ___||  _____||   | |       ||  |_|  ||_     _|
|   | __ |   |___ | |_____ |   | |       ||       |  |   |
|   ||  ||    ___||_____  ||   | |      _||       |  |   |
|   |_| ||   |___  _____| ||   | |     |_ |   _   |  |   |
|_______||_______||_______||___| |_______||__| |__|  |___|
""".strip("\n")


def print_banner() -> None:
    """Print the wordmark to the shared console (stderr-safe, colour-aware)."""
    from .core.console import console

    console.print(BANNER, style="cyan", highlight=False)
