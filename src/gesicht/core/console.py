"""Shared Rich console + small output helpers."""

from __future__ import annotations

from rich.console import Console

console = Console()
err_console = Console(stderr=True)


def info(msg: str) -> None:
    console.print(msg)


def ok(msg: str) -> None:
    console.print(f"[green]✓[/green] {msg}")


def warn(msg: str) -> None:
    err_console.print(f"[yellow]![/yellow] {msg}")


def fail(msg: str) -> None:
    err_console.print(f"[red]✗[/red] {msg}")
