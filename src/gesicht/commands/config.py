"""``gesicht config`` - view and edit the global config (~/.config/gesicht/config.yml)."""

from __future__ import annotations

import json
from dataclasses import asdict

import typer

from ..core.config import CONFIG_PATH, load_config, save_config
from ..core.console import console, ok
from ..core.errors import UsageError

app = typer.Typer(help="View and edit global settings.", no_args_is_help=True)

_SCALAR = {"workspaces_root", "current", "user_agent", "h1_handle"}
_INT = {"concurrency"}
_FLOAT = {"rate_per_host"}


@app.command("path")
def path_() -> None:
    """Print the config file path."""
    console.print(str(CONFIG_PATH))


@app.command()
def get(
    key: str = typer.Argument(None, help="Key to read (omit for all)."),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Show the current config."""
    cfg = asdict(load_config())
    if key:
        if key.startswith("tool."):
            console.print(cfg["tool_paths"].get(key[5:], ""))
            return
        if key not in cfg:
            raise UsageError(f"unknown key '{key}'")
        console.print(json.dumps(cfg[key]) if as_json else str(cfg[key]))
        return
    console.print_json(json.dumps(cfg)) if as_json else console.print(cfg)


@app.command("set")
def set_(
    key: str = typer.Argument(..., help="e.g. workspaces_root, h1_handle, tool.subfinder"),
    value: str = typer.Argument(...),
) -> None:
    """Set a value (use `tool.<name>` for a tool path override)."""
    cfg = load_config()
    if key.startswith("tool."):
        cfg.tool_paths[key[5:]] = value
    elif key in _SCALAR:
        setattr(cfg, key, value)
    elif key in _INT:
        setattr(cfg, key, int(value))
    elif key in _FLOAT:
        setattr(cfg, key, float(value))
    else:
        raise UsageError(
            f"unknown key '{key}' (settable: {', '.join(sorted(_SCALAR | _INT | _FLOAT))}, "
            "or tool.<name>)"
        )
    p = save_config(cfg)
    ok(f"set {key} = {value}  ({p})")


@app.command()
def unset(key: str = typer.Argument(...)) -> None:
    """Clear a tool path override or reset a scalar to empty."""
    cfg = load_config()
    if key.startswith("tool."):
        cfg.tool_paths.pop(key[5:], None)
    elif key in _SCALAR:
        setattr(cfg, key, None if key in {"current", "h1_handle"} else "")
    else:
        raise UsageError(f"cannot unset '{key}'")
    save_config(cfg)
    ok(f"unset {key}")
