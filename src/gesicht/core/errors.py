"""Typed errors mapped to stable process exit codes.

These subclass :class:`click.ClickException` so both the ``gesicht`` entry point and
``typer.testing.CliRunner`` render them the same way - a one-line message on
stderr and the exit code below (never a traceback).

Exit code contract (also documented in the plan):
    0  ok
    1  generic / usage error
    2  scope violation - an out-of-scope target was requested
    3  a required external tool is missing and no fallback exists
    4  partial parse - a tool produced output we could only partly read
"""

from __future__ import annotations

import click


class GesichtError(click.ClickException):
    """Base class for all expected gesicht failures."""

    exit_code = 1

    def show(self, file=None) -> None:  # noqa: ANN001
        click.secho(f"✗ {self.format_message()}", fg="red", err=True)


class UsageError(GesichtError):
    exit_code = 1


class WorkspaceNotFoundError(UsageError):
    """No workspace could be resolved from flags, env, cwd, or config."""


class ScopeViolation(GesichtError):
    """An action was requested against a target that is not in scope."""

    exit_code = 2

    def __init__(self, target: str, reason: str) -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"{target}: {reason}")


class ToolUnavailable(GesichtError):
    """A required tool is not installed and could not be substituted."""

    exit_code = 3

    def __init__(self, tool: str, hint: str = "") -> None:
        self.tool = tool
        self.hint = hint
        msg = f"required tool '{tool}' is not available"
        if hint:
            msg += f" - {hint}"
        super().__init__(msg)


class PartialParse(GesichtError):
    """A tool's output was only partially parseable; some records were dropped."""

    exit_code = 4
