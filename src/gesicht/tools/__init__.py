"""External-tool orchestration.

Nothing in this package launches a process without a
:class:`~gesicht.scope.guard.ScopeDecision` - the orchestrator calls
``ScopeGuard.authorize()`` before every ``subprocess`` invocation.

Note: import the module ``gesicht.tools.registry`` for its functions/singleton;
this package intentionally does not re-export the ``registry`` instance to avoid
shadowing the submodule name.
"""

from .base import Availability, InstallSpec, Task, ToolAdapter
from .orchestrator import Orchestrator, RunResult

__all__ = [
    "Availability",
    "InstallSpec",
    "Task",
    "ToolAdapter",
    "Orchestrator",
    "RunResult",
]
