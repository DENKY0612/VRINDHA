"""Autonomous operations package.

Exports are resolved lazily so importing a single submodule (for example
``vrin_SOC.autonomous.goals``) does not pull the scheduler, executor, and
tooling stack — that previously created circular-import pressure with the
Brain and API layers.
"""

from pathlib import Path
import sys

_repo = Path(__file__).resolve().parents[2]
if (_repo / "Vrin_TI").is_dir() and str(_repo) not in sys.path:
    sys.path.insert(0, str(_repo))

try:
    from vrin_SOC._imports import bind_package
except ImportError:
    bind_package = None

if bind_package is not None:
    bind_package(__name__)

__all__ = [
    "autonomous_agent",
    "GoalEngine",
    "Planner",
    "AutonomyPolicy",
    "Scheduler",
    "TaskManager",
]

_EXPORTS = {
    "autonomous_agent": (".agent", "autonomous_agent"),
    "GoalEngine": (".goals", "GoalEngine"),
    "Planner": (".planner", "Planner"),
    "AutonomyPolicy": (".policy", "AutonomyPolicy"),
    "Scheduler": (".scheduler", "Scheduler"),
    "TaskManager": (".task_manager", "TaskManager"),
}


def __getattr__(name: str):
    try:
        module_name, attr = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    from importlib import import_module

    value = getattr(import_module(module_name, __name__), attr)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
