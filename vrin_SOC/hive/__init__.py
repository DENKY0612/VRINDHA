"""Hive coordination layer — collective agent orchestration for Vrindha SOC.

The Hive layer sits above individual agents and below the Brain, providing:

* Agent registration and health monitoring
* Cross-agent intelligence sharing (sightings, IOCs, correlations)
* Collective task dispatch with load balancing
* Swarm-wide status aggregation

The Brain delegates multi-agent coordination to the Hive; single-agent
commands continue to route directly through the existing tool executor.
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
    "HiveCoordinator",
    "AgentRegistry",
    "SwarmDispatcher",
    "hive",
]

_EXPORTS = {
    "HiveCoordinator": (".coordinator", "HiveCoordinator"),
    "AgentRegistry": (".registry", "AgentRegistry"),
    "SwarmDispatcher": (".swarm", "SwarmDispatcher"),
    "hive": (".coordinator", "hive"),
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
