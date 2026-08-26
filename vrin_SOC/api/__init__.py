"""Vrindha API Package — FastAPI application and route bindings.

Supports both canonical (``vrin_SOC.api``) and legacy (``api``) import
paths.  The ``app`` object is re-exported so callers can write::

    from api import app          # legacy flat-import spelling
    from vrin_SOC.api import app # canonical package spelling
"""
from pathlib import Path
import sys

_repo = Path(__file__).resolve().parents[2]
if (_repo / "Vrin_TI").is_dir() and str(_repo) not in sys.path:
    sys.path.insert(0, str(_repo))

try:
    from vrin_SOC._imports import bind_package
except ImportError:  # flat image / unpackaged checkout
    bind_package = None

if bind_package is not None:
    bind_package(__name__)

__all__ = ["app"]

_EXPORTS = {
    "app": (".main", "app"),
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
