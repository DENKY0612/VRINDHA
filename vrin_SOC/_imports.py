"""Canonical import bootstrap and legacy-name aliases for the SOC package.

The repository is a two-package tree:

* ``vrin_SOC`` — SOC CLI, API, agents, tools
* ``Vrin_TI`` — independent threat-intelligence service

Library modules import those names from the repository root.  Historically the
SOC was launched with ``vrin_SOC/`` on ``sys.path`` (``from core.brain import
brain``, ``uvicorn api.main:app``).  This module keeps both spellings bound to
the *same* module objects so singletons are not duplicated.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional
import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import sys

LEGACY_ROOTS: tuple[str, ...] = (
    "agents",
    "api",
    "automation",
    "autonomous",
    "core",
    "database",
    "ml",
    "tools",
)
CANONICAL_PREFIX = "vrin_SOC"
_INSTALL_FLAG = "_vrindha_import_aliases_installed"


def repository_root(start: Optional[Path] = None) -> Path:
    """Locate the checkout that contains both ``vrin_SOC`` and ``Vrin_TI``."""
    here = Path(start or __file__).resolve()
    for candidate in (here, *here.parents):
        if (candidate / "vrin_SOC").is_dir() and (candidate / "Vrin_TI").is_dir():
            return candidate
    # Fall back to the parent of this package (``<root>/vrin_SOC/_imports.py``).
    return Path(__file__).resolve().parents[1]


def ensure_repository_root(start: Optional[Path] = None) -> Path:
    """Put the repository root on ``sys.path`` if it is not already there."""
    root = repository_root(start)
    root_str = str(root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    return root


def _legacy_name(canonical: str) -> Optional[str]:
    prefix = CANONICAL_PREFIX + "."
    if not canonical.startswith(prefix):
        return None
    remainder = canonical[len(prefix):]
    if remainder.split(".", 1)[0] in LEGACY_ROOTS:
        return remainder
    return None


def _canonical_name(legacy: str) -> Optional[str]:
    root = legacy.split(".", 1)[0]
    if root in LEGACY_ROOTS:
        return f"{CANONICAL_PREFIX}.{legacy}"
    return None


def alias_loaded(names: Optional[Iterable[str]] = None) -> None:
    """Bind ``core.*`` ↔ ``vrin_SOC.core.*`` for every already-imported module."""
    snapshot = list(names) if names is not None else list(sys.modules)
    for name in snapshot:
        module = sys.modules.get(name)
        if module is None:
            continue
        legacy = _legacy_name(name)
        if legacy:
            existing = sys.modules.get(legacy)
            if existing is None:
                sys.modules[legacy] = module
            elif existing is not module:
                # Prefer the canonical object so later imports share singletons.
                sys.modules[legacy] = module
            continue
        canonical = _canonical_name(name)
        if canonical:
            existing = sys.modules.get(canonical)
            if existing is None:
                sys.modules[canonical] = module
            elif existing is not module:
                sys.modules[name] = existing


class _AliasLoader(importlib.abc.Loader):
    def __init__(self, canonical: str) -> None:
        self.canonical = canonical

    def create_module(self, spec):  # type: ignore[override]
        return importlib.import_module(self.canonical)

    def exec_module(self, module) -> None:  # type: ignore[override]
        alias_loaded((self.canonical, getattr(module, "__name__", self.canonical)))


class _VrindhaAliasFinder(importlib.abc.MetaPathFinder):
    """Map ``core.brain`` → ``vrin_SOC.core.brain`` when the package exists."""

    _busy = False

    def find_spec(self, fullname, path, target=None):  # type: ignore[override]
        if self._busy:
            return None
        canonical = _canonical_name(fullname)
        if canonical is None:
            return None
        if fullname in sys.modules and canonical in sys.modules:
            return None
        if canonical in sys.modules:
            spec = importlib.machinery.ModuleSpec(fullname, _AliasLoader(canonical))
            spec.origin = getattr(sys.modules[canonical], "__file__", None)
            spec.submodule_search_locations = getattr(sys.modules[canonical], "__path__", None)
            return spec
        self._busy = True
        try:
            found = importlib.util.find_spec(canonical)
        except (ImportError, ValueError, ModuleNotFoundError):
            found = None
        finally:
            self._busy = False
        if found is None:
            return None
        spec = importlib.machinery.ModuleSpec(
            fullname,
            _AliasLoader(canonical),
            origin=found.origin,
            is_package=found.submodule_search_locations is not None,
        )
        spec.submodule_search_locations = found.submodule_search_locations
        return spec


def install() -> None:
    """Install the alias finder once and sync already-imported modules."""
    ensure_repository_root()
    if getattr(sys, _INSTALL_FLAG, False):
        alias_loaded()
        return
    if not any(isinstance(finder, _VrindhaAliasFinder) for finder in sys.meta_path):
        sys.meta_path.insert(0, _VrindhaAliasFinder())
    setattr(sys, _INSTALL_FLAG, True)
    alias_loaded()


def bind_package(module_name: str) -> None:
    """Called from package ``__init__`` files so either spelling is registered."""
    install()
    module = sys.modules.get(module_name)
    if module is None:
        return
    legacy = _legacy_name(module_name)
    if legacy:
        sys.modules.setdefault(legacy, module)
        return
    canonical = _canonical_name(module_name)
    if canonical:
        sys.modules.setdefault(canonical, module)
