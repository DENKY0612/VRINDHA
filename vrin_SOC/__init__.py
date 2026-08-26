"""Vrindha SOC — ethical, defensive-first cybersecurity assistant.

Import this package (or any ``vrin_SOC.*`` module) from the repository root.
Legacy top-level names such as ``core``, ``api`` and ``database`` resolve to the
same module objects via :mod:`vrin_SOC._imports`.
"""

from ._imports import install as _install_import_aliases

__version__ = "1.1.0"

_install_import_aliases()

__all__ = ["__version__"]
