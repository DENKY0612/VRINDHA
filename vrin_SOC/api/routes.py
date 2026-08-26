"""API Routes — modular route re-exports for the Vrindha API package.

Supports both ``from api.routes import app`` (legacy) and
``from vrin_SOC.api.routes import app`` (canonical).
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

from .main import app  # noqa: F401 — re-export for organizational clarity

# Additional route modules can be imported here for modularity per blueprint.
__all__ = ["app"]
