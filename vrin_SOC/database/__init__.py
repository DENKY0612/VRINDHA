"""Vrindha Database Package"""
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
