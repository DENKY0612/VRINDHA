"""Import-structure smoke tests for the remodeled package layout."""
from __future__ import annotations

import compileall
import importlib
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_vrin_soc_and_vrin_ti_are_importable_packages():
    soc = importlib.import_module("vrin_SOC")
    ti = importlib.import_module("Vrin_TI")
    assert soc.__version__
    assert ti.__version__
    assert Path(soc.__file__).resolve().parent == REPO_ROOT / "vrin_SOC"
    assert Path(ti.__file__).resolve().parent == REPO_ROOT / "Vrin_TI"


def test_legacy_and_canonical_names_are_the_same_module():
    importlib.import_module("vrin_SOC")
    canonical = importlib.import_module("vrin_SOC.core.gita_engine")
    legacy = importlib.import_module("core.gita_engine")
    assert canonical is legacy
    assert sys.modules["core.gita_engine"] is sys.modules["vrin_SOC.core.gita_engine"]
    assert sys.modules["api"] is sys.modules["vrin_SOC.api"]


def test_vrin_ti_relative_package_imports():
    models = importlib.import_module("Vrin_TI.models")
    engine_mod = importlib.import_module("Vrin_TI.engine")
    assert models.ThreatIndicator is not None
    assert engine_mod.ThreatIntelligenceEngine is not None


def test_packages_compile():
    assert compileall.compile_dir(str(REPO_ROOT / "vrin_SOC"), quiet=1, maxlevels=10)
    assert compileall.compile_dir(str(REPO_ROOT / "Vrin_TI"), quiet=1, maxlevels=10)


def test_legacy_short_imports_used_by_docs_still_work():
    from core.gita_engine import GitaEngine
    from api.auth import AuthModule

    assert GitaEngine is importlib.import_module("vrin_SOC.core.gita_engine").GitaEngine
    assert AuthModule is importlib.import_module("vrin_SOC.api.auth").AuthModule
