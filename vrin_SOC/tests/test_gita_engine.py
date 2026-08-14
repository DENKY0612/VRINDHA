import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from core.gita_engine import GitaEngine


def test_gita_engine_loads_bhagavad_gita_chapter_files():
    engine = GitaEngine()

    assert engine.loaded is True
    assert engine.source_type == "BhagavadGita"
    assert len(engine.verses) >= 700

    verse = engine.get_verse(1, 1)
    assert verse["status"] == "success"
    assert verse["chapter"] == 1
    assert verse["verse"] == 1
    assert verse["meaning"]
    assert verse["text"]
    assert verse["sanskrit"]
