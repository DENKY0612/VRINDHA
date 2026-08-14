"""
Gita Engine Module - Bhagavad Gita JSON Integration
Per MASTER BLUEPRINT: integrate all 18 chapters and 700+ verses for ethical guidance
and user education.
"""
import json
import random
from pathlib import Path
from typing import Any, Dict, List, Optional

from .error_handler import ErrorHandler


class GitaEngine:
    """
    Loads Bhagavad Gita chapter JSON files once at startup, provides search,
    verse lookup, random verse selection, and ethical guidance.
    """

    def __init__(self, json_path: Optional[str] = None, chapter_dir: Optional[str] = None):
        self.json_path = Path(json_path) if json_path else None
        self.chapter_dir = Path(chapter_dir) if chapter_dir else None
        self.verses: List[Dict[str, Any]] = []
        self.chapters: Dict[int, Dict[str, Any]] = {}
        self.loaded = False
        self.source_type = "none"
        self._tag_index: Dict[str, List[Dict[str, Any]]] = {}
        self.load()

    def _resolve_paths(self) -> List[Path]:
        repo_root = Path(__file__).resolve().parent.parent
        candidates: List[Path] = []

        if self.json_path is not None:
            candidates.append(self.json_path)
        if self.chapter_dir is not None:
            candidates.append(self.chapter_dir)

        candidates.extend(
            [
                repo_root / "data" / "BhagavadGita",
                repo_root / "data" / "gita.json",
                repo_root / "vrindha" / "data" / "BhagavadGita",
                repo_root / "vrindha" / "data" / "gita.json",
                Path("data/BhagavadGita"),
                Path("data/gita.json"),
            ]
        )

        resolved: List[Path] = []
        seen = set()
        for candidate in candidates:
            if candidate is None:
                continue
            path = candidate if candidate.is_absolute() else (repo_root / candidate).resolve()
            if path not in seen:
                seen.add(path)
                resolved.append(path)
        return resolved

    def load(self) -> None:
        try:
            self.verses = []
            self.chapters = {}
            self._tag_index = {}

            chapter_files: List[Path] = []
            for path in self._resolve_paths():
                if path.is_dir():
                    chapter_files.extend(sorted(path.glob("bhagavad_gita_chapter_*.json")))
                elif path.is_file() and path.name.endswith(".json") and "bhagavad_gita_chapter_" in path.name:
                    chapter_files.append(path)

            if chapter_files:
                for chapter_file in chapter_files:
                    with open(chapter_file, "r", encoding="utf-8") as handle:
                        data = json.load(handle)

                    chapter_data = data.get("bhagavadGita", {}).get("chapter", {})
                    chapter_number = int(chapter_data.get("number", 0))
                    if not chapter_number:
                        continue

                    chapter_meta = {
                        "chapter": chapter_number,
                        "name": chapter_data.get("name", f"Chapter {chapter_number}"),
                        "englishName": chapter_data.get("englishName", f"Chapter {chapter_number}"),
                        "description": chapter_data.get("description", ""),
                        "totalVerses": chapter_data.get("totalVerses", 0),
                        "theme": chapter_data.get("theme", ""),
                        "speakers": chapter_data.get("speakers", []),
                    }
                    self.chapters[chapter_number] = chapter_meta

                    for verse_data in data.get("bhagavadGita", {}).get("verses", []):
                        verse_number = verse_data.get("verseNumber") or verse_data.get("verse") or verse_data.get("number")
                        normalized = {
                            "chapter": chapter_number,
                            "chapter_name": chapter_meta["name"],
                            "english_name": chapter_meta["englishName"],
                            "description": chapter_meta["description"],
                            "theme": chapter_meta["theme"],
                            "verse_number": verse_number,
                            "verse": verse_number,
                            "text": verse_data.get("englishTranslation") or verse_data.get("meaning") or verse_data.get("sanskrit", ""),
                            "meaning": verse_data.get("meaning") or verse_data.get("englishTranslation") or verse_data.get("sanskrit", ""),
                            "sanskrit": verse_data.get("sanskrit", ""),
                            "transliteration": verse_data.get("transliteration", ""),
                            "english_translation": verse_data.get("englishTranslation", ""),
                            "speaker": verse_data.get("speaker", ""),
                            "tags": self.tag_verse(
                                f"{verse_data.get('meaning', '')} {verse_data.get('englishTranslation', '')} {verse_data.get('sanskrit', '')}"
                            ),
                            "source": "BhagavadGita",
                        }
                        self.verses.append(normalized)

                self.loaded = True
                self.source_type = "BhagavadGita"
            else:
                for path in self._resolve_paths():
                    if path.is_file() and path.name == "gita.json":
                        with open(path, "r", encoding="utf-8") as handle:
                            data = json.load(handle)
                        self.verses = data.get("verses", [])
                        self.loaded = True
                        self.source_type = "gita.json"
                        break

            for verse in self.verses:
                for tag in verse.get("tags", []):
                    self._tag_index.setdefault(tag, []).append(verse)

            print(f"[GitaEngine] Loaded {len(self.verses)} verses from {self.source_type}")
        except Exception as exc:
            ErrorHandler.handle_exception(exc, "GitaEngine.load")
            self.verses = []
            self.loaded = False
            self.source_type = "none"

    def get_chapter(self, chapter: int) -> Dict[str, Any]:
        try:
            chapter_verses = [verse for verse in self.verses if verse.get("chapter") == chapter]
            chapter_meta = self.chapters.get(chapter, {})
            return {
                "status": "success" if chapter_verses else "not_found",
                "chapter": chapter,
                "chapter_name": chapter_meta.get("name", f"Chapter {chapter}"),
                "english_name": chapter_meta.get("englishName", f"Chapter {chapter}"),
                "description": chapter_meta.get("description", ""),
                "theme": chapter_meta.get("theme", ""),
                "total_verses": len(chapter_verses),
                "verses": chapter_verses,
            }
        except Exception as exc:
            return ErrorHandler.handle_exception(exc, "GitaEngine.get_chapter")

    def get_verse(self, chapter: int, verse: int) -> Dict[str, Any]:
        try:
            for entry in self.verses:
                if entry.get("chapter") == chapter and (entry.get("verse_number") == verse or entry.get("verse") == verse):
                    return {
                        "status": "success",
                        "chapter": chapter,
                        "chapter_name": entry.get("chapter_name", f"Chapter {chapter}"),
                        "verse": entry.get("verse_number") or entry.get("verse"),
                        "text": entry.get("text", ""),
                        "meaning": entry.get("meaning", ""),
                        "sanskrit": entry.get("sanskrit", ""),
                        "transliteration": entry.get("transliteration", ""),
                        "english_translation": entry.get("english_translation", ""),
                        "speaker": entry.get("speaker", ""),
                        "tags": entry.get("tags", []),
                        "message": f"Gita {chapter}.{entry.get('verse_number') or entry.get('verse')}: {entry.get('meaning', '')}",
                    }
            return {
                "status": "not_found",
                "message": f"Verse {chapter}.{verse} not found",
                "chapter": chapter,
                "verse": verse,
                "text": "True strength lies in protecting, not exploiting.",
                "meaning": "Perform your duty with righteousness.",
            }
        except Exception as exc:
            return ErrorHandler.handle_exception(exc, "GitaEngine.get_verse")

    def search_by_keyword(self, keyword: str) -> Dict[str, Any]:
        try:
            keyword = keyword.lower()
            results = []
            for verse in self.verses:
                haystack = " ".join(
                    [
                        str(verse.get("text", "")),
                        str(verse.get("meaning", "")),
                        str(verse.get("english_translation", "")),
                        str(verse.get("sanskrit", "")),
                        str(verse.get("chapter_name", "")),
                        str(verse.get("speaker", "")),
                        str(verse.get("tags", [])),
                    ]
                ).lower()
                if keyword in haystack:
                    results.append(verse)
            return {"status": "success", "keyword": keyword, "count": len(results), "results": results[:10]}
        except Exception as exc:
            return ErrorHandler.handle_exception(exc, "GitaEngine.search_by_keyword")

    def get_random_verse(self) -> Dict[str, Any]:
        try:
            if not self.verses:
                return {"chapter": 2, "verse": 47, "text": "Karmanye vadhikaraste...", "meaning": "Focus on duty, not results", "tags": ["duty"]}
            verse = random.choice(self.verses)
            return {
                "chapter": verse.get("chapter"),
                "verse": verse.get("verse_number"),
                "chapter_name": verse.get("chapter_name"),
                "text": verse.get("text"),
                "meaning": verse.get("meaning"),
                "sanskrit": verse.get("sanskrit"),
                "speaker": verse.get("speaker"),
                "tags": verse.get("tags"),
            }
        except Exception as exc:
            return ErrorHandler.handle_exception(exc, "GitaEngine.get_random_verse")

    def get_ethical_guidance(self, action_type: str) -> Dict[str, Any]:
        """
        Map action_type to Gita teaching.
        """
        try:
            action_type = action_type.lower()
            mapping = {
                "attack": ["non_violence", "self_control", "dharma"],
                "exploit": ["non_violence", "self_control", "dharma"],
                "hack": ["non_violence", "self_control"],
                "defense": ["duty", "dharma", "protection"],
                "protect": ["duty", "protection", "dharma"],
                "block": ["protection", "duty"],
                "learning": ["knowledge", "wisdom", "duty"],
                "learn": ["knowledge", "wisdom"],
                "knowledge": ["knowledge", "wisdom"],
                "scan": ["duty", "knowledge"],
                "default": ["dharma", "duty"],
            }

            desired_tags = None
            for key, tags in mapping.items():
                if key in action_type:
                    desired_tags = tags
                    break
            if not desired_tags:
                desired_tags = mapping["default"]

            candidates: List[Dict[str, Any]] = []
            for tag in desired_tags:
                candidates.extend(self._tag_index.get(tag, []))

            if not candidates:
                candidates = self.verses

            if candidates:
                chosen = random.choice(candidates)
                return {
                    "action_type": action_type,
                    "principle": desired_tags[0],
                    "verse": {
                        "chapter": chosen.get("chapter"),
                        "verse": chosen.get("verse_number"),
                        "chapter_name": chosen.get("chapter_name"),
                        "text": chosen.get("text"),
                        "meaning": chosen.get("meaning"),
                    },
                    "message": chosen.get("meaning", "Act with duty and righteousness"),
                    "ethical": True,
                }

            return {
                "action_type": action_type,
                "principle": "dharma",
                "verse": {"chapter": 2, "verse": 47, "text": "Karmanye vadhikaraste", "meaning": "Focus on duty, not results - True strength lies in protecting, not exploiting."},
                "message": "Use your skills to protect, not harm.",
                "ethical": True,
            }
        except Exception as exc:
            return ErrorHandler.handle_exception(exc, "GitaEngine.get_ethical_guidance")

    def tag_verse(self, verse_text: str) -> List[str]:
        """Auto-tag based on keywords for ethical guidance and education."""
        text_lower = verse_text.lower()
        tags: List[str] = []
        if any(word in text_lower for word in ["dharma", "righteous", "duty", "karma"]):
            tags.append("dharma")
        if any(word in text_lower for word in ["control", "mind", "discipline", "self-control"]):
            tags.append("self_control")
        if any(word in text_lower for word in ["knowledge", "wisdom", "learn", "understanding"]):
            tags.append("knowledge")
        if any(word in text_lower for word in ["non-violence", "ahimsa", "protect", "harm", "peace"]):
            tags.append("non_violence")
        if any(word in text_lower for word in ["duty", "action", "service", "responsibility"]):
            tags.append("duty")
        if any(word in text_lower for word in ["protection", "defense", "safety", "guard"]):
            tags.append("protection")
        return tags if tags else ["dharma"]


# Singleton instance
gita_engine = GitaEngine()
