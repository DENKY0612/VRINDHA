"""
Gita Engine Module - Bhagavad Gita JSON Integration
Per MASTER BLUEPRINT: Integrate 700 verses with tagging, ethical mapping
"""
import json
import random
from pathlib import Path
from typing import Dict, List, Optional, Any
from .error_handler import ErrorHandler

class GitaEngine:
    """
    Loads Gita JSON once at startup, provides search and ethical guidance.
    File: data/gita.json
    Methods: get_verse, search_by_keyword, get_random_verse, get_ethical_guidance, tag_verse
    """
    
    def __init__(self, json_path: str = "data/gita.json"):
        self.json_path = Path(json_path)
        self.verses = []
        self.loaded = False
        self._tag_index = {}  # tag -> list of verses
        self.load()
    
    def load(self):
        try:
            if not self.json_path.exists():
                # Try alternative paths
                alt_paths = [Path("vrindha/data/gita.json"), Path("../data/gita.json"), Path("/home/user/vrindha/data/gita.json")]
                for p in alt_paths:
                    if p.exists():
                        self.json_path = p
                        break
            with open(self.json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.verses = data.get("verses", [])
            self.loaded = True
            # Build tag index
            for verse in self.verses:
                for tag in verse.get("tags", []):
                    self._tag_index.setdefault(tag, []).append(verse)
            print(f"[GitaEngine] Loaded {len(self.verses)} verses from {self.json_path}")
        except Exception as e:
            ErrorHandler.handle_exception(e, "GitaEngine.load")
            self.verses = []
    
    def get_verse(self, chapter: int, verse: int) -> Dict:
        try:
            for v in self.verses:
                if v.get("chapter") == chapter and (v.get("verse_number") == verse or v.get("verse") == verse):
                    return {
                        "status": "success",
                        "chapter": chapter,
                        "verse": verse,
                        "text": v.get("text"),
                        "meaning": v.get("meaning"),
                        "tags": v.get("tags", []),
                        "message": f"Gita {chapter}.{verse}: {v.get('meaning','')}"
                    }
            return {"status": "not_found", "message": f"Verse {chapter}.{verse} not found", "chapter": chapter, "verse": verse, "text": "True strength lies in protecting, not exploiting.", "meaning": "Perform your duty with righteousness."}
        except Exception as e:
            return ErrorHandler.handle_exception(e, "GitaEngine.get_verse")
    
    def search_by_keyword(self, keyword: str) -> Dict:
        try:
            keyword = keyword.lower()
            results = []
            for v in self.verses:
                if keyword in v.get("text","").lower() or keyword in v.get("meaning","").lower() or keyword in str(v.get("tags",[])).lower():
                    results.append(v)
            return {"status": "success", "keyword": keyword, "count": len(results), "results": results[:10]}  # limit 10
        except Exception as e:
            return ErrorHandler.handle_exception(e, "GitaEngine.search_by_keyword")
    
    def get_random_verse(self) -> Dict:
        try:
            if not self.verses:
                return {"chapter": 2, "verse": 47, "text": "Karmanye vadhikaraste...", "meaning": "Focus on duty, not results", "tags": ["duty"]}
            v = random.choice(self.verses)
            return {
                "chapter": v.get("chapter"),
                "verse": v.get("verse_number"),
                "text": v.get("text"),
                "meaning": v.get("meaning"),
                "tags": v.get("tags")
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "GitaEngine.get_random_verse")
    
    def get_ethical_guidance(self, action_type: str) -> Dict:
        """
        Map action_type to Gita teaching
        attack -> non-harm / non_violence
        defense -> duty / dharma
        learning -> knowledge
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
                "default": ["dharma", "duty"]
            }
            # Find matching tags
            desired_tags = None
            for key, tags in mapping.items():
                if key in action_type:
                    desired_tags = tags
                    break
            if not desired_tags:
                desired_tags = mapping["default"]
            
            # Search for verses with those tags
            candidates = []
            for tag in desired_tags:
                if tag in self._tag_index:
                    candidates.extend(self._tag_index[tag])
            
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
                        "text": chosen.get("text"),
                        "meaning": chosen.get("meaning")
                    },
                    "message": chosen.get("meaning", "Act with duty and righteousness"),
                    "ethical": True
                }
            else:
                # Fallback known verse
                return {
                    "action_type": action_type,
                    "principle": "dharma",
                    "verse": {"chapter": 2, "verse": 47, "text": "Karmanye vadhikaraste", "meaning": "Focus on duty, not results - True strength lies in protecting, not exploiting."},
                    "message": "Use your skills to protect, not harm."
                }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "GitaEngine.get_ethical_guidance")
    
    def tag_verse(self, verse_text: str) -> List[str]:
        """Auto-tag based on keywords"""
        text_lower = verse_text.lower()
        tags = []
        if any(w in text_lower for w in ["dharma", "righteous", "duty"]):
            tags.append("dharma")
        if any(w in text_lower for w in ["control", "mind", "discipline"]):
            tags.append("self_control")
        if any(w in text_lower for w in ["knowledge", "wisdom", "learn"]):
            tags.append("knowledge")
        if any(w in text_lower for w in ["non-violence", "ahimsa", "protect", "harm"]):
            tags.append("non_violence")
        if any(w in text_lower for w in ["duty", "karma", "action"]):
            tags.append("duty")
        return tags if tags else ["dharma"]

# Singleton instance
gita_engine = GitaEngine()
