"""
Knowledge Base Prompt - Cybersecurity Knowledge Base
Content: Known vulnerabilities (CVE-style), attack patterns, defense strategies
Use: Assist agents in decision-making, provide explanations, update continuously
"""
import json
from pathlib import Path
from typing import Dict, List
from .error_handler import ErrorHandler

class KnowledgeBase:
    def __init__(self, kb_path: str = "data/knowledge.json"):
        self.kb_path = Path(kb_path)
        self.data = {"vulnerabilities": [], "attack_patterns": [], "defense_strategies": []}
        self.load()
    
    def load(self):
        try:
            # Try multiple paths
            candidates = [self.kb_path, Path("vrindha/data/knowledge.json"), Path("/home/user/vrindha/data/knowledge.json")]
            for p in candidates:
                if p.exists():
                    self.kb_path = p
                    break
            if self.kb_path.exists():
                with open(self.kb_path, 'r') as f:
                    self.data = json.load(f)
                print(f"[KnowledgeBase] Loaded from {self.kb_path}")
        except Exception as e:
            ErrorHandler.handle_exception(e, "KnowledgeBase.load")
    
    def search_vulnerability(self, keyword: str) -> List[Dict]:
        try:
            kw = keyword.lower()
            results = []
            for vuln in self.data.get("vulnerabilities", []):
                if kw in str(vuln).lower():
                    results.append(vuln)
            return results
        except Exception as e:
            ErrorHandler.handle_exception(e, "KnowledgeBase.search_vulnerability")
            return []
    
    def get_defense_for(self, threat_type: str) -> Dict:
        try:
            for strat in self.data.get("defense_strategies", []):
                if threat_type.lower() in strat.get("strategy","").lower() or threat_type.lower() in str(strat.get("when","")).lower():
                    return strat
            # Default
            return {"strategy": "Block Suspicious IP", "tools": ["ufw","fail2ban"], "when": "Generic threat"}
        except Exception as e:
            return ErrorHandler.handle_exception(e, "KnowledgeBase.get_defense_for")
    
    def get_attack_pattern(self, pattern_name: str) -> Dict:
        for pat in self.data.get("attack_patterns", []):
            if pattern_name.lower() in pat.get("pattern","").lower():
                return pat
        return {}
    
    def update_from_new_data(self, new_entry: Dict):
        try:
            # Continuous learning: append new threat
            if "type" in new_entry and new_entry["type"] == "vulnerability":
                self.data["vulnerabilities"].append(new_entry)
            elif new_entry.get("type") == "attack":
                self.data["attack_patterns"].append(new_entry)
            # Save back
            with open(self.kb_path, 'w') as f:
                json.dump(self.data, f, indent=2)
            return {"status": "success", "message": "Knowledge base updated"}
        except Exception as e:
            return ErrorHandler.handle_exception(e, "KnowledgeBase.update")

knowledge_base = KnowledgeBase()
