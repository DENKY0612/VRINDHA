"""
Vrindha Self-Improvement Engine
A built-in learning system that tracks user interactions, identifies knowledge gaps,
and continuously improves the AI's capabilities over time.
"""
import json
import re
import random
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional


class SelfImprovementEngine:
    """
    Tracks user interactions, identifies patterns, and improves Vrindha's responses.
    
    Capabilities:
    - Learn from every interaction (what user asks, what worked, what didn't)
    - Identify knowledge gaps and suggest improvements
    - Auto-update knowledge base with new topics
    - Track command patterns and user preferences
    - Self-assess and improve based on usage analytics
    """
    
    def __init__(self):
        """Initialize the self-improvement engine."""
        self.project_root = self._detect_project_root()
        self.improvement_file = self.project_root / "vrin_SOC" / "data" / "improvement_log.json"
        self.interaction_log: List[Dict] = []
        self.knowledge_gaps: List[Dict] = []
        self.improvement_suggestions: List[Dict] = []
        self._load_data()
        
    def _detect_project_root(self) -> Path:
        """Detect Vrindha project root."""
        current = Path.cwd()
        for path in [current] + list(current.parents):
            if (path / "vrin_SOC").is_dir():
                return path
        fallback = Path("/mnt/c/Users/n4ndh/Documents/port/vrind/BACKEND")
        if fallback.exists():
            return fallback
        return current
    
    def _load_data(self):
        """Load improvement data from disk."""
        try:
            if self.improvement_file.exists():
                data = json.loads(self.improvement_file.read_text(encoding="utf-8"))
                self.interaction_log = data.get("interactions", [])[-500:]  # Keep last 500
                self.knowledge_gaps = data.get("knowledge_gaps", [])[-50:]
                self.improvement_suggestions = data.get("improvements", [])[-50:]
        except Exception:
            pass
    
    def _save_data(self):
        """Save improvement data to disk."""
        try:
            data = {
                "interactions": self.interaction_log[-500:],
                "knowledge_gaps": self.knowledge_gaps[-50:],
                "improvements": self.improvement_suggestions[-50:],
                "last_updated": datetime.now().isoformat()
            }
            self.improvement_file.parent.mkdir(parents=True, exist_ok=True)
            self.improvement_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass
    
    def log_interaction(self, user_input: str, response: str, mode: str = "soc"):
        """
        Log every interaction for pattern analysis.
        
        Args:
            user_input: What the user asked
            response: What Vrindha responded
            mode: Which mode (soc, daily, dev)
        """
        interaction = {
            "timestamp": datetime.now().isoformat(),
            "user_input": user_input[:200],
            "response_preview": response[:200],
            "mode": mode,
            "category": self._categorize(user_input),
            "outcome": self._assess_outcome(user_input, response)
        }
        self.interaction_log.append(interaction)
        
        # Check for knowledge gaps
        self._detect_knowledge_gap(user_input, response)
        
        # Save periodically
        if len(self.interaction_log) % 10 == 0:
            self._save_data()
    
    def _categorize(self, user_input: str) -> str:
        """Categorize user input."""
        lower = user_input.lower()
        if any(w in lower for w in ["scan", "nmap", "recon", "discover"]):
            return "reconnaissance"
        elif any(w in lower for w in ["vuln", "nikto", "exploit", "cve"]):
            return "vulnerability"
        elif any(w in lower for w in ["threat", "attack", "malware", "incident"]):
            return "threat_analysis"
        elif any(w in lower for w in ["help", "how", "what", "explain", "teach"]):
            return "education"
        elif any(w in lower for w in ["fix", "patch", "secure", "protect"]):
            return "remediation"
        elif any(w in lower for w in ["code", "file", "read", "edit", "patch"]):
            return "development"
        elif any(w in lower for w in ["who are", "about you", "capabilities"]):
            return "identity"
        elif any(w in lower for w in ["how are", "joke", "funny", "hello", "hi"]):
            return "casual"
        return "general"
    
    def _assess_outcome(self, user_input: str, response: str) -> str:
        """Assess if the interaction was successful."""
        lower_response = response.lower()
        failure_indicators = [
            "i can't", "i cannot", "i don't know", "i'm sorry",
            "unable to", "failed", "not capable", "cannot help",
            "no specific knowledge", "not in my", "unavailable"
        ]
        if any(ind in lower_response for ind in failure_indicators):
            return "failure"
        if len(response) > 100 and "success" in lower_response:
            return "success"
        return "partial"
    
    def _detect_knowledge_gap(self, user_input: str, response: str):
        """Detect knowledge gaps from failed interactions."""
        if self._assess_outcome(user_input, response) == "failure":
            gap = {
                "query": user_input[:200],
                "timestamp": datetime.now().isoformat(),
                "category": self._categorize(user_input),
                "resolved": False
            }
            self.knowledge_gaps.append(gap)
    
    def get_improvement_report(self) -> str:
        """
        Generate a self-improvement report based on interaction analysis.
        
        Returns:
            Formatted report string
        """
        total = len(self.interaction_log) or 1
        successes = sum(1 for i in self.interaction_log if i["outcome"] == "success")
        failures = sum(1 for i in self.interaction_log if i["outcome"] == "partial")
        
        category_counts: Dict[str, int] = {}
        for interaction in self.interaction_log:
            cat = interaction["category"]
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        # Find top knowledge gaps
        unresolved_gaps = [g for g in self.knowledge_gaps if not g["resolved"]]
        
        report = (
            "📊 Vrindha Self-Improvement Report\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📈 Total Interactions: {total}\n"
            f"✅ Success Rate: {successes * 100 // total}%\n"
            f"⚠️ Partial/Failures: {failures * 100 // total}%\n"
            "\n📊 Usage by Category:\n"
        )
        
        for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
            bar = "█" * (count * 20 // total)
            report += f"  {cat:20s} {bar} {count}\n"
        
        if unresolved_gaps:
            report += f"\n🔍 Knowledge Gaps ({len(unresolved_gaps)}):\n"
            for gap in unresolved_gaps[:5]:
                report += f"  • [{gap['category']}] {gap['query'][:60]}\n"
        
        if self.improvement_suggestions:
            report += f"\n💡 Improvement Suggestions:\n"
            for sug in self.improvement_suggestions[-5:]:
                report += f"  • {sug.get('suggestion', 'N/A')[:80]}\n"
        
        report += "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        return report
    
    def get_self_improvement_suggestions(self) -> List[str]:
        """
        Generate actionable improvement suggestions based on analysis.
        
        Returns:
            List of suggestion strings
        """
        suggestions = []
        
        # Analyze patterns
        categories: Dict[str, int] = {}
        for interaction in self.interaction_log:
            cat = interaction["category"]
            categories[cat] = categories.get(cat, 0) + 1
        
        total = len(self.interaction_log) or 1
        
        # Suggest based on patterns
        if categories.get("reconnaissance", 0) > total * 0.3:
            suggestions.append("High recon usage — consider adding more scan presets and output detail")
        if categories.get("vulnerability", 0) > total * 0.2:
            suggestions.append("Vulnerability scanning is frequent — expand knowledge base with more CVE mappings")
        if categories.get("education", 0) > total * 0.2:
            suggestions.append("Many education requests — add more daily topics and learning paths")
        if categories.get("threat_analysis", 0) > total * 0.1:
            suggestions.append("Threat analysis common — add more threat intelligence integrations")
        
        # Suggest based on failures
        unresolved = [g for g in self.knowledge_gaps if not g["resolved"]]
        if len(unresolved) > 5:
            suggestions.append(f"Found {len(unresolved)} unresolved knowledge gaps — consider web search expansion")
        
        self.improvement_suggestions.extend([
            {"suggestion": s, "timestamp": datetime.now().isoformat()}
            for s in suggestions
        ])
        
        return suggestions
    
    def auto_improve(self) -> Dict[str, Any]:
        """
        Run automatic self-improvement routines.
        
        Returns:
            Dict with improvement results
        """
        results = {
            "timestamp": datetime.now().isoformat(),
            "actions_taken": [],
            "suggestions": []
        }
        
        # 1. Identify and log knowledge gaps
        gaps = [g for g in self.knowledge_gaps if not g["resolved"]]
        if gaps:
            results["actions_taken"].append(f"Found {len(gaps)} unresolved knowledge gaps")
        
        # 2. Generate improvement suggestions
        suggestions = self.get_self_improvement_suggestions()
        results["suggestions"] = suggestions
        if suggestions:
            results["actions_taken"].append(f"Generated {len(suggestions)} improvement suggestions")
        
        # 3. Clean old data
        if len(self.interaction_log) > 500:
            self.interaction_log = self.interaction_log[-500:]
            results["actions_taken"].append("Trimmed interaction log to 500 entries")
        
        # 4. Save state
        self._save_data()
        results["actions_taken"].append("Saved improvement state")
        
        return results


# Global instance
_self_improvement: Optional[SelfImprovementEngine] = None


def get_improvement_engine() -> SelfImprovementEngine:
    """Get or create the global self-improvement engine instance."""
    global _self_improvement
    if _self_improvement is None:
        _self_improvement = SelfImprovementEngine()
    return _self_improvement


def log_interaction(user_input: str, response: str, mode: str = "soc"):
    """Convenience function to log an interaction."""
    engine = get_improvement_engine()
    engine.log_interaction(user_input, response, mode)


def get_report() -> str:
    """Convenience function to get improvement report."""
    engine = get_improvement_engine()
    return engine.get_improvement_report()


def run_auto_improve() -> Dict[str, Any]:
    """Convenience function to run auto-improvement."""
    engine = get_improvement_engine()
    return engine.auto_improve()
