"""Vulnerability agent: nikto/HTTP probe plus knowledge-base mapping."""
from datetime import datetime
import sys
from pathlib import Path
from typing import Dict

sys.path.append(str(Path(__file__).parent.parent))

from tools.nikto_tool import run_nikto
from core.error_handler import ErrorHandler
from core.knowledge_base import knowledge_base


class VulnAgent:
    def __init__(self):
        self.name = "VulnAgent"

    def run(self, target: str = "127.0.0.1") -> Dict:
        try:
            nikto_result = run_nikto(target)
            kb_hits = knowledge_base.search_vulnerability(target) or knowledge_base.search_vulnerability("port")
            discovered = list(nikto_result.get("vulnerabilities") or [])
            if not discovered:
                for item in nikto_result.get("findings") or []:
                    discovered.append({
                        "id": f"HTTP-{item.get('status')}",
                        "name": f"Path {item.get('path')}",
                        "severity": "Low" if item.get("status") in {200, 301, 302} else "Medium",
                        "description": f"HTTP {item.get('status')} at {item.get('path')}",
                    })
            if not discovered and nikto_result.get("status") == "success":
                discovered.append({
                    "id": "INFO-001",
                    "name": "No high-signal web findings",
                    "severity": "Low",
                    "description": "Probe completed; no common sensitive paths responded",
                })
            summary = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
            for vuln in discovered:
                level = str(vuln.get("severity", "Low")).title()
                summary[level] = summary.get(level, 0) + 1
            return {
                "type": "vulnerability_scan",
                "agent": self.name,
                "target": target,
                "status": nikto_result.get("status", "success"),
                "engine": nikto_result.get("engine"),
                "vulnerabilities": discovered,
                "nikto_output": (nikto_result.get("result") or "")[:2000],
                "knowledge_base_matches": kb_hits[:5],
                "severity_summary": summary,
                "timestamp": datetime.now().isoformat(),
                "recommendation": "Review exposed paths, patch outdated services, and confirm findings before any exploit research",
            }
        except Exception as e:
            err = ErrorHandler.handle_exception(e, "VulnAgent.run")
            return {
                "type": "vulnerability_scan",
                "agent": self.name,
                "target": target,
                "vulnerabilities": [],
                "status": "error",
                "error": str(e),
                "details": err,
            }


vuln_agent = VulnAgent()
