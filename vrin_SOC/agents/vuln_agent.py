"""
Vulnerability Agent - Per MASTER BLUEPRINT and Day 15-16
Tools: nikto, openvas, searchsploit (suggestion)
Flow: Ask for confirmation (handled by Brain), scan target, return vulnerabilities, no automatic execution
"""
from typing import Dict
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from tools.nikto_tool import run_nikto
from core.error_handler import ErrorHandler
from core.knowledge_base import knowledge_base
from datetime import datetime

class VulnAgent:
    def __init__(self):
        self.name = "VulnAgent"
    
    def run(self, target: str = "127.0.0.1") -> Dict:
        try:
            # Per blueprint: Use nikto for web vuln
            nikto_result = run_nikto(target)
            
            # Also check knowledge base for relevant vulns
            kb_hits = knowledge_base.search_vulnerability(target)
            
            # Dummy vulnerability data per Day 15 if needed
            dummy_vulns = [
                {"id": "VULN-001", "name": "Open Port 22", "severity": "Low", "description": "SSH port open, ensure secured"},
                {"id": "VULN-002", "name": "Directory Listing", "severity": "Medium", "description": "Potential directory indexing enabled"},
                {"id": "VULN-003", "name": "Outdated Apache", "severity": "High", "description": "Apache version may have known CVEs, check searchsploit"}
            ]
            
            return {
                "type": "vulnerability_scan",
                "agent": self.name,
                "target": target,
                "status": nikto_result.get("status","success"),
                "vulnerabilities": dummy_vulns,
                "nikto_output": nikto_result.get("result","")[:2000],
                "knowledge_base_matches": kb_hits,
                "severity_summary": {"Low": 1, "Medium": 1, "High": 1},
                "timestamp": datetime.now().isoformat(),
                "recommendation": "Map CVEs using searchsploit, patch outdated services"
            }
        except Exception as e:
            err = ErrorHandler.handle_exception(e, "VulnAgent.run")
            return {
                "type": "vulnerability_scan",
                "agent": self.name,
                "target": target,
                "vulnerabilities": [{"id": "dummy", "severity": "Low", "description": "dummy vulnerability data"}],
                "status": "error",
                "error": str(e)
            }

vuln_agent = VulnAgent()
