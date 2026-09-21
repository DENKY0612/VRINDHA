"""Vulnerability agent: nikto/HTTP probe plus knowledge-base mapping."""
from datetime import datetime
import time
from typing import Dict

from vrin_SOC.tools.nikto_tool import run_nikto
from vrin_SOC.core.error_handler import ErrorHandler
from vrin_SOC.core.knowledge_base import knowledge_base


class VulnAgent:
    def __init__(self):
        self.name = "VulnAgent"

    def run(self, target: str = "127.0.0.1") -> Dict:
        start_time = time.time()
        try:
            nikto_result = run_nikto(target)
            kb_hits = knowledge_base.search_vulnerability(target) or knowledge_base.search_vulnerability("port")
            discovered = list(nikto_result.get("vulnerabilities") or [])
            
            # Determine IP type and reverse DNS
            is_ipv6 = ":" in target and not target.startswith("[")
            reverse_dns = None
            try:
                import socket
                reverse_dns = socket.gethostbyaddr(target.strip("[]"))[0]
            except Exception:
                pass
            
            # Parse findings from HTTP probe output
            if not discovered:
                for item in nikto_result.get("findings") or []:
                    path = item.get("path", "")
                    status = item.get("status")
                    
                    # Determine severity based on path and status
                    severity = "Low"
                    if path in {"/admin", "/login", "/config", "/backup", "/.git/HEAD", "/server-status"}:
                        severity = "Medium"
                    elif status == 200 and "/.env" in path:
                        severity = "High"
                    elif status == 200 and "/wp-admin" in path:
                        severity = "Medium"
                    
                    discovered.append({
                        "id": f"PATH-{status}",
                        "name": f"Exposed path: {path}",
                        "severity": severity,
                        "description": f"HTTP {status} at {path}",
                        "recommendation": self._get_path_recommendation(path, status),
                    })
            
            # Add service-specific vulnerabilities from HTTP probe
            if not discovered:
                discovered.append({
                    "id": "INFO-001",
                    "name": "No high-signal web findings",
                    "severity": "Low",
                    "description": "Probe completed; no common sensitive paths responded",
                    "recommendation": "Regular web application scanning is still recommended",
                })
            
            # Calculate severity summary
            summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for vuln in discovered:
                level = str(vuln.get("severity", "Low")).title()
                if level not in summary:
                    level = "Low"
                summary[level] = summary.get(level, 0) + 1
            
            elapsed = round(time.time() - start_time, 2)
            
            # Generate actionable recommendations
            recommendations = self._generate_vuln_recommendations(discovered, summary)
            
            return {
                "type": "vulnerability_scan",
                "agent": self.name,
                "target": target,
                "target_ip_type": "IPv6" if is_ipv6 else "IPv4",
                "target_reverse_dns": reverse_dns,
                "status": nikto_result.get("status", "success"),
                "engine": nikto_result.get("engine"),
                "tool_used": nikto_result.get("tool", "nikto"),
                "vulnerabilities": discovered,
                "vulnerability_count": len(discovered),
                "severity_summary": summary,
                "severity_counts": {
                    "critical": summary["Critical"],
                    "high": summary["High"],
                    "medium": summary["Medium"],
                    "low": summary["Low"],
                    "total": len(discovered),
                },
                "highest_severity": self._get_highest_severity(summary),
                "nikto_output": (nikto_result.get("result") or "")[:2000],
                "knowledge_base_matches": kb_hits[:5],
                "recommendations": recommendations,
                "scan_duration_seconds": elapsed,
                "timestamp": datetime.now().isoformat(),
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
                "scan_duration_seconds": round(time.time() - start_time, 2),
                "timestamp": datetime.now().isoformat(),
            }
    
    def _get_path_recommendation(self, path: str, status: int) -> str:
        """Get recommendation for a specific exposed path."""
        recs = {
            "/admin": "Restrict admin access to authorized IPs only",
            "/login": "Implement rate limiting and MFA",
            "/config": "Remove configuration files from web root",
            "/backup": "Store backups outside web-accessible directories",
            "/.git/HEAD": "Block access to version control directories",
            "/server-status": "Disable server-status page or restrict access",
            "/.env": "Remove .env files from web root immediately",
            "/wp-admin": "Use strong passwords and 2FA for WordPress admin",
            "/phpinfo": "Remove phpinfo() files from production",
            "/.htaccess": "Ensure proper access controls on .htaccess",
        }
        return recs.get(path, f"Review access controls for {path}")
    
    def _generate_vuln_recommendations(self, vulns: list, summary: dict) -> list:
        """Generate actionable recommendations based on findings."""
        recs = []
        
        if summary["Critical"] > 0:
            recs.append(f"🔴 {summary['Critical']} CRITICAL vulnerabilities found - IMMEDIATE action required")
        
        if summary["High"] > 0:
            recs.append(f"🟠 {summary['High']} HIGH severity findings - address within 24-48 hours")
        
        if summary["Medium"] > 0:
            recs.append(f"🟡 {summary['Medium']} MEDIUM findings - address within 1-2 weeks")
        
        if summary["Low"] > 0:
            recs.append(f"🟢 {summary['Low']} LOW findings - address in next maintenance window")
        
        # Specific recommendations
        paths_found = [v.get("name", "") for v in vulns]
        if any("/.git" in p for p in paths_found):
            recs.append("⚠️  Git repository exposed - block access to .git directories immediately")
        
        if any("/.env" in p for p in paths_found):
            recs.append("⚠️  Environment file exposed - CRITICAL: remove from web root and rotate secrets")
        
        if any("/admin" in p for p in paths_found):
            recs.append("🔒 Admin panel exposed - implement IP allowlisting and strong authentication")
        
        if not recs:
            recs.append("✅ No significant vulnerabilities detected - maintain regular patching schedule")
        
        recs.append("📋 Consider: WAF deployment, regular vulnerability scanning, and penetration testing")
        
        return recs
    
    def _get_highest_severity(self, summary: dict) -> str:
        """Determine highest severity level present."""
        if summary["Critical"] > 0:
            return "Critical"
        elif summary["High"] > 0:
            return "High"
        elif summary["Medium"] > 0:
            return "Medium"
        elif summary["Low"] > 0:
            return "Low"
        return "None"


vuln_agent = VulnAgent()
