"""
Recon Agent - Per MASTER BLUEPRINT and 30-Day Plan
Tools: nmap, netdiscover, amass, sublist3r, whois, gobuster, dirb, tcpdump
Flow: Validate target, ask user confirmation (handled by Brain), run scan, return structured result
Do NOT auto-execute without approval - Brain handles that
"""
from typing import Dict

from vrin_SOC.tools.nmap_tool import run_nmap
from vrin_SOC.tools.network_tool import run_netdiscover
from vrin_SOC.tools.whois_tool import run_whois
from vrin_SOC.tools.amass_tool import run_amass
from vrin_SOC.tools.sublist3r_tool import run_sublist3r
from vrin_SOC.tools.gobuster_tool import run_gobuster
from vrin_SOC.core.error_handler import ErrorHandler
from datetime import datetime

class ReconAgent:
    def __init__(self):
        self.name = "ReconAgent"
    
    def run(self, target: str = "127.0.0.1", tool: str = "nmap") -> Dict:
        """Main run method per Day 5-11 plan - returns structured JSON"""
        import time
        start_time = time.time()
        
        try:
            if not target:
                target = "127.0.0.1"
            
            # Determine IP type
            is_ipv6 = ":" in target and not target.startswith("[")
            
            # Try reverse DNS lookup
            reverse_dns = None
            try:
                import socket
                reverse_dns = socket.gethostbyaddr(target.strip("[]"))[0]
            except Exception:
                pass
            
            # Route by tool choice
            if tool == "netdiscover":
                result = run_netdiscover(target)
            elif tool == "whois":
                result = run_whois(target)
            elif tool == "amass":
                result = run_amass(target)
            elif tool == "sublist3r":
                result = run_sublist3r(target)
            elif tool == "gobuster":
                result = run_gobuster(target)
            else:  # default nmap per Day 10
                result = run_nmap(target)
            
            elapsed = round(time.time() - start_time, 2)
            
            # Enrich result with additional context
            result["target"] = target
            result["target_ip_type"] = "IPv6" if is_ipv6 else "IPv4"
            result["target_reverse_dns"] = reverse_dns or result.get("target_reverse_dns")
            result["scan_duration_seconds"] = elapsed
            result["tool_used"] = tool
            result["agent"] = self.name
            result["timestamp"] = datetime.now().isoformat()
            
            # Add summary stats if findings exist
            if "findings" in result:
                findings = result["findings"]
                open_count = sum(1 for f in findings if f.get("state") == "open")
                filtered_count = sum(1 for f in findings if f.get("state") == "filtered")
                closed_count = sum(1 for f in findings if f.get("state") == "closed")
                result["open_ports"] = open_count
                result["filtered_ports"] = filtered_count
                result["closed_ports"] = closed_count
                result["total_ports"] = len(findings)
            
            # Add recommendations if not already present
            if "recommendations" not in result:
                result["recommendations"] = self._generate_recommendations(result)
            
            return result
        except Exception as e:
            err = ErrorHandler.handle_exception(e, "ReconAgent.run")
            return {
                "type": "network_scan",
                "agent": self.name,
                "target": target,
                "result": err.get("message", "scan failed"),
                "status": "error",
                "error": str(e),
                "scan_duration_seconds": round(time.time() - start_time, 2),
                "timestamp": datetime.now().isoformat(),
            }
    
    def _generate_recommendations(self, result: Dict) -> list:
        """Generate recommendations based on scan results."""
        recs = []
        findings = result.get("findings", [])
        open_ports = [f for f in findings if f.get("state") == "open"]
        
        if not open_ports:
            recs.append("✅ Target appears well-hardened - no open ports detected")
            return recs
        
        # Check for risky services
        risky = {
            23: "Telnet - disable and use SSH",
            21: "FTP - consider SFTP/SCP",
            139: "NetBIOS - disable if not needed",
            445: "SMB - ensure patched and firewall-restricted",
            3389: "RDP - restrict access and use NLA",
            5900: "VNC - ensure encrypted tunnel used",
            6379: "Redis - should not be publicly accessible",
            3306: "MySQL - restrict to internal network",
            5432: "PostgreSQL - restrict to internal network",
        }
        
        for f in open_ports:
            port = f.get("port", 0)
            if port in risky:
                recs.append(f"⚠️  Port {port}: {risky[port]}")
        
        if len(open_ports) > 10:
            recs.append("📊 Many open ports detected - review attack surface")
        
        if not recs:
            recs.append("✅ Minimal attack surface - only standard services detected")
        
        return recs
    
    def run_dummy(self) -> Dict:
        """Dummy version per Day 5"""
        return {
            "type": "network_scan",
            "data": "dummy result",
            "agent": self.name,
            "status": "success"
        }

# Global instance
recon_agent = ReconAgent()
