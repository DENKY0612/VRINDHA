"""
Nikto Tool - Vulnerability Scanning per blueprint
"""
from core.tool_executor import tool_executor
from core.error_handler import ErrorHandler
import shutil
from datetime import datetime

def run_nikto(target: str = "http://127.0.0.1") -> dict:
    try:
        if not target.startswith("http"):
            target = f"http://{target}"
        
        if not shutil.which("nikto"):
            return {
                "type": "vulnerability_scan",
                "target": target,
                "status": "simulated",
                "tool": "nikto",
                "result": f"[SIMULATION] nikto -h {target}\n- Server: Apache/2.4\n- OSVDB-3233: /icons/README: Apache default file found\n- /config/ directory indexing enabled - Potential info disclosure",
                "vulnerabilities": ["Default Apache file", "Directory indexing"],
                "timestamp": datetime.now().isoformat()
            }
        
        result = tool_executor.execute(f"nikto -h {target}", tool_name="nikto")
        return {
            "type": "vulnerability_scan",
            "target": target,
            "status": result.get("status"),
            "tool": "nikto",
            "result": result.get("output","")[:5000],
            "timestamp": datetime.now().isoformat(),
            "error": result.get("error","")
        }
    except Exception as e:
        return ErrorHandler.handle_exception(e, "run_nikto")
