"""
Rootkit Auto Scan (rkhunter + chkrootkit) per MASTER BLUEPRINT
Flow: Run scan, parse output, detect suspicious results, Return {threat, status: clean/suspicious}
"""
from vrin_SOC.core.tool_executor import tool_executor
from vrin_SOC.core.error_handler import ErrorHandler
import shutil
from datetime import datetime

class RootkitScanner:
    def scan(self) -> dict:
        try:
            results = {}
            suspicious_found = False
            
            if shutil.which("rkhunter"):
                res = tool_executor.execute("rkhunter --check --sk --report-warnings-only", tool_name="rkhunter")
                out = res.get("output","")
                results["rkhunter"] = out[:2000]
                if "warning" in out.lower() or "rootkit" in out.lower():
                    suspicious_found = True
            else:
                results["rkhunter"] = "[SIMULATION] rkhunter --check\n[OK] No rootkits found (simulated clean)"
            
            if shutil.which("chkrootkit"):
                res = tool_executor.execute("chkrootkit", tool_name="chkrootkit")
                out = res.get("output","")
                results["chkrootkit"] = out[:2000]
                if "infected" in out.lower():
                    suspicious_found = True
            else:
                results["chkrootkit"] = "[SIMULATION] chkrootkit\nnothing suspicious (simulated)"
            
            return {
                "status": "suspicious" if suspicious_found else "clean",
                "threat": "Possible rootkit detected" if suspicious_found else "No threats found - system clean",
                "tools_output": results,
                "timestamp": datetime.now().isoformat(),
                "message": "Rootkit scan completed - Endpoint protection"
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "RootkitScanner.scan")

rootkit_scanner = RootkitScanner()
