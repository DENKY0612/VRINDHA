"""
Gobuster Tool - Web Testing per blueprint
Function: run_gobuster(url) with confirmation, runs gobuster dir -u url -w /usr/share/wordlists/dirb/common.txt
"""
from core.tool_executor import tool_executor
from core.error_handler import ErrorHandler
import shutil
from datetime import datetime

def run_gobuster(url: str) -> dict:
    try:
        if not url:
            url = "http://127.0.0.1"
        if not url.startswith("http"):
            url = f"http://{url}"
        
        if not shutil.which("gobuster"):
            return {
                "tool": "gobuster",
                "target": url,
                "status": "simulated",
                "data": f"[SIMULATION] gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt\n/admin (Status: 301)\n/config (Status: 200)\n/backup (Status: 403)",
                "error": "",
                "timestamp": datetime.now().isoformat()
            }
        
        # Use safe wordlist if exists, else without
        wordlist_path = "/usr/share/wordlists/dirb/common.txt"
        cmd = f"gobuster dir -u {url} -w {wordlist_path} -t 20"
        if not shutil.os.path.exists(wordlist_path):
            cmd = f"gobuster dir -u {url} --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 20"
        
        result = tool_executor.execute(cmd, tool_name="gobuster")
        return {
            "tool": "gobuster",
            "target": url,
            "status": result.get("status"),
            "data": result.get("output","")[:5000],
            "error": result.get("error",""),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return ErrorHandler.handle_exception(e, "run_gobuster")
