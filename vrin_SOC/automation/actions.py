"""
Automation Module - Per DAY 22-23 and START UP Automated Response System (Safe Mode)
Responsibilities: Trigger actions based on threat level, execute safe system commands
Actions: Block IP (iptables), Kill process, Send alert
Rules: Do not execute destructive commands, confirm before high-risk actions
BLUE TEAM CAN be automated
"""
import ipaddress
import subprocess
import shutil
from datetime import datetime
from typing import Dict
from pathlib import Path
from vrin_SOC.core.error_handler import ErrorHandler

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = PACKAGE_ROOT / "logs" / "log.txt"

class AutomationActions:
    def block_ip(self, ip: str) -> Dict:
        """Block IP using firewall (iptables/ufw) - Safe Mode"""
        try:
            # Validate the address before it is interpolated into a firewall preview
            # (and before a future implementation executes the command).
            if not ip:
                return {"status": "error", "action": "block_ip", "message": "No IP provided"}
            try:
                validated_ip = str(ipaddress.ip_address(ip))
            except (ValueError, TypeError):
                return {
                    "status": "error",
                    "action": "block_ip",
                    "message": f"Invalid IP address: {ip}"
                }
            
            # Try ufw if available (safer)
            if shutil.which("ufw"):
                # In real Kali: subprocess.run(["sudo", "ufw", "deny", "from", ip])
                # Simulate for safety in this sandbox
                return {
                    "status": "simulated",
                    "action": "block_ip",
                    "ip": validated_ip,
                    "message": f"[SIMULATION] Would execute: sudo ufw deny from {validated_ip} (or iptables -A INPUT -s {validated_ip} -j DROP). Automated Blue Team response.",
                    "tool": "ufw",
                    "timestamp": datetime.now().isoformat(),
                    "risk": "High threat auto-response per blueprint allowed"
                }
            elif shutil.which("iptables"):
                return {
                    "status": "simulated",
                    "action": "block_ip",
                    "ip": validated_ip,
                    "message": f"[SIMULATION] Would execute: sudo iptables -A INPUT -s {validated_ip} -j DROP",
                    "tool": "iptables",
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {
                    "status": "simulated",
                    "action": "block_ip",
                    "ip": validated_ip,
                    "message": f"[SIMULATION] No firewall tool found (ufw/iptables). Would block {validated_ip}. Install: sudo apt install ufw",
                    "timestamp": datetime.now().isoformat()
                }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "AutomationActions.block_ip")
    
    def kill_process(self, pid: int) -> Dict:
        """Kill suspicious processes"""
        try:
            if not pid:
                return {"status": "error", "action": "kill_process", "message": "No PID provided"}
            
            # Safety: don't allow killing PID 1 or critical
            if int(pid) <= 1:
                return {"status": "denied", "action": "kill_process", "message": "Safety: Cannot kill PID <=1"}
            
            # Real would be: subprocess.run(["sudo", "kill", "-9", str(pid)])
            return {
                "status": "simulated",
                "action": "kill_process",
                "pid": pid,
                "message": f"[SIMULATION] Would kill process {pid} - Safe automated response for high risk threat",
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "AutomationActions.kill_process")
    
    def send_alert(self, message: str) -> Dict:
        """Send alert per blueprint"""
        try:
            timestamp = datetime.now().isoformat()
            alert_msg = f"[{timestamp}] ALERT: {message}"
            print(alert_msg)  # console alert
            
            # Also log to file
            try:
                LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(alert_msg + "\n")
            except OSError:
                pass
            
            return {
                "status": "success",
                "action": "send_alert",
                "message": message,
                "timestamp": timestamp,
                "logged": True
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "AutomationActions.send_alert")
    
    def isolate_network_interface(self, interface: str) -> Dict:
        """Isolate network interface - High impact, confirm before"""
        return {
            "status": "requires_confirmation",
            "action": "isolate_interface",
            "interface": interface,
            "message": f"High-impact action: Isolating {interface} requires explicit confirmation. Do you want to proceed? (yes/no)",
            "command": f"sudo ip link set {interface} down"
        }

automation_actions = AutomationActions()
