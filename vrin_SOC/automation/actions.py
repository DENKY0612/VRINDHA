"""
Automation Module - Per DAY 22-23 and START UP Automated Response System (Safe Mode)
Responsibilities: Trigger actions based on threat level, execute safe system commands
Actions: Block IP (iptables), Kill process, Send alert
Rules: Do not execute destructive commands, require analyst validation before high-impact containment
BLUE TEAM can automate low-impact alerting/monitoring; containment stays human-validated

Real execution is controlled by VRINDHA_REAL_EXECUTION_ENABLED env var (default: false).
When false (default), ALL actions run in SIMULATION mode.
When true, actions that are approved and validated will execute for real.
"""
import ipaddress
import subprocess
import shutil
import os
from datetime import datetime
from typing import Dict
from pathlib import Path
from vrin_SOC.core.error_handler import ErrorHandler

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
LOG_FILE = PACKAGE_ROOT / "logs" / "log.txt"

# Real execution flag (Phase 3: real firewall execution boundary)
REAL_EXECUTION_ENABLED = os.getenv("VRINDHA_REAL_EXECUTION_ENABLED", "false").lower() == "true"

class AutomationActions:
    def block_ip(self, ip: str) -> Dict:
            """Block IP using firewall (iptables/ufw) - Safe Mode with optional real execution."""
            try:
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

                if not REAL_EXECUTION_ENABLED:
                    # Simulation mode (default)
                    if shutil.which("ufw"):
                        return {
                            "status": "simulated",
                            "action": "block_ip",
                            "ip": validated_ip,
                            "message": f"[SIMULATION] Would execute: sudo ufw deny from {validated_ip} (or iptables -A INPUT -s {validated_ip} -j DROP). Automated Blue Team response.",
                            "tool": "ufw",
                            "timestamp": datetime.now().isoformat(),
                            "risk": "High-impact containment must be human-validated before real execution"
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

                # REAL EXECUTION MODE (only when VRINDHA_REAL_EXECUTION_ENABLED=true)
                if shutil.which("ufw"):
                    result = subprocess.run(
                        ["sudo", "ufw", "deny", "from", validated_ip],
                        capture_output=True, text=True, timeout=30
                    )
                    return {
                        "status": "executed" if result.returncode == 0 else "error",
                        "action": "block_ip",
                        "ip": validated_ip,
                        "message": result.stdout if result.returncode == 0 else result.stderr,
                        "tool": "ufw",
                        "timestamp": datetime.now().isoformat(),
                        "real_execution": True
                    }
                elif shutil.which("iptables"):
                    result = subprocess.run(
                        ["sudo", "iptables", "-A", "INPUT", "-s", validated_ip, "-j", "DROP"],
                        capture_output=True, text=True, timeout=30
                    )
                    return {
                        "status": "executed" if result.returncode == 0 else "error",
                        "action": "block_ip",
                        "ip": validated_ip,
                        "message": result.stdout if result.returncode == 0 else result.stderr,
                        "tool": "iptables",
                        "timestamp": datetime.now().isoformat(),
                        "real_execution": True
                    }
                else:
                    return {
                        "status": "error",
                        "action": "block_ip",
                        "ip": validated_ip,
                        "message": "No firewall tool found (ufw/iptables). Install: sudo apt install ufw",
                        "timestamp": datetime.now().isoformat()
                    }
            except Exception as e:
                return ErrorHandler.handle_exception(e, "AutomationActions.block_ip")
    
    def kill_process(self, pid: int) -> Dict:
            """Kill suspicious processes - Safe Mode with optional real execution."""
            try:
                if not pid:
                    return {"status": "error", "action": "kill_process", "message": "No PID provided"}

                # Safety: don't allow killing PID 1 or critical
                if int(pid) <= 1:
                    return {"status": "denied", "action": "kill_process", "message": "Safety: Cannot kill PID <=1"}

                if not REAL_EXECUTION_ENABLED:
                    # Simulation mode (default)
                    return {
                        "status": "simulated",
                        "action": "kill_process",
                        "pid": pid,
                        "message": f"[SIMULATION] Would kill process {pid} - Safe automated response for high risk threat",
                        "timestamp": datetime.now().isoformat()
                    }

                # REAL EXECUTION MODE
                result = subprocess.run(
                    ["sudo", "kill", "-9", str(pid)],
                    capture_output=True, text=True, timeout=30
                )
                return {
                    "status": "executed" if result.returncode == 0 else "error",
                    "action": "kill_process",
                    "pid": pid,
                    "message": result.stdout if result.returncode == 0 else result.stderr,
                    "timestamp": datetime.now().isoformat(),
                    "real_execution": True
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
