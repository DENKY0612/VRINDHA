"""
Tool Execution Prompt (Safe Automation) - per MASTER BLUEPRINT
Create a safe execution layer for Kali tools
RULES: Check tool availability, use subprocess safely, handle errors, timeout 10 seconds
"""
import subprocess
import shutil
import shlex
from typing import Dict, Tuple
from .error_handler import ErrorHandler

# Canonical definition lives in vrin_SOC.tools.security; re-exported here so
# existing callers of tool_executor keep a single import site.
from vrin_SOC.tools.security import INTERFACE_RE, validate_interface  # noqa: F401

class ToolExecutor:
    """Safe tool execution layer"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def check_tool(self, tool_name: str) -> bool:
        """Check if tool is installed via shutil.which"""
        return shutil.which(tool_name) is not None
    
    def execute(self, command, tool_name: str = None, timeout: int = None) -> Dict:
        """
        Execute command safely with timeout
        command: full shell command string or list
        tool_name: optional for availability check
        Returns: {status: success/error, output:..., error:...}
        """
        limit = timeout if timeout is not None else self.timeout
        try:
            # Check availability if tool_name provided
            if tool_name:
                if not self.check_tool(tool_name):
                    return {
                        "status": "error",
                        "tool": tool_name,
                        "output": "",
                        "error": f"Tool '{tool_name}' not installed. Suggest: sudo apt install {tool_name}",
                        "suggestion": f"sudo apt install {tool_name}"
                    }
            
            # Safely split command if string
            if isinstance(command, str):
                # For simple execution, use shell=False with shlex split for safety
                # But some tools require shell pipe; we will allow shell only for specific safe patterns
                args = shlex.split(command)
            else:
                args = command
            
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=limit,
                shell=False
            )
            
            # Combine stdout + stderr
            output = result.stdout
            if result.stderr:
                output += "\n" + result.stderr
            
            if result.returncode == 0:
                return {
                    "status": "success",
                    "tool": tool_name or args[0],
                    "output": output[:10000],  # truncate large outputs
                    "error": "",
                    "returncode": result.returncode
                }
            else:
                return {
                    "status": "error",
                    "tool": tool_name or args[0],
                    "output": output[:10000],
                    "error": f"Tool returned non-zero exit code {result.returncode}",
                    "returncode": result.returncode
                }
                
        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "tool": tool_name or "unknown",
                "output": "",
                "error": f"Tool execution timed out after {limit} seconds - limited for safety per blueprint"
            }
        except FileNotFoundError as e:
            return {
                "status": "error",
                "tool": tool_name or "unknown",
                "output": "",
                "error": f"Tool not found: {e}. Did you install it?"
            }
        except Exception as e:
            ErrorHandler.handle_exception(e, "ToolExecutor.execute")
            return {
                "status": "error",
                "tool": tool_name or "unknown",
                "output": "",
                "error": str(e)
            }
    
    def execute_simulation(self, tool_name: str, target: str) -> Dict:
        """Simulation mode when real execution not allowed or tool missing"""
        return {
            "status": "simulated",
            "tool": tool_name,
            "output": f"[SIMULATION] Would run {tool_name} on {target}. Real execution requires confirmation and tool installation.",
            "error": "",
            "note": "Prefer simulation over real attack when possible per blueprint"
        }

# Global executor
tool_executor = ToolExecutor(timeout=10)
