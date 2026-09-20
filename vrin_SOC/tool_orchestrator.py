# -*- coding: utf-8 -*-
"""
Vrindha Tool Orchestrator
Auto-launches security tools (sqlmap, zphisher, etc.) in separate terminals
when Vrindha SOC starts up.
"""
import subprocess
import sys
import os
import time
from pathlib import Path
from typing import List, Dict, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

# Tool configurations: command to launch, window title, and description
TOOL_CONFIGS: List[Dict] = [
    {
        "name": "Nmap",
        "command": ["nmap", "--version"],
        "title": "VRINDHA :: Nmap Scanner",
        "description": "Network scanner",
        "auto_start": False,
    },
    {
        "name": "SQLMap",
        "command": ["sqlmap", "--version"],
        "title": "VRINDHA :: SQLMap",
        "description": "SQL injection tool",
        "auto_start": False,
    },
    {
        "name": "Zphisher",
        "command": ["cd", "~/.config/zphisher", "&&", "bash", "zphisher.sh"],
        "title": "VRINDHA :: Zphisher",
        "description": "Phishing toolkit (authorized use only)",
        "auto_start": False,
    },
    {
        "name": "Nikto",
        "command": ["nikto", "--Version"],
        "title": "VRINDHA :: Nikto",
        "description": "Web vulnerability scanner",
        "auto_start": False,
    },
    {
        "name": "Gobuster",
        "command": ["gobuster", "--help"],
        "title": "VRINDHA :: Gobuster",
        "description": "Directory brute-forcer",
        "auto_start": False,
    },
    {
        "name": "TCPDump",
        "command": ["tcpdump", "--version"],
        "title": "VRINDHA :: TCPDump",
        "description": "Packet capture",
        "auto_start": False,
    },
    {
        "name": "Snort",
        "command": ["snort", "--version"],
        "title": "VRINDHA :: Snort IDS",
        "description": "Intrusion Detection",
        "auto_start": False,
    },
    {
        "name": "Hashcat",
        "command": ["hashcat", "--version"],
        "title": "VRINDHA :: Hashcat",
        "description": "Hash cracker (assistant only)",
        "auto_start": False,
    },
]


class ToolOrchestrator:
    """Manages launching security tools in separate terminal windows."""
    
    def __init__(self, tool_configs: List[Dict] = None):
        self.tool_configs = tool_configs or TOOL_CONFIGS
        self.running_tools: Dict[str, subprocess.Popen] = {}
        self.platform = sys.platform
        
    def is_windows(self) -> bool:
        return self.platform == "win32"
    
    def is_linux(self) -> bool:
        return self.platform.startswith("linux")
    
    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is installed and available."""
        import shutil
        return shutil.which(tool_name.lower()) is not None
    
    def launch_tool(self, tool_config: Dict) -> Optional[subprocess.Popen]:
        """
        Launch a single tool in a new terminal window.
        Returns the subprocess.Popen object or None if failed.
        """
        name = tool_config["name"]
        command = tool_config["command"]
        title = tool_config.get("title", f"VRINDHA :: {name}")
        description = tool_config.get("description", "")
        
        # Check if tool is available
        if not self.is_tool_available(command[0]):
            console.print(f"  [bold #ff5f5f]✗[/bold #ff5f5f] {name} [dim](not installed)[/dim]")
            return None
        
        try:
            if self.is_windows():
                # Windows: start new cmd window
                cmd_str = " ".join(command)
                full_cmd = f'start "{title}" cmd /k "echo VRINDHA SOC TOOL: {name} ({description}) && echo. && {cmd_str} && echo. && echo Tool ready. Type commands above."'
                proc = subprocess.Popen(full_cmd, shell=True)
            elif self.is_linux():
                # Linux/WSL: check for display server
                display = os.environ.get("DISPLAY")
                if not display:
                    # No display server (headless/WSL) - skip terminal window
                    console.print(f"  [bold #f0e68c]⚠[/bold #f0e68c] {name} [dim](no display - use CLI directly)[/dim]")
                    return None
                # Try gnome-terminal, then xterm
                try:
                    proc = subprocess.Popen([
                        "gnome-terminal", "--title", title, "--", "bash", "-c"
                    ])
                except FileNotFoundError:
                    try:
                        proc = subprocess.Popen([
                            "xterm", "-title", title, "-e", "bash", "-c"
                        ])
                    except FileNotFoundError:
                        console.print(f"  [bold #ff5f5f]✗[/bold #ff5f5f] {name} [dim](no terminal emulator)[/dim]")
                        return None
            else:
                console.print(f"  [bold #ff5f5f]✗[/bold #ff5f5f] {name} [dim](unsupported platform)[/dim]")
                return None
            
            self.running_tools[name] = proc
            console.print(f"  [bold #77dd77]✓[/bold #77dd77] {name} [dim]({description}) launched[/dim]")
            return proc
            
        except Exception as e:
            console.print(f"  [bold #ff5f5f]✗[/bold #ff5f5f] {name} [dim](error: {e})[/dim]")
            return None
    
    def launch_all(self, only_available: bool = True) -> Dict[str, subprocess.Popen]:
        """Launch all tools in the configuration."""
        console.print()
        console.print(
            Panel(
                "[bold]🔧 Launching Security Tools[/bold]\n"
                "[dim]Each tool opens in its own terminal window[/dim]",
                title="VRINDHA TOOL ORCHESTRATOR",
                border_style="#7c4dff",
            )
        )
        
        launched = {}
        for config in self.tool_configs:
            proc = self.launch_tool(config)
            if proc:
                launched[config["name"]] = proc
            time.sleep(0.3)  # Small delay between launches
        
        console.print()
        if launched:
            console.print(
                f"  [bold #77dd77]Launched {len(launched)} tool(s) successfully[/bold #77dd77]"
            )
        else:
            console.print(
                "  [bold #f0e68c]⚠ No tools launched. Install Kali tools to enable.[/bold #f0e68c]"
            )
        console.print()
        
        return launched
    
    def stop_tool(self, tool_name: str) -> bool:
        """Stop a running tool."""
        if tool_name in self.running_tools:
            proc = self.running_tools[tool_name]
            proc.terminate()
            proc.wait(timeout=5)
            del self.running_tools[tool_name]
            console.print(f"  [bold #ff5f5f]⏹ {tool_name} stopped[/bold #5fafff]")
            return True
        return False
    
    def stop_all(self):
        """Stop all running tools."""
        for name in list(self.running_tools.keys()):
            self.stop_tool(name)
    
    def get_status(self) -> Dict[str, Dict]:
        """Get status of all tools."""
        status = {}
        for config in self.tool_configs:
            name = config["name"]
            available = self.is_tool_available(config["command"][0])
            running = name in self.running_tools
            status[name] = {
                "name": name,
                "available": available,
                "running": running,
                "description": config.get("description", ""),
            }
        return status


# Instance for use in main.py
orchestrator = ToolOrchestrator()
