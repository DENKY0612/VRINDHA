# -*- coding: utf-8 -*-
"""
Vrindha Terminal UI — Beautiful SOC-like interface for the terminal.
Uses rich library for panels, tables, and live displays.
"""
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.columns import Columns
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich import box
from rich.style import Style
import pyfiglet
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional

console = Console()

# SOC Color Palette (dark theme)
COLORS = {
    "bg": "#0a0e1a",
    "panel": "#151a2d",
    "text": "#d4d4d4",
    "accent": "#7c4dff",
    "red": "#ff5f5f",
    "blue": "#5fafff",
    "green": "#77dd77",
    "yellow": "#f0e68c",
    "orange": "#ff9800",
    "gray": "#696969",
    "cyan": "#00bcd4",
    "magenta": "#e91e63",
    "white": "#ffffff",
}

STATUS_EMOJI = {
    "healthy": "🟢",
    "degraded": "🟡",
    "unhealthy": "🔴",
    "offline": "⚫",
    "ok": "🟢",
    "warn": "🟡",
    "error": "🔴",
}


def get_banner() -> str:
    """Generate ASCII art banner."""
    try:
        banner = pyfiglet.figlet_format("VRINDHA", font="slant")
    except Exception:
        banner = r"""
 ╦  ╦╦═╗╦╔╗╔╔╦╗╦ ╦╔═╗
 ╚╗╔╝╠═╝║║║║ ║ ║ ║╠═╣
  ╚╝ ╩  ╩╝╚╝ ╩ ╚═╝╩ ╩
    AI SOC SYSTEM
        """
    return banner


def print_startup_banner(brain_loaded: bool = True, tools_count: int = 0, 
                         tools_total: int = 0, agents: List[str] = None):
    """Print beautiful startup banner with system status."""
    banner = get_banner()
    
    # Print banner with color
    console.print(banner, style=f"bold {COLORS['accent']}", justify="center")
    
    # Status line
    status_text = Text()
    status_text.append("  🛡️  ", style=COLORS['green'])
    status_text.append("Vrindha AI SOC System", style=f"bold {COLORS['white']}")
    status_text.append("  —  ", style=COLORS['gray'])
    status_text.append("Ethical AI Cybersecurity", style=COLORS['text'])
    status_text.append("\n")
    status_text.append("  Mode: ", style=COLORS['gray'])
    status_text.append("DEFENSIVE", style=f"bold {COLORS['green']}")
    status_text.append("  |  ", style=COLORS['gray'])
    status_text.append("Red Team: ", style=COLORS['gray'])
    status_text.append("MANUAL", style=f"bold {COLORS['red']}")
    status_text.append("  |  ", style=COLORS['gray'])
    status_text.append("Blue Team: ", style=COLORS['gray'])
    status_text.append("AUTOMATED", style=f"bold {COLORS['blue']}")
    
    console.print(status_text, justify="center")
    console.print()
    
    # System status panel
    if agents:
        agent_panels = []
        for agent_name in agents[:8]:
            agent_panels.append(
                Panel(
                    f"{STATUS_EMOJI['healthy']} [bold]{agent_name}[/bold]\n[dim]Ready[/dim]",
                    border_style=COLORS['green'],
                    width=16,
                    height=4,
                )
            )
        console.print(Columns(agent_panels, expand=True))
        console.print()
    
    # Tools status
    if tools_total > 0:
        pct = (tools_count / tools_total) * 100
        color = COLORS['green'] if pct > 70 else COLORS['orange'] if pct > 40 else COLORS['red']
        console.print(
            f"  [bold {color}]⚙️  Tools: {tools_count}/{tools_total} installed ({pct:.0f}%)[/bold {color}]",
            justify="center"
        )
    
    console.print()
    console.print(f"  [{COLORS['gray']}]Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/{COLORS['gray']}]")
    console.print(f"  [{COLORS['gray']}]Type [bold]help[/bold] for commands, [bold]exit[/bold] to quit[/{COLORS['gray']}]")
    console.print()


def _parse_tool_output(data: Dict) -> str:
    """Parse messy tool result dicts into clean readable output.
    
    `data` may be either the tool result dict directly (from brain's data['result'])
    or the full data dict. We detect network_scan by checking both the top-level
    and nested 'result' key.
    """
    if not isinstance(data, dict):
        return str(data)[:500]
    
    lines = []
    
    # Determine where the actual tool result lives
    tool_result = data
    if 'result' in data and isinstance(data['result'], dict):
        tool_result = data['result']
    
    # Network scan / nmap - RICH DETAILED OUTPUT
    if tool_result.get('type') == 'network_scan' or 'nmap' in str(tool_result.get('engine', '')):
        return _format_network_scan_rich(tool_result)
    
    # Whois
    if data.get('type') == 'whois':
        return _format_whois_rich(data)
    
    # Vulnerability scan - RICH DETAILED OUTPUT
    if data.get('type') == 'vulnerability_scan':
        return _format_vulnerability_scan_rich(data)
    
    # Generic fallback: show key fields, skip nested raw dicts
    skip_keys = {'raw', 'result'}  # too verbose
    for key in ['type', 'agent', 'target', 'tool_used', 'status', 'engine']:
        if key in tool_result:
            val = tool_result[key]
            if isinstance(val, str):
                lines.append(f"[bold]{key.replace('_',' ').title()}:[/bold] {val[:100]}")
    
    # Show findings if present
    findings = tool_result.get('findings', [])
    if findings:
        lines.append("")
        lines.append("[bold]Findings:[/bold]")
        for f in findings[:10]:
            lines.append(f"  • {str(f)[:100]}")
    
    # Show result text (trimmed)
    result_text = tool_result.get('result', '')
    if isinstance(result_text, str) and result_text:
        lines.append("")
        lines.append("[bold]Output:[/bold]")
        lines.append(result_text[:800])
    
    return "\n".join(lines) if lines else str(data)[:500]


def _severity_color_rich(severity: str) -> str:
    """Return Rich color markup for severity levels."""
    level = severity.upper()
    if level == 'CRITICAL':
        return f"bold {COLORS['red']}"
    if level == 'HIGH':
        return f"bold {COLORS['orange']}"
    if level == 'MEDIUM':
        return f"bold {COLORS['yellow']}"
    if level == 'LOW':
        return f"bold {COLORS['green']}"
    return COLORS['gray']


def _format_network_scan_rich(data: Dict) -> str:
    """Format network scan results with rich detail."""
    lines = []
    
    # Header section
    lines.append(f"[bold cyan]════════════════════════════════════════════════════════════════[/bold cyan]")
    lines.append(f"[bold cyan]  🔍 NETWORK SCAN REPORT[/bold cyan]")
    lines.append(f"[bold cyan]════════════════════════════════════════════════════════════════[/bold cyan]")
    lines.append("")
    
    # Target Information
    lines.append(f"[bold]📡 Target Information[/bold]")
    lines.append(f"   Target: [bold white]{data.get('target', 'unknown')}[/bold white]")
    lines.append(f"   IP Type: [dim]{data.get('target_ip_type', 'IPv4')}[/dim]")
    if data.get('target_reverse_dns'):
        lines.append(f"   Reverse DNS: [cyan]{data['target_reverse_dns']}[/cyan]")
    lines.append(f"   Scanner: [dim]{data.get('tool', data.get('tool_used', 'nmap'))}[/dim]")
    lines.append(f"   Scan Type: [bold yellow]{data.get('scan_type', 'Standard')}[/bold yellow]")
    lines.append("")
    
    # Timing
    if data.get('scan_duration_seconds'):
        lines.append(f"[bold]⏱️  Scan Timing[/bold]")
        lines.append(f"   Duration: [bold]{data['scan_duration_seconds']}s[/bold]")
        lines.append("")
    
    # Summary Statistics
    lines.append(f"[bold]📊 Port Statistics[/bold]")
    open_count = data.get('open_ports', 0)
    filtered_count = data.get('filtered_ports', 0)
    closed_count = data.get('closed_ports', 0)
    total_ports = data.get('ports_scanned', data.get('total_ports', 0))
    lines.append(f"   Ports Scanned: [bold]{total_ports}[/bold]")
    lines.append(f"   Open: [bold green]{open_count}[/bold green] | Filtered: [bold yellow]{filtered_count}[/bold yellow] | Closed: [bold red]{closed_count}[/bold red]")
    lines.append("")
    
    # OS Detection
    if data.get('os_guess'):
        lines.append(f"[bold]🖥️  OS Detection[/bold]")
        lines.append(f"   {data['os_guess']}")
        lines.append("")
    
    # Open Ports Details
    findings = data.get('findings', [])
    if findings:
        open_findings = [f for f in findings if f.get('state') == 'open']
        filtered_findings = [f for f in findings if f.get('state') == 'filtered']
        
        if open_findings:
            lines.append(f"[bold]🚪 Open Ports & Services[/bold]")
            for f in open_findings:
                port = f.get('port', '?')
                state = f.get('state', 'open')
                service = f.get('service', 'unknown')
                version = f.get('version', '')
                if version:
                    lines.append(f"   [bold green]{port:<6}[/bold green]/tcp  [green]{state:<10}[/green]  [cyan]{service}[/cyan]  [dim]{version}[/dim]")
                else:
                    lines.append(f"   [bold green]{port:<6}[/bold green]/tcp  [green]{state:<10}[/green]  [cyan]{service}[/cyan]")
            lines.append("")
        
        if filtered_findings:
            lines.append(f"[bold]🔒 Filtered Ports[/bold]")
            for f in filtered_findings[:10]:
                port = f.get('port', '?')
                service = f.get('service', 'unknown')
                lines.append(f"   [bold yellow]{port:<6}[/bold yellow]/tcp  [yellow]{'filtered':<10}[/yellow]  [dim]{service}[/dim]")
            if len(filtered_findings) > 10:
                lines.append(f"   [dim]... and {len(filtered_findings) - 10} more filtered ports[/dim]")
            lines.append("")
    else:
        lines.append(f"[dim]   No open ports detected in scan range.[/dim]")
        lines.append("")
    
    # Recommendations
    if data.get('recommendations'):
        lines.append(f"[bold]💡 Recommendations[/bold]")
        for rec in data['recommendations']:
            lines.append(f"   {rec}")
        lines.append("")
    
    lines.append(f"[bold cyan]════════════════════════════════════════════════════════════════[/bold cyan]")
    
    return "\n".join(lines)


def _format_vulnerability_scan_rich(data: Dict) -> str:
    """Format vulnerability scan results with rich detail."""
    lines = []
    
    # Header section
    lines.append(f"[bold red]════════════════════════════════════════════════════════════════[/bold red]")
    lines.append(f"[bold red]  🛡️  VULNERABILITY SCAN REPORT[/bold red]")
    lines.append(f"[bold red]════════════════════════════════════════════════════════════════[/bold red]")
    lines.append("")
    
    # Target Information
    lines.append(f"[bold]📡 Target Information[/bold]")
    lines.append(f"   Target: [bold white]{data.get('target', 'unknown')}[/bold white]")
    lines.append(f"   IP Type: [dim]{data.get('target_ip_type', 'IPv4')}[/dim]")
    if data.get('target_reverse_dns'):
        lines.append(f"   Reverse DNS: [cyan]{data['target_reverse_dns']}[/cyan]")
    lines.append(f"   Scanner: [dim]{data.get('tool_used', 'nikto')}[/dim]")
    lines.append("")
    
    # Timing
    if data.get('scan_duration_seconds'):
        lines.append(f"[bold]⏱️  Scan Timing[/bold]")
        lines.append(f"   Duration: [bold]{data['scan_duration_seconds']}s[/bold]")
        lines.append("")
    
    # Severity Summary
    severity_summary = data.get('severity_summary', {})
    severity_counts = data.get('severity_counts', {})
    
    lines.append(f"[bold]🎯 Severity Summary[/bold]")
    crit = severity_summary.get('Critical', 0)
    high = severity_summary.get('High', 0)
    med = severity_summary.get('Medium', 0)
    low = severity_summary.get('Low', 0)
    total = data.get('vulnerability_count', len(data.get('vulnerabilities', [])))
    
    crit_color = COLORS['red'] if crit > 0 else COLORS['gray']
    high_color = COLORS['orange'] if high > 0 else COLORS['gray']
    med_color = COLORS['yellow'] if med > 0 else COLORS['gray']
    low_color = COLORS['green'] if low > 0 else COLORS['gray']
    
    lines.append(f"   🔴 Critical: [bold {crit_color}]{crit}[/bold {crit_color}] | 🟠 High: [bold {high_color}]{high}[/bold {high_color}] | 🟡 Medium: [bold {med_color}]{med}[/bold {med_color}] | 🟢 Low: [bold {low_color}]{low}[/bold {low_color}]")
    lines.append(f"   Total Vulnerabilities: [bold]{total}[/bold]")
    
    if data.get('highest_severity'):
        sev_color = _severity_color_rich(data['highest_severity'])
        lines.append(f"   Highest Severity: [{sev_color}]{data['highest_severity']}[/{sev_color}]")
    lines.append("")
    
    # Vulnerability Details
    vulnerabilities = data.get('vulnerabilities', [])
    if vulnerabilities:
        lines.append(f"[bold]📋 Vulnerability Details[/bold]")
        for i, vuln in enumerate(vulnerabilities, 1):
            name = vuln.get('name', 'Unknown')
            severity = vuln.get('severity', 'Low')
            description = vuln.get('description', '')
            recommendation = vuln.get('recommendation', '')
            
            sev_color = _severity_color_rich(severity)
            
            lines.append(f"   [{sev_color}]#{i} {name}[/{sev_color}]")
            lines.append(f"      Severity: [{sev_color}]{severity}[/{sev_color}]")
            if description:
                lines.append(f"      Description: {description[:100]}")
            if recommendation:
                lines.append(f"      Fix: [dim]{recommendation[:100]}[/dim]")
            lines.append("")
    else:
        lines.append(f"[dim]   No vulnerabilities detected.[/dim]")
        lines.append("")
    
    # Recommendations
    if data.get('recommendations'):
        lines.append(f"[bold]💡 Recommendations[/bold]")
        for rec in data['recommendations']:
            lines.append(f"   {rec}")
        lines.append("")
    
    lines.append(f"[bold red]════════════════════════════════════════════════════════════════[/bold red]")
    
    return "\n".join(lines)


def _format_whois_rich(data: Dict) -> str:
    """Format WHOIS results with rich detail."""
    lines = []
    
    raw_result = data.get('result', '')
    target = data.get('target', 'unknown')
    
    lines.append(f"[bold cyan]════════════════════════════════════════════════════════════════[/bold cyan]")
    lines.append(f"[bold cyan]  🌐 WHOIS LOOKUP REPORT[/bold cyan]")
    lines.append(f"[bold cyan]════════════════════════════════════════════════════════════════[/bold cyan]")
    lines.append("")
    
    lines.append(f"[bold]📡 Target:[/bold] [bold white]{target}[/bold white]")
    lines.append(f"[bold]📅 Timestamp:[/bold] [dim]{data.get('timestamp', 'N/A')}[/dim]")
    lines.append("")
    
    if isinstance(raw_result, str) and raw_result:
        lines.append(f"[bold]📄 WHOIS Data[/bold]")
        # Parse key fields
        for line in raw_result.split('\n'):
            line = line.strip()
            if not line:
                continue
            if line.startswith('@url:'):
                continue  # skip markdown noise
            if ':' in line and not line.startswith(' '):
                lines.append(f"   {line[:120]}")
            elif line.startswith('Domain Status'):
                lines.append(f"   [dim]{line[:120]}[/dim]")
        lines = lines[:25]  # cap output
    else:
        lines.append("[dim]   No WHOIS data available.[/dim]")
    
    lines.append("")
    lines.append(f"[bold cyan]════════════════════════════════════════════════════════════════[/bold cyan]")
    
    return "\n".join(lines)


def print_result(result: Dict):
    """Print formatted result in a beautiful way."""
    mode = result.get('mode', 'unknown').upper()
    action = result.get('action', '')
    status = result.get('status', '').upper()
    message = result.get('message', '')
    
    # Choose color based on mode
    mode_colors = {
        'red': COLORS['red'],
        'blue': COLORS['blue'],
        'green': COLORS['green'],
    }
    mode_color = mode_colors.get(mode.lower(), COLORS['accent'])
    
    # Status color
    status_colors = {
        'success': COLORS['green'],
        'error': COLORS['red'],
        'awaiting_confirmation': COLORS['yellow'],
        'confirmation_required': COLORS['yellow'],
        'denied': COLORS['red'],
    }
    status_color = status_colors.get(status.lower(), COLORS['gray'])
    
    # Create result table
    table = Table(
        show_header=False,
        box=box.ROUNDED,
        border_style=mode_color,
        width=console.width - 4,
        padding=(0, 2),
    )
    table.add_column("Field", style=f"bold {COLORS['gray']}", width=12)
    table.add_column("Value", style=COLORS['text'])
    
    table.add_row("MODE", f"[bold {mode_color}]{mode}[/bold {mode_color}]")
    table.add_row("ACTION", f"[bold]{action}[/bold]")
    table.add_row("STATUS", f"[bold {status_color}]{status}[/bold {status_color}]")
    table.add_row("MESSAGE", message)
    
    console.print(table)
    
    # Data sections
    data = result.get('data', {})
    if not data:
        return
    
    # Threat Analysis (compact)
    if 'threat' in data or 'threat_analysis' in data:
        threat = data.get('threat') or data.get('threat_analysis')
        if isinstance(threat, dict):
            t_table = Table(
                title="🛡️  Threat Analysis",
                box=box.SIMPLE_HEAVY,
                border_style=COLORS['blue'],
                show_header=False,
                padding=(0, 2),
            )
            t_table.add_column("Key", style=f"bold {COLORS['gray']}", width=20)
            t_table.add_column("Value", style=COLORS['text'])
            for k in ['threat_level', 'risk_level', 'confidence', 'threat_detected', 'failed_login_attempts', 'indicators', 'anomaly_score']:
                if k in threat:
                    v = threat[k]
                    if k == 'threat_detected':
                        v = '[red]YES[/red]' if v else '[green]NO[/green]'
                    elif k == 'indicators' and not v:
                        v = '[dim]none[/dim]'
                    elif k == 'threat_level':
                        v = f"[bold {_threat_color(str(v))}]{v}[/bold {_threat_color(str(v))}]"
                    t_table.add_row(k.replace('_', ' ').title(), str(v)[:100])
            console.print(t_table)
    
    # Gita Wisdom
    if 'gita_verse' in data and data['gita_verse']:
        gv = data['gita_verse']
        if isinstance(gv, dict):
            verse_text = f"🕉️  Chapter {gv.get('chapter')}, Verse {gv.get('verse')}\n"
            verse_text += f"\"{gv.get('text', '')[:250]}\"\n"
            verse_text += f"[dim]Meaning: {gv.get('meaning', '')[:300]}[/dim]"
            console.print(
                Panel(
                    verse_text,
                    title="Gita Wisdom",
                    border_style=COLORS['yellow'],
                    width=console.width - 4,
                )
            )
    
    # Dharma
    if 'dharma' in data:
        dharma = data['dharma']
        if isinstance(dharma, dict):
            decision = dharma.get('decision', '').upper()
            decision_colors = {
                'allow': COLORS['green'],
                'deny': COLORS['red'],
                'warn': COLORS['yellow'],
            }
            dharma_color = decision_colors.get(decision.lower(), COLORS['gray'])
            dharma_text = (
                f"[bold]Decision:[/bold] [bold {dharma_color}]{decision}[/bold {dharma_color}]\n"
                f"[bold]Reason:[/bold] {dharma.get('reason', '')}\n"
                f"[bold]Risk Level:[/bold] {dharma.get('risk_level', '')}"
            )
            console.print(
                Panel(
                    dharma_text,
                    title="⚖️  Dharma Engine",
                    border_style=dharma_color,
                    width=console.width - 4,
                )
            )
    
    # Tool Output (clean formatted)
    if 'result' in data:
        result_data = data['result']
        if isinstance(result_data, dict):
            formatted = _parse_tool_output(result_data)
        elif isinstance(result_data, str):
            formatted = result_data[:800]
        else:
            formatted = str(result_data)[:500]
        
        console.print(
            Panel(
                formatted,
                title="📋 Tool Output",
                border_style=COLORS['cyan'],
                width=console.width - 4,
            )
        )
    
    console.print()


def _threat_color(level: str) -> str:
    level = level.upper()
    if level == 'HIGH' or level == 'CRITICAL':
        return COLORS['red']
    if level == 'MEDIUM':
        return COLORS['yellow']
    if level == 'LOW':
        return COLORS['green']
    return COLORS['gray']


def print_help():
    """Print help in a beautiful format."""
    help_table = Table(
        title="📖 Vrindha Command Reference",
        box=box.DOUBLE_EDGE,
        border_style=COLORS['accent'],
        width=console.width - 4,
    )
    help_table.add_column("Category", style=f"bold {COLORS['yellow']}", width=14)
    help_table.add_column("Command", style=f"bold {COLORS['cyan']}", width=24)
    help_table.add_column("Description", style=COLORS['text'])
    
    # Blue Team
    help_table.add_row("🔵 Blue Team", "status", "System status & agent health")
    help_table.add_row("", "detect threats <text>", "Threat detection (auto)")
    help_table.add_row("", "block ip <ip>", "Block an IP (auto if HIGH)")
    help_table.add_row("", "firewall check", "Check firewall status")
    help_table.add_row("", "rootkit scan", "Scan for rootkits")
    help_table.add_row("", "ids monitor", "IDS monitoring")
    help_table.add_row("", "show logs / siem", "View SIEM logs")
    help_table.add_row("", "analyze anomaly", "ML anomaly detection")
    help_table.add_row("", "risk score", "Get risk score")
    help_table.add_row("", "logs analysis", "Data pipeline analysis")
    
    # Red Team
    help_table.add_row("🔴 Red Team", "scan network <target>", "Nmap scan (manual confirm)")
    help_table.add_row("", "whois <domain>", "WHOIS lookup (manual confirm)")
    help_table.add_row("", "scan vulns <target>", "Vulnerability scan (manual confirm)")
    help_table.add_row("", "nikto <target>", "Nikto web scan (manual confirm)")
    help_table.add_row("", "gobuster <url>", "Directory brute-force (manual confirm)")
    help_table.add_row("", "amass <domain>", "Subdomain enum (manual confirm)")
    help_table.add_row("", "tcpdump <interface>", "Packet capture (manual confirm)")
    help_table.add_row("", "hashcat <hash>", "Hash analysis (manual confirm)")
    help_table.add_row("", "exploit suggest <vuln>", "Exploit suggestion (manual confirm)")
    
    # System
    help_table.add_row("⚙️  System", "yes / confirm", "Confirm pending action")
    help_table.add_row("", "no / cancel", "Cancel pending action")
    help_table.add_row("", "gita random", "Random Gita verse")
    help_table.add_row("", "tools verify", "Verify tool installation")
    help_table.add_row("", "help", "Show this help")
    help_table.add_row("", "exit / quit", "Exit Vrindha")
    
    console.print(help_table)


def print_gita_verse(verse: Dict):
    """Print a Gita verse beautifully."""
    verse_text = f"🕉️  Chapter {verse.get('chapter')}, Verse {verse.get('verse')}\n\n"
    verse_text += f"\"{verse.get('text', '')[:400]}\"\n\n"
    verse_text += f"[dim]Meaning: {verse.get('meaning', '')[:500]}[/dim]"
    if verse.get('tags'):
        verse_text += f"\n[dim]Tags: {', '.join(verse['tags'][:5])}[/dim]"
    
    console.print(
        Panel(
            verse_text,
            title="Bhagavad Gita",
            border_style=COLORS['yellow'],
            width=console.width - 4,
        )
    )


def print_tool_verification(installed: int, total: int, missing: List[str]):
    """Print tool verification results."""
    pct = (installed / total) * 100 if total > 0 else 0
    color = COLORS['green'] if pct > 70 else COLORS['orange'] if pct > 40 else COLORS['red']
    
    table = Table(
        title="⚙️  Tool Verification",
        box=box.ROUNDED,
        border_style=color,
        width=console.width - 4,
    )
    table.add_column("Metric", style=f"bold {COLORS['gray']}")
    table.add_column("Value", style=COLORS['text'])
    table.add_row("Installed", f"[bold {color}]{installed}/{total} ({pct:.0f}%)[/bold {color}]")
    table.add_row("Missing", str(len(missing)))
    
    if missing:
        table.add_row("Missing Tools", ", ".join(missing[:8]))
    
    console.print(table)


def print_status(status_data: Dict):
    """Print system status in a panel."""
    table = Table(
        title="📊 System Status",
        box=box.DOUBLE_EDGE,
        border_style=COLORS['blue'],
        width=console.width - 4,
    )
    table.add_column("Component", style=f"bold {COLORS['gray']}")
    table.add_column("Status", style=COLORS['text'])
    
    for component, info in status_data.items():
        if isinstance(info, dict):
            status = info.get('status', 'unknown')
            emoji = STATUS_EMOJI.get(status.lower(), '❓')
            detail = info.get('detail', '')
            table.add_row(component, f"{emoji} {status} {detail}")
        else:
            table.add_row(component, str(info))
    
    console.print(table)


def print_live_event_bus(events: List[Dict]):
    """Print live event bus panel."""
    if not events:
        return
    
    table = Table(
        title="🔴 Live Event Bus",
        box=box.SIMPLE_HEAVY,
        border_style=COLORS['red'],
        width=console.width - 4,
    )
    table.add_column("Time", style=f"bold {COLORS['gray']}", width=10)
    table.add_column("Type", style=f"bold {COLORS['cyan']}", width=18)
    table.add_column("Event", style=COLORS['text'])
    
    for event in events[-8:]:
        ts = event.get('timestamp', '')[-8:]
        etype = event.get('type', 'unknown')
        detail = str(event.get('detail', event.get('message', '')))[:80]
        table.add_row(ts, etype, detail)
    
    console.print(table)
