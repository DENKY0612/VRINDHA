# -*- coding: utf-8 -*-
"""
Vrindha AI SOC — Main Entry Point
Beautiful terminal UI + auto-launching security tools.
"""
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Dict

# Ensure we can import vrin_SOC package
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Load autonomy policy
_POLICY_PATH = _REPO_ROOT / "vrin_SOC" / "config" / "autonomy_policy.json"
if _POLICY_PATH.exists():
    import json
    with open(_POLICY_PATH, "r", encoding="utf-8") as _pf:
        AUTO_POLICY = json.load(_pf)
    from vrin_SOC.core.brain import set_autonomy_policy
    set_autonomy_policy(AUTO_POLICY.get("thresholds", {}))
else:
    AUTO_POLICY = {"medium": 40, "high": 70, "critical": 85}

# Import Vrindha components
from vrin_SOC.core.brain import brain
from vrin_SOC.core.gita_engine import gita_engine
from vrin_SOC.tools.installer import verify_all_tools
from vrin_SOC.database.db import init_db

# Import terminal UI
try:
    from vrin_SOC.terminal_ui import (
        console, print_startup_banner, print_result, print_help,
        print_gita_verse, print_tool_verification, print_status,
        print_live_event_bus, COLORS, STATUS_EMOJI
    )
    HAS_RICH_UI = True
except ImportError:
    HAS_RICH_UI = False

# Import tool orchestrator
try:
    from vrin_SOC.tool_orchestrator import orchestrator
    HAS_ORCHESTRATOR = True
except ImportError:
    HAS_ORCHESTRATOR = False


def print_fallback_banner():
    """Fallback banner if rich is not available."""
    print("""
╔═════════════════════════════════════════════════════════════╗
║  🛡️  Vrindha AI SOC System - Ethical AI Cybersecurity     ║
║  Controlled + Automated | Red Team Manual, Blue Automated  ║
║  Dharma Engine | Gita Wisdom | Kali Linux Compatible       ║
╚═════════════════════════════════════════════════════════════╝
    """)
    print(f"Mode: DEFENSIVE (default) | Gita Loaded: {gita_engine.loaded} ({len(gita_engine.verses) if hasattr(gita_engine, 'verses') else 0} verses)")
    print(f"Time: {datetime.now().isoformat()}")
    print("Type 'help' for commands, 'exit' to quit, 'yes/no' for Red Team confirmations\n")


def launch_tools_if_enabled():
    """Launch security tools in separate terminals if enabled."""
    if not HAS_ORCHESTRATOR:
        return
    
    # Check if auto-launch is enabled (default: False for WSL compatibility)
    auto_launch = os.environ.get("VRINDHA_AUTO_LAUNCH_TOOLS", "false").lower() == "true"
    if not auto_launch:
        return
    
    # Check for display server (required for terminal windows)
    import sys
    if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
        # No display server in WSL - tools are available via CLI only
        return
    
    orchestrator.launch_all(only_available=True)


def main():
    """Main entry point for Vrindha SOC."""
    import argparse
    parser = argparse.ArgumentParser(description="Vrindha AI SOC System")
    parser.add_argument("--batch", action="store_true", help="Run in batch mode (read JSON from stdin, output JSON)")
    parser.add_argument("--input", type=str, help="Input file for batch mode (default: stdin)")
    parser.add_argument("--no-tools", action="store_true", help="Don't auto-launch tools")
    parser.add_argument("--tools-only", action="store_true", help="Only launch tools, don't start CLI")
    parser.add_argument("--auto-confirm", action="store_true", help="Auto-confirm Red Team commands (admin only)")
    parser.add_argument("--force-auto-confirm", action="store_true", help="Force auto-confirm for CLI demo (bypasses admin check)")
    args = parser.parse_args()
    
    # Batch mode
    if args.batch:
        run_batch_mode(args.input)
        return
    
    # Print banner
    if HAS_RICH_UI:
        print_startup_banner(
            brain_loaded=True,
            tools_count=verify_all_tools()["installed_count"],
            tools_total=verify_all_tools()["total"],
            agents=[
                "Commander", "Threat Intel", "Data Science",
                "SOC Analyst", "Infrastructure", "Ethics",
                "Knowledge", "Vrindha"
            ],
        )
    else:
        print_fallback_banner()
        tools = verify_all_tools()
        print(f"[Startup] Tool verification: {tools['installed_count']}/{tools['total']} installed")
    
    # Welcome verse
    verse = gita_engine.get_random_verse()
    if HAS_RICH_UI:
        console.print(f"  [bold #f0e68c]🕉️  {verse.get('meaning', 'Perform your duty with detachment')} (Ch {verse.get('chapter')}.{verse.get('verse')})[/bold #f0e68c]\n")
    else:
        print(f"🕉️ Gita Wisdom: {verse.get('meaning', '')} (Ch {verse.get('chapter')}.{verse.get('verse')})\n")
    
    # Launch tools
    if not args.no_tools:
        launch_tools_if_enabled()
    
    # If tools-only mode, just launch and exit
    if args.tools_only:
        console.print("[dim]Tools launched. Press Ctrl+C to exit.[/dim]" if HAS_RICH_UI else "Tools launched.")
        try:
            while True:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            console.print("\n[bold #ff5f5f]⏹ Stopping all tools...[/bold #ff5f5f]" if HAS_RICH_UI else "\nStopping tools...")
            orchestrator.stop_all()
        return
    
    # Main CLI loop
    if HAS_RICH_UI:
        console.print()
        console.print(f"  [{COLORS['gray']}]Type [bold]help[/bold] for commands, [bold]exit[/bold] to quit[/{COLORS['gray']}]")
        console.print()
    while True:
        try:
            if HAS_RICH_UI:
                try:
                    from rich.prompt import Prompt
                    user_input = Prompt.ask("[bold #7c4dff]Vrindha[/bold #7c4dff]").strip()
                except (EOFError, KeyboardInterrupt):
                    raise
                except Exception:
                    user_input = input("Vrindha> ").strip()
            else:
                user_input = input("Vrindha> ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() in ["clear", "cls"]:
                # Clear terminal screen
                if os.name == 'nt':
                    os.system('cls')
                else:
                    os.system('clear')
                continue
            
            if user_input.lower() in ["exit", "quit", "bye"]:
                if HAS_RICH_UI:
                    console.print("[bold #77dd77]Exiting Vrindha AI SOC — Stay protected! Dharma protects those who protect Dharma. 🛡️[/bold #77dd77]")
                else:
                    print("Exiting Vrindha AI SOC - Stay protected! Dharma protects those who protect Dharma. 🛡️")
                break
            
            # Process via Brain
            user_token = "admin" if args.force_auto_confirm else None
            result = brain.process(user_input, auto_confirm=args.auto_confirm or args.force_auto_confirm, user_token=user_token)
            
            if HAS_RICH_UI:
                print_result(result)
            else:
                print_fallback_result(result)
            
        except KeyboardInterrupt:
            if HAS_RICH_UI:
                console.print("\n[dim]Use 'exit' to quit safely[/dim]")
            else:
                print("\nUse 'exit' to quit safely")
            continue
        except EOFError:
            break
        except Exception as e:
            if HAS_RICH_UI:
                console.print(f"\n[bold #ff5f5f]❌ Error (but system continues): {e}[/bold #ff5f5f]")
            else:
                print(f"\n❌ Error (but system continues): {e}")
            continue


def _format_tool_output_fallback(data: Dict) -> str:
    """Format tool output cleanly without rich - enhanced with detailed recon/vuln info.
    
    Can be called with either:
    - The full data dict from brain result (with 'result' key containing tool output)
    - The tool result dict directly (with 'type' key indicating the tool type)
    """
    lines = []
    if not isinstance(data, dict):
        return str(data)[:500]
    
    # Determine where the actual tool result lives
    # Case 1: data has 'result' key containing the tool output (from brain's data structure)
    # Case 2: data IS the tool output directly
    tool_result = data
    if 'result' in data and isinstance(data['result'], dict) and 'type' in data['result']:
        tool_result = data['result']
    
    # Network scan - detailed fallback output
    if tool_result.get('type') == 'network_scan' or 'nmap' in str(tool_result.get('engine', '')):
        return _format_network_scan_fallback(tool_result)
    
    # Handle string result with nmap
    result_data = data.get('result', {})
    if isinstance(result_data, str) and 'nmap' in result_data.lower():
        lines.append(f"Scanner: nmap")
        lines.append(f"Status: SUCCESS")
        lines.append("")
        lines.append("Output:")
        lines.append(result_data[:800])
        return "\n".join(lines)
    
    # Whois
    if tool_result.get('type') == 'whois':
        return _format_whois_fallback(tool_result)
    
    # Vulnerability scan - detailed fallback output
    if tool_result.get('type') == 'vulnerability_scan':
        return _format_vulnerability_scan_fallback(tool_result)
    
    # Generic: show key fields only
    for key in ['type', 'agent', 'target', 'tool_used', 'status', 'engine']:
        if key in tool_result:
            val = tool_result[key]
            if isinstance(val, str):
                lines.append(f"{key.replace('_',' ').title()}: {val[:100]}")
    
    findings = tool_result.get('findings', [])
    if findings:
        lines.append("")
        lines.append("Findings:")
        for f in findings[:10]:
            lines.append(f"  • {str(f)[:100]}")
    
    result_text = tool_result.get('result', '')
    if isinstance(result_text, str) and result_text:
        lines.append("")
        lines.append("Output:")
        lines.append(result_text[:800])
    
    return "\n".join(lines) if lines else str(data)[:500]


def _format_network_scan_fallback(data: Dict) -> str:
    """Format network scan results with detailed fallback output."""
    lines = []
    
    # Header
    lines.append("=" * 60)
    lines.append("  🔍 NETWORK SCAN REPORT")
    lines.append("=" * 60)
    lines.append("")
    
    # Target Information
    lines.append("📡 Target Information")
    lines.append(f"   Target: {data.get('target', 'unknown')}")
    lines.append(f"   IP Type: {data.get('target_ip_type', 'IPv4')}")
    if data.get('target_reverse_dns'):
        lines.append(f"   Reverse DNS: {data['target_reverse_dns']}")
    lines.append(f"   Scanner: {data.get('tool', data.get('tool_used', 'nmap'))}")
    lines.append(f"   Scan Type: {data.get('scan_type', 'Standard')}")
    lines.append("")
    
    # Timing
    if data.get('scan_duration_seconds'):
        lines.append("⏱️  Scan Timing")
        lines.append(f"   Duration: {data['scan_duration_seconds']}s")
        lines.append("")
    
    # Summary Statistics
    lines.append("📊 Port Statistics")
    open_count = data.get('open_ports', 0)
    filtered_count = data.get('filtered_ports', 0)
    closed_count = data.get('closed_ports', 0)
    total_ports = data.get('ports_scanned', data.get('total_ports', 0))
    lines.append(f"   Ports Scanned: {total_ports}")
    lines.append(f"   Open: {open_count} | Filtered: {filtered_count} | Closed: {closed_count}")
    lines.append("")
    
    # OS Detection
    if data.get('os_guess'):
        lines.append("🖥️  OS Detection")
        lines.append(f"   {data['os_guess']}")
        lines.append("")
    
    # Open Ports Details
    findings = data.get('findings', [])
    if findings:
        open_findings = [f for f in findings if f.get('state') == 'open']
        filtered_findings = [f for f in findings if f.get('state') == 'filtered']
        
        if open_findings:
            lines.append("🚪 Open Ports & Services")
            for f in open_findings:
                port = f.get('port', '?')
                state = f.get('state', 'open')
                service = f.get('service', 'unknown')
                version = f.get('version', '')
                if version:
                    lines.append(f"   {port:<6}/tcp  {state:<10}  {service}  {version}")
                else:
                    lines.append(f"   {port:<6}/tcp  {state:<10}  {service}")
            lines.append("")
        
        if filtered_findings:
            lines.append("🔒 Filtered Ports")
            for f in filtered_findings[:10]:
                port = f.get('port', '?')
                service = f.get('service', 'unknown')
                lines.append(f"   {port:<6}/tcp  filtered   {service}")
            if len(filtered_findings) > 10:
                lines.append(f"   ... and {len(filtered_findings) - 10} more filtered ports")
            lines.append("")
    else:
        lines.append("   No open ports detected in scan range.")
        lines.append("")
    
    # Recommendations
    if data.get('recommendations'):
        lines.append("💡 Recommendations")
        for rec in data['recommendations']:
            lines.append(f"   {rec}")
        lines.append("")
    
    lines.append("=" * 60)
    
    return "\n".join(lines)


def _format_vulnerability_scan_fallback(data: Dict) -> str:
    """Format vulnerability scan results with detailed fallback output."""
    lines = []
    
    # Header
    lines.append("=" * 60)
    lines.append("  🛡️  VULNERABILITY SCAN REPORT")
    lines.append("=" * 60)
    lines.append("")
    
    # Target Information
    lines.append("📡 Target Information")
    lines.append(f"   Target: {data.get('target', 'unknown')}")
    lines.append(f"   IP Type: {data.get('target_ip_type', 'IPv4')}")
    if data.get('target_reverse_dns'):
        lines.append(f"   Reverse DNS: {data['target_reverse_dns']}")
    lines.append(f"   Scanner: {data.get('tool_used', 'nikto')}")
    lines.append("")
    
    # Timing
    if data.get('scan_duration_seconds'):
        lines.append("⏱️  Scan Timing")
        lines.append(f"   Duration: {data['scan_duration_seconds']}s")
        lines.append("")
    
    # Severity Summary
    severity_summary = data.get('severity_summary', {})
    
    lines.append("🎯 Severity Summary")
    crit = severity_summary.get('Critical', 0)
    high = severity_summary.get('High', 0)
    med = severity_summary.get('Medium', 0)
    low = severity_summary.get('Low', 0)
    total = data.get('vulnerability_count', len(data.get('vulnerabilities', [])))
    
    lines.append(f"   🔴 Critical: {crit} | 🟠 High: {high} | 🟡 Medium: {med} | 🟢 Low: {low}")
    lines.append(f"   Total Vulnerabilities: {total}")
    
    if data.get('highest_severity'):
        lines.append(f"   Highest Severity: {data['highest_severity']}")
    lines.append("")
    
    # Vulnerability Details
    vulnerabilities = data.get('vulnerabilities', [])
    if vulnerabilities:
        lines.append("📋 Vulnerability Details")
        for i, vuln in enumerate(vulnerabilities, 1):
            name = vuln.get('name', 'Unknown')
            severity = vuln.get('severity', 'Low')
            description = vuln.get('description', '')
            recommendation = vuln.get('recommendation', '')
            
            lines.append(f"   #{i} {name}")
            lines.append(f"      Severity: {severity}")
            if description:
                lines.append(f"      Description: {description[:100]}")
            if recommendation:
                lines.append(f"      Fix: {recommendation[:100]}")
            lines.append("")
    else:
        lines.append("   No vulnerabilities detected.")
        lines.append("")
    
    # Recommendations
    if data.get('recommendations'):
        lines.append("💡 Recommendations")
        for rec in data['recommendations']:
            lines.append(f"   {rec}")
        lines.append("")
    
    lines.append("=" * 60)
    
    return "\n".join(lines)


def _format_whois_fallback(data: Dict) -> str:
    """Format WHOIS results with detailed fallback output."""
    lines = []
    
    raw_result = data.get('result', '')
    target = data.get('target', 'unknown')
    
    lines.append("=" * 60)
    lines.append("  🌐 WHOIS LOOKUP REPORT")
    lines.append("=" * 60)
    lines.append("")
    
    lines.append(f"📡 Target: {target}")
    lines.append(f"📅 Timestamp: {data.get('timestamp', 'N/A')}")
    lines.append("")
    
    if isinstance(raw_result, str) and raw_result:
        lines.append("📄 WHOIS Data")
        # Parse key fields
        count = 0
        for line in raw_result.split('\n'):
            line = line.strip()
            if not line:
                continue
            if line.startswith('@url:'):
                continue
            if ':' in line and not line.startswith(' '):
                lines.append(f"   {line[:120]}")
                count += 1
            elif line.startswith('Domain Status'):
                lines.append(f"   {line[:120]}")
                count += 1
            if count >= 20:
                break
    else:
        lines.append("   No WHOIS data available.")
    
    lines.append("")
    lines.append("=" * 60)
    
    return "\n".join(lines)


def print_fallback_result(result: dict):
    """Fallback result printing without rich - enhanced with detailed scan info."""
    print("\n" + "="*70)
    print(f"MODE: {result.get('mode','').upper()} | ACTION: {result.get('action','')} | STATUS: {result.get('status','').upper()}")
    print("-"*70)
    
    message = result.get('message', '')
    if message:
        print(f"Message: {message}")
    
    # Show scan summary if available (from brain's enriched result)
    data = result.get('data', {})
    if data:
        scan_summary = data.get('scan_summary', '')
        if scan_summary:
            print(f"\n📊 Scan Summary: {scan_summary}")
        
        if 'threat' in data or 'threat_analysis' in data:
            threat = data.get('threat') or data.get('threat_analysis')
            if isinstance(threat, dict):
                print("\n--- Threat Analysis ---")
                for k in ['threat_level', 'risk_level', 'confidence', 'threat_detected', 'failed_login_attempts', 'indicators']:
                    if k in threat:
                        print(f"  {k.replace('_',' ').title()}: {threat[k]}")
        
        if 'gita_verse' in data and data['gita_verse']:
            gv = data['gita_verse']
            if isinstance(gv, dict):
                print(f"\n--- Gita Wisdom ---")
                print(f"Chapter {gv.get('chapter')}, Verse {gv.get('verse')}: {gv.get('text','')[:200]}")
        
        if 'result' in data:
            print("\n--- Tool Output ---")
            result_data = data['result']
            if isinstance(result_data, dict):
                print(_format_tool_output_fallback(result_data))
            else:
                print(str(result_data)[:800])
    
    print("="*70 + "\n")


def run_batch_mode(input_file: str = None):
    """Batch mode: read JSON commands from stdin or file."""
    import json
    
    if input_file:
        with open(input_file, "r", encoding="utf-8") as f:
            commands = json.load(f)
    else:
        commands = json.load(sys.stdin)
    
    if not isinstance(commands, list):
        commands = [commands]
    
    results = []
    for cmd in commands:
        if isinstance(cmd, str):
            text = cmd
        elif isinstance(cmd, dict):
            text = cmd.get("command", cmd.get("text", ""))
        else:
            text = str(cmd)
        result = brain.process(text)
        results.append(result)
    
    json.dump({"results": results}, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
