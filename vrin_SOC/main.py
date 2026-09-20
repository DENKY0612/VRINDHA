# -*- coding: utf-8 -*-
"""
Vrindha AI SOC — Main Entry Point
Beautiful terminal UI + auto-launching security tools.
"""
import sys
import os
from pathlib import Path
from datetime import datetime

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
    
    # Check if auto-launch is enabled (default: True)
    auto_launch = os.environ.get("VRINDHA_AUTO_LAUNCH_TOOLS", "true").lower() == "true"
    if not auto_launch:
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
    
    use_rich_input = HAS_RICH_UI and not args.force_auto_confirm
    
    while True:
        try:
            if use_rich_input:
                try:
                    from rich.prompt import Prompt
                    user_input = Prompt.ask("[bold #7c4dff]Vrindha[/bold #7c4dff]").strip()
                except (EOFError, KeyboardInterrupt):
                    raise
                except Exception:
                    # Fallback to basic input if rich fails (WSL compatibility)
                    user_input = input("Vrindha> ").strip()
            else:
                user_input = input("Vrindha> ").strip()
            
            if not user_input:
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


def print_fallback_result(result: dict):
    """Fallback result printing without rich."""
    print("\n" + "="*70)
    print(f"MODE: {result.get('mode','').upper()} | ACTION: {result.get('action','')} | STATUS: {result.get('status','').upper()}")
    print("-"*70)
    print(f"Message: {result.get('message','')}")
    
    data = result.get('data', {})
    if data:
        if 'threat' in data or 'threat_analysis' in data:
            threat = data.get('threat') or data.get('threat_analysis')
            print(f"\n--- Threat Analysis ---")
            import json
            print(json.dumps(threat, indent=2)[:1000])
        if 'gita_verse' in data and data['gita_verse']:
            gv = data['gita_verse']
            if isinstance(gv, dict):
                print(f"\n--- 🕉️ Gita Wisdom ---")
                print(f"Chapter {gv.get('chapter')}, Verse {gv.get('verse')}: {gv.get('text','')[:200]}")
        if 'result' in data:
            print(f"\n--- Tool Output ---")
            print(str(data['result'])[:1000])
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
