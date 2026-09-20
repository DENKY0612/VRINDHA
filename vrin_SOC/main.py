# -*- coding: utf-8 -*-
"""Terminal AI Assistant Prompt - Per DAY 2, 4, 24 and MASTER BLUEPRINT
Build a command-line AI assistant for Vrindha
Requirements: Accept user input continuously, pass input to Brain, display formatted output
Features: Interactive loop, exit command, clean output formatting
File: main.py, Flow: while True: input -> brain.process() -> print output
Also: Multi-agent, logging, SIEM, Dharma integration, Gita wisdom
"""
from datetime import datetime
from pathlib import Path
import sys
import json

# Allow `python vrin_SOC/main.py` and `cd vrin_SOC && python main.py`.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Load autonomy policy dynamically (Phase 1 stability fix)
_POLICY_PATH = _REPO_ROOT / "vrin_SOC" / "config" / "autonomy_policy.json"
if _POLICY_PATH.exists():
    with open(_POLICY_PATH, "r", encoding="utf-8") as _pf:
        AUTO_POLICY = json.load(_pf)
    # expose selected thresholds to the brain module
    from vrin_SOC.core.brain import set_autonomy_policy
    set_autonomy_policy(AUTO_POLICY.get("thresholds", {}))
else:
    AUTO_POLICY = {"medium": 40, "high": 70, "critical": 85}

from vrin_SOC.core.brain import brain
from vrin_SOC.core.gita_engine import gita_engine
from vrin_SOC.tools.installer import verify_all_tools
from vrin_SOC.database.db import init_db

def print_banner():
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

def format_output(result: dict):
    print("\n" + "="*70)
    print(f"MODE: {result.get('mode','').upper()} | ACTION: {result.get('action','')} | STATUS: {result.get('status','').upper()}")
    print("-"*70)
    print(f"Message: {result.get('message','')}")
    
    data = result.get('data', {})
    if data:
        # Pretty print key parts
        if 'result' in data:
            print(f"\n--- Tool Output ---")
            print(str(data['result'])[:1000])
        if 'threat' in data or 'threat_analysis' in data:
            threat = data.get('threat') or data.get('threat_analysis')
            print(f"\n--- Threat Analysis ---")
            print(json.dumps(threat, indent=2)[:1000])
        if 'gita_verse' in data and data['gita_verse']:
            gv = data['gita_verse']
            if isinstance(gv, dict):
                print(f"\n--- 🕉️ Gita Wisdom ---")
                print(f"Chapter {gv.get('chapter')}, Verse {gv.get('verse')}: {gv.get('text','')[:200]}")
                print(f"Meaning: {gv.get('meaning','')[:300]}")
        if 'dharma' in data:
            dharma = data['dharma']
            if isinstance(dharma, dict):
                print(f"\n--- Dharma Engine ---")
                print(f"Decision: {dharma.get('decision')} | Reason: {dharma.get('reason')}")
        if 'safety' in data:
            print(f"\n--- Safety ---")
            print(json.dumps(data.get('safety'), indent=2)[:500])
    
    print("="*70 + "\n")

def run_batch_mode(input_file: str = None) -> None:
    """Batch mode: read JSON commands from stdin or file, output JSON results."""
    import json
    import sys

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


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Vrindha AI SOC System")
    parser.add_argument("--batch", action="store_true", help="Run in batch mode (read JSON from stdin, output JSON)")
    parser.add_argument("--input", type=str, help="Input file for batch mode (default: stdin)")
    args = parser.parse_args()

    if args.batch:
        run_batch_mode(args.input)
        return

    print_banner()
    
    # Initial tool verification per blueprint advice: start with nmap → nikto → wireshark → fail2ban
    tools = verify_all_tools()
    print(f"[Startup] Tool verification: {tools['installed_count']}/{tools['total']} installed")
    if tools['missing']:
        print(f"         Missing: {', '.join(tools['missing'][:5])}... Install via: sudo apt install <tool>")
    print()
    
    # Welcome verse
    verse = gita_engine.get_random_verse()
    print(f"🕉️ Gita Wisdom: {verse.get('meaning','Perform your duty with detachment')} (Ch {verse.get('chapter')}.{verse.get('verse')})\n")
    
    while True:
        try:
            user_input = input("Vrindha> ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() in ["exit", "quit", "bye"]:
                print("Exiting Vrindha AI SOC - Stay protected! Dharma protects those who protect Dharma. 🛡️")
                break
            
            # Process via Brain
            result = brain.process(user_input)
            format_output(result)
            
            # Special handling for confirmation_required - Brain already stores pending, just loop will handle yes/no next iteration
            
        except KeyboardInterrupt:
            print("\nUse 'exit' to quit safely per error handling blueprint")
            continue
        except EOFError:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"\n❌ Error (but system continues per Error Handling Prompt): {e}")
            print("System continues running - never crash per blueprint")
            continue

if __name__ == "__main__":
    main()