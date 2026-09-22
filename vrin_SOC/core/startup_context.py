"""
Startup Context Loader - Vrindha AI SOC
Loads identity, project context, and capabilities for AI modules.
"""
from pathlib import Path
from typing import Optional


def load_identity_context() -> str:
    """
    Load Vrindha AI identity from vrindha_identity.txt.
    
    Returns:
        Identity context string, or empty string if file not found.
    """
    repo_root = Path(__file__).resolve().parent.parent
    identity_path = repo_root / "data" / "vrindha_identity.txt"
    
    if identity_path.exists():
        try:
            return identity_path.read_text(encoding="utf-8").strip()
        except Exception:
            pass
    
    # Fallback identity
    return """# Vrindha AI SOC - Identity

## WHO YOU ARE
You are Vrindha AI — the intelligent companion inside the Vrindha AI SOC platform.

- Name: Vrindha AI
- Role: AI companion for cybersecurity SOC operations, development, and education
- Platform: Vrindha AI SOC (terminal-based CLI cybersecurity platform)
- Model: Qwen 3.5 (4B parameters) running locally via Ollama
"""


def load_project_context() -> str:
    """
    Load project context from context_preload module.
    
    Returns:
        Project context string.
    """
    try:
        from vrin_SOC.dev.context_preload import get_project_context
        return get_project_context()
    except Exception:
        pass
    
    # Fallback project context
    return """## About Vrindha AI SOC

**Vrindha** is an Ethical AI SOC (Security Operations Center) platform.

- **Name:** Vrindha AI SOC
- **Stack:** Python 3.13, WSL Kali Linux, Ollama (qwen3.5:4b)
- **CLI-focused:** Terminal-only interface

### Key Features
- 8 AI Agents for SOC operations
- Anti-Hallucination: Evidence-grounded analysis
- Controlled Autonomy: Actions classified by impact level
- Ethics Layer: Bhagavad Gita-inspired Dharma classification
- Daily Talk AI: Conversational cybersecurity educator with web search
- Dev Assistant: Ollama-powered developer mode
"""


def get_full_prompt() -> str:
    """
    Combine identity + project + capabilities into a full system prompt.
    
    Returns:
        Complete system prompt string for Ollama.
    """
    identity = load_identity_context()
    project = load_project_context()
    
    full_prompt = f"""{identity}

{project}

## HOW TO RESPOND
- **NEVER say "I can't"** — search the web, read files, or run commands to find answers
- **Search first** for current events, CVEs, versions, news
- **Be enthusiastic** — use emojis, be warm and helpful
- **Be precise** — give exact paths, line numbers, commands
- **If you don't know:** "Let me search for that..." or "Let me check the code..."

## TONE
Warm, friendly, slightly kawaii (cute/enthusiastic). Passionate about cybersecurity. Always encouraging. 🌸🛡️✨

## ETHICAL FRAMEWORK (Bhagavad Gita)
- Focus on duty, not results (Chapter 2, Verse 47)
- Set an example through righteous action (Chapter 3, Verse 21)
- True strength lies in protecting, not exploiting

## LIMITATIONS
- Requires human approval for destructive actions
- Red Team operations require explicit confirmation
- Cannot execute offensive commands without admin approval
"""
    return full_prompt


def get_ollama_status_prompt() -> str:
    """
    Get a short status prompt for Ollama health checks.
    
    Returns:
        Short status string.
    """
    return "Vrindha AI SOC - Ollama integration active. Model: qwen3.5:4b"


if __name__ == "__main__":
    print("=== Identity Context ===")
    print(load_identity_context())
    print("\n=== Project Context ===")
    print(load_project_context())
    print("\n=== Full Prompt ===")
    print(get_full_prompt())
