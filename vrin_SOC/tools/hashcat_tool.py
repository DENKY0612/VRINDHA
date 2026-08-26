"""
Hashcat Tool - Credential Testing (STRICT CONTROL) per blueprint
IMPORTANT: DO NOT auto-run attacks - only suggestion, requires explicit approval
Features: Accept hash input, suggest hashcat command
Example: hashcat -m <mode> <hash> wordlist.txt
"""
from vrin_SOC.core.error_handler import ErrorHandler
from vrin_SOC.core.tool_executor import tool_executor
import shutil
from datetime import datetime

def run_hashcat_assistant(hash_input: str = "") -> dict:
    """
    Hashcat assistant - per blueprint STRICT CONTROL
    Does NOT auto-run, suggests command and explains risks
    """
    try:
        # Basic hash type detection
        hash_type_suggestion = "0"  # MD5 default
        if len(hash_input) == 32:
            hash_type_suggestion = "0 (MD5)"
        elif len(hash_input) == 40:
            hash_type_suggestion = "100 (SHA1)"
        elif len(hash_input) == 64:
            hash_type_suggestion = "1400 (SHA256)"
        
        suggested_command = f"hashcat -m {hash_type_suggestion.split()[0]} '{hash_input or '<hash>'}' /usr/share/wordlists/rockyou.txt"
        
        # Check if installed
        installed = shutil.which("hashcat") is not None
        
        return {
            "tool": "hashcat",
            "status": "assistant" if not installed else "suggested",
            "hash_input": hash_input[:100] if hash_input else "Not provided",
            "suggested_command": suggested_command,
            "explanation": f"Detected hash type: {hash_type_suggestion}. Use rockyou wordlist for testing.",
            "risks": "Credential cracking should only be done on authorized hashes you own. Unauthorized cracking violates laws and Dharma.",
            "requires_confirmation": True,
            "installed": installed,
            "dharma_note": "High-risk tool → require strict confirmation + justification per Gita self-control teaching",
            "timestamp": datetime.now().isoformat(),
            "execution": "NOT auto-executed per STRICT CONTROL blueprint - manual approval required"
        }
    except Exception as e:
        return ErrorHandler.handle_exception(e, "run_hashcat_assistant")

def run_hashcat_verified(hash_value: str, mode: str = "0", wordlist: str = "/usr/share/wordlists/rockyou.txt", confirm: bool = False) -> dict:
    """Only run if explicitly approved"""
    if not confirm:
        return {
            "status": "requires_confirmation",
            "message": "Do you want to run Hashcat? Explain risks and get explicit approval. (yes/no)",
            "suggested": f"hashcat -m {mode} {hash_value} {wordlist}"
        }
    
    if not shutil.which("hashcat"):
        return {"status": "error", "error": "hashcat not installed"}
    
    # Safety wrapper - real execution only if confirmed
    result = tool_executor.execute(f"hashcat -m {mode} {hash_value} {wordlist} --force", tool_name="hashcat")
    return result
