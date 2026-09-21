"""
Ollama-Powered Developer Assistant for Vrindha AI SOC.
Provides intelligent code review, patching, and project management
via the Vrindha CLI 'dev' command.
"""
import os
import json
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


class OllamaDev:
    """
    Developer Assistant powered by Ollama for intelligent responses,
    with direct file access and project modification capabilities.
    """

    def __init__(self):
        """Initialize OllamaDev with project root detection and Ollama connection."""
        self.project_root = self._detect_project_root()
        self.original_cwd = os.getcwd()
        self.history: List[Dict[str, str]] = []
        self.ollama_available = self._check_ollama()

    def _detect_project_root(self) -> Path:
        """Detect Vrindha project root by looking for vrin_SOC directory."""
        current = Path.cwd()
        for path in [current] + list(current.parents):
            if (path / "vrin_SOC").is_dir():
                return path
        fallback = Path("/mnt/c/Users/n4ndh/Documents/port/vrind/BACKEND")
        if fallback.exists():
            return fallback
        return current

    def _check_ollama(self) -> bool:
        """Check if Ollama server is available, try to start if binary exists."""
        try:
            import urllib.request
            req = urllib.request.Request("http://localhost:11434/api/tags")
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except Exception:
            pass
        
        # Server not running - try to auto-start
        ollama_bin = self._find_ollama_binary()
        if ollama_bin:
            try:
                subprocess.Popen(
                    [str(ollama_bin), "serve"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                # Wait for server to start
                import time
                time.sleep(3)
                # Re-check
                import urllib.request
                req = urllib.request.Request("http://localhost:11434/api/tags")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    return resp.status == 200
            except Exception:
                pass
        
        return False
    
    def _find_ollama_binary(self) -> Optional[Path]:
        """Find ollama binary in common locations."""
        candidates = [
            Path("/usr/local/bin/ollama"),
            Path("/usr/bin/ollama"),
            Path("/home/kali/.local/bin/ollama"),
            Path.home() / ".local" / "bin" / "ollama",
        ]
        for p in candidates:
            if p.exists() and p.is_file():
                return p
        return None

    def _try_web_search(self, user_message: str) -> Optional[str]:
        """Detect if message needs web search and return context."""
        # Keywords that trigger web search
        web_keywords = [
            "CVE", "exploit", "vulnerability", "news", "latest",
            "what is", "how to protect", "best practices",
            "zero-day", "ransomware", "threat intelligence"
        ]
        lower = user_message.lower()
        if not any(k in lower for k in web_keywords):
            return None
        
        try:
            from vrin_SOC.dev.web_search import search_context
            return search_context(user_message, max_results=3)
        except Exception:
            return None

    def _get_python_path(self) -> str:
        """Get the path to the project's Python interpreter."""
        venv_python = self.project_root / ".venv_kali" / "bin" / "python"
        if venv_python.exists():
            return str(venv_python)
        return "python3"

    def _ollama_chat(self, user_message: str, context: str = "") -> Optional[str]:
        """Send a message to Ollama and return the response.
        Enriches with web search when cybersecurity topics are detected."""
        if not self.ollama_available:
            return None
        try:
            import urllib.request
            system_prompt = (
                "You are Vrindha Dev Assistant, an AI developer partner for the "
                "Vrindha AI SOC cybersecurity project. You help with code review, "
                "debugging, patching, and project management. Be concise, technical, "
                "and provide exact file paths and line numbers. Use emojis sparingly. "
                "You have access to web search for current cybersecurity information. "
                f"Project root: {self.project_root}"
            )
            if context:
                system_prompt += f"\n\nRecent conversation:\n{context}"

            # Detect cybersecurity queries and enrich with web search
            web_context = self._try_web_search(user_message)
            if web_context:
                system_prompt += f"\n\nWeb search results:\n{web_context}"

            payload = {
                "model": "qwen3.5:4b",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message}
                ],
                "stream": False
            }
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                "http://localhost:11434/api/chat",
                data=data,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result.get("message", {}).get("content", "")
        except Exception as e:
            return f"[Ollama error: {e}]"

    def enter(self) -> str:
        """Return greeting message when entering dev mode."""
        os.chdir(self.project_root)
        ollama_status = "✅ Connected" if self.ollama_available else "❌ Not available (using templates)"
        greeting = (
            "🛡️ Vrindha Developer Assistant 🛡️\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📁 Project: {self.project_root}\n"
            f"🤖 Ollama: {ollama_status}\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "I can read, review, edit, and manage your project!\n"
            "Just tell me what you need in plain English.\n"
            "Type 'exit' to return to SOC mode.\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        )
        return greeting

    def process(self, user_input: str) -> Dict[str, Any]:
        """
        Process a developer command.
        Routes to specific handlers or falls back to Ollama.
        """
        if not user_input.strip():
            return {"output": "", "files_modified": []}

        # Check for exit
        if user_input.strip().lower() in ("exit", "quit", "back"):
            return {"output": self.exit_dev(), "files_modified": [], "exit": True}

        # Parse command
        parts = user_input.strip().split(None, 1)
        command = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        # Direct command handlers
        handlers = {
            "read": self._read_file,
            "grep": self._grep_files,
            "files": self._list_files,
            "status": self._project_status,
            "patch": self._patch_file,
            "git": self._git_command,
            "run": self._run_command,
            "python": self._run_python,
            "review": self._review_file,
            "help": self._help,
        }

        handler = handlers.get(command)
        if handler:
            return handler(args)

        # No direct command match - use Ollama for natural language
        return self._handle_natural_language(user_input)

    def _handle_natural_language(self, user_input: str) -> Dict[str, Any]:
        """Handle natural language input via Ollama or template fallback."""
        # Build context from recent history
        context = "\n".join(
            [f"{h['role']}: {h['content']}" for h in self.history[-6:]]
        )

        # Try Ollama first
        if self.ollama_available:
            response = self._ollama_chat(user_input, context)
            if response and not response.startswith("[Ollama error"):
                self.history.append({"role": "user", "content": user_input})
                self.history.append({"role": "assistant", "content": response})
                return {"output": response, "files_modified": []}

        # Template fallback
        return self._template_response(user_input)

    def _template_response(self, user_input: str) -> Dict[str, Any]:
        """Template-based fallback when Ollama is unavailable."""
        lower = user_input.lower()

        # File-related queries
        if any(w in lower for w in ["what files", "list files", "show files", "project structure"]):
            return self._list_files("*.py")
        if any(w in lower for w in ["status", "overview", "project state"]):
            return self._project_status()
        if "brain.py" in lower:
            return self._read_file("vrin_SOC/core/brain.py")
        if "main.py" in lower:
            return self._read_file("vrin_SOC/main.py")

        # Git queries
        if any(w in lower for w in ["git status", "changes", "modified files"]):
            return self._git_command("status")
        if any(w in lower for w in ["recent commits", "git log", "history"]):
            return self._git_command("log --oneline -10")

        # Default
        return {
            "output": (
                f"🤔 I understand you want: '{user_input}'\n"
                f"Try commands: read, grep, files, status, patch, git, run, python, review\n"
                f"Or be specific: 'read brain.py', 'grep auto_confirm', 'review main.py'"
            ),
            "files_modified": []
        }

    def _read_file(self, args: str) -> Dict[str, Any]:
        """Read and display a file."""
        if not args:
            return {"output": "Usage: read <file_path>", "files_modified": []}
        file_path = self._resolve_path(args)
        try:
            if not file_path.exists():
                return {"output": f"File not found: {args}", "files_modified": []}
            content = file_path.read_text(encoding="utf-8", errors="replace")
            lines = content.split("\n")
            line_info = f" ({len(lines)} lines)"
            if len(lines) > 100:
                display = "\n".join(lines[:50] + ["... (truncated) ..."] + lines[-50:])
                line_info += " [truncated]"
            else:
                display = content
            return {
                "output": f"📖 {file_path.relative_to(self.project_root)}{line_info}\n{'='*60}\n{display}",
                "files_modified": []
            }
        except Exception as e:
            return {"output": f"Error reading file: {e}", "files_modified": []}

    def _grep_files(self, args: str) -> Dict[str, Any]:
        """Search files for a pattern."""
        if not args:
            return {"output": "Usage: grep <pattern> [file_pattern]", "files_modified": []}
        parts = args.split(None, 1)
        pattern = parts[0]
        file_pattern = parts[1] if len(parts) > 1 else "*.py"
        try:
            result = subprocess.run(
                ["grep", "-rn", "--include", file_pattern, pattern, "."],
                capture_output=True, text=True, cwd=self.project_root
            )
            if result.returncode == 0 and result.stdout.strip():
                matches = result.stdout.strip().split("\n")
                output = "\n".join(matches[:50])
                if len(matches) > 50:
                    output += f"\n... ({len(matches)} total matches)"
                return {"output": f"🔍 Results for '{pattern}':\n{'='*60}\n{output}", "files_modified": []}
            return {"output": f"No matches found for '{pattern}'", "files_modified": []}
        except Exception as e:
            return {"output": f"Error searching: {e}", "files_modified": []}

    def _list_files(self, args: str) -> Dict[str, Any]:
        """List files matching a pattern."""
        pattern = args if args else "*.py"
        try:
            files = list(self.project_root.rglob(pattern))
            files = [f for f in files if '.venv_kali' not in str(f) and '__pycache__' not in str(f)]
            files = [f for f in files if not any(p.startswith('.') and p not in ('.', '..') for p in f.relative_to(self.project_root).parts[1:])]
            files.sort()
            output_lines = [f"📂 Files matching '{pattern}' ({len(files)} total):\n{'='*60}"]
            for f in files[:100]:
                output_lines.append(f"  {f.relative_to(self.project_root)}")
            if len(files) > 100:
                output_lines.append(f"\n... and {len(files) - 100} more")
            return {"output": "\n".join(output_lines), "files_modified": []}
        except Exception as e:
            return {"output": f"Error listing files: {e}", "files_modified": []}

    def _project_status(self, args: str = "") -> Dict[str, Any]:
        """Show project status overview."""
        try:
            branch = subprocess.run(["git", "branch", "--show-current"], capture_output=True, text=True, cwd=self.project_root).stdout.strip()
            changes = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, cwd=self.project_root).stdout.strip().split("\n")
            changes = [c for c in changes if c]
            recent = subprocess.run(["git", "log", "--oneline", "-5"], capture_output=True, text=True, cwd=self.project_root).stdout.strip()
            py_count = len(list(self.project_root.rglob("*.py")))
            venv_ok = (self.project_root / ".venv_kali").is_dir()
            output = (
                f"📊 Project Status: Vrindha AI SOC\n{'='*60}\n"
                f"📁 Root: {self.project_root}\n"
                f"🌿 Branch: {branch}\n"
                f"📝 Uncommitted: {len(changes)}\n"
                f"📄 Python files: {py_count}\n"
                f"🐍 .venv_kali: {'✅' if venv_ok else '❌'}\n"
                f"📜 Recent commits:\n{recent}\n"
            )
            if changes:
                output += f"{'─'*40}\n📝 Changed:\n"
                for c in changes[:10]:
                    output += f"  {c}\n"
            return {"output": output, "files_modified": []}
        except Exception as e:
            return {"output": f"Error: {e}", "files_modified": []}

    def _patch_file(self, args: str) -> Dict[str, Any]:
        """Interactive file patching."""
        if not args:
            return {"output": "Usage: patch <file_path>", "files_modified": []}
        file_path = self._resolve_path(args)
        if not file_path.exists():
            return {"output": f"File not found: {args}", "files_modified": []}
        content = file_path.read_text(encoding="utf-8")
        lines = content.split("\n")
        output = f"📝 {file_path.relative_to(self.project_root)} - Enter edits as '<line>: <new_text>'\n{'='*60}\n"
        for i, line in enumerate(lines, 1):
            output += f"{i:4d} | {line}\n"
        output += f"{'='*60}\nEnter 'done' to apply, 'cancel' to abort.\n"
        return {"output": output, "files_modified": [], "awaiting_edit": True, "file_path": str(file_path)}

    def apply_patch(self, file_path: str, edits: List[tuple]) -> Dict[str, Any]:
        """Apply collected edits to a file."""
        try:
            path = Path(file_path)
            content = path.read_text(encoding="utf-8")
            lines = content.split("\n")
            for line_num, new_content in edits:
                if 1 <= line_num <= len(lines):
                    lines[line_num - 1] = new_content
            path.write_text("\n".join(lines), encoding="utf-8")
            return {"output": f"✅ Applied {len(edits)} edit(s) to {path.relative_to(self.project_root)}", "files_modified": [str(path.relative_to(self.project_root))]}
        except Exception as e:
            return {"output": f"Error: {e}", "files_modified": []}

    def _git_command(self, args: str) -> Dict[str, Any]:
        """Run a git command."""
        if not args:
            args = "status"
        dangerous = ["push", "reset --hard", "checkout -B", "branch -D", "clean -f"]
        if any(d in args for d in dangerous):
            return {"output": f"⚠️ Dangerous git blocked: '{args}'", "files_modified": []}
        try:
            result = subprocess.run(["git"] + shlex.split(args), capture_output=True, text=True, cwd=self.project_root)
            output = result.stdout + (f"\n{result.stderr}" if result.stderr else "")
            return {"output": f"🌿 git {args}:\n{'='*60}\n{output}", "files_modified": []}
        except Exception as e:
            return {"output": f"Error: {e}", "files_modified": []}

    def _run_command(self, args: str) -> Dict[str, Any]:
        """Run a shell command."""
        if not args:
            return {"output": "Usage: run <command>", "files_modified": []}
        dangerous = ["rm -rf /", "mkfs", "dd if=/dev/zero", "sudo rm -rf /"]
        if any(d in args for d in dangerous):
            return {"output": f"⚠️ Dangerous command blocked: '{args}'", "files_modified": []}
        try:
            result = subprocess.run(args, shell=True, capture_output=True, text=True, cwd=self.project_root, timeout=30)
            output = result.stdout + (f"\n{result.stderr}" if result.stderr else "")
            return {"output": f"💻 {args}:\n{'='*60}\n{output}", "files_modified": []}
        except subprocess.TimeoutExpired:
            return {"output": "Command timed out (30s limit)", "files_modified": []}
        except Exception as e:
            return {"output": f"Error: {e}", "files_modified": []}

    def _run_python(self, args: str) -> Dict[str, Any]:
        """Execute Python code."""
        if not args:
            return {"output": "Usage: python <code>", "files_modified": []}
        try:
            result = subprocess.run([self._get_python_path(), "-c", args], capture_output=True, text=True, cwd=self.project_root, timeout=30)
            output = result.stdout + (f"\nError: {result.stderr}" if result.stderr else "")
            return {"output": f"🐍 Python:\n{'='*60}\n{output}", "files_modified": []}
        except subprocess.TimeoutExpired:
            return {"output": "Python execution timed out (30s limit)", "files_modified": []}
        except Exception as e:
            return {"output": f"Error: {e}", "files_modified": []}

    def _review_file(self, args: str) -> Dict[str, Any]:
        """Review a file and provide suggestions."""
        if not args:
            return {"output": "Usage: review <file_path>", "files_modified": []}
        file_path = self._resolve_path(args)
        if not file_path.exists():
            return {"output": f"File not found: {args}", "files_modified": []}
        content = file_path.read_text(encoding="utf-8", errors="replace")
        lines = content.split("\n")
        issues = []
        suggestions = []
        for i, line in enumerate(lines, 1):
            if "print(" in line and "debug" not in line.lower():
                suggestions.append(f"Line {i}: Consider using logging instead of print()")
            if "TODO" in line or "FIXME" in line:
                issues.append(f"Line {i}: {line.strip()}")
            if "except:" in line and "except Exception" not in line:
                issues.append(f"Line {i}: Bare except clause")
            if "import *" in line:
                issues.append(f"Line {i}: Wildcard import")
        output = f"📋 Review: {file_path.relative_to(self.project_root)}\n{'='*60}\n"
        output += f"📊 Stats: {len(lines)} lines\n"
        if issues:
            output += f"\n⚠️ Issues ({len(issues)}):\n"
            for issue in issues[:10]:
                output += f"  • {issue}\n"
        else:
            output += "\n✅ No obvious issues found!\n"
        if suggestions:
            output += f"\n💡 Suggestions ({len(suggestions)}):\n"
            for s in suggestions[:10]:
                output += f"  • {s}\n"
        return {"output": output, "files_modified": []}

    def _help(self, args: str = "") -> Dict[str, Any]:
        """Show help information."""
        return {
            "output": (
                "🛡️ Vrindha Dev Assistant - Commands\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                "📖 read <file>       - Read a file\n"
                "🔍 grep <pat> [glob] - Search files (default: *.py)\n"
                "📂 files [pattern]   - List files (default: *.py)\n"
                "📊 status            - Project status overview\n"
                "✏️  patch <file>      - Edit a file (interactive)\n"
                "🌿 git [args]        - Git commands (safe only)\n"
                "💻 run <cmd>         - Run shell command\n"
                "🐍 python <code>     - Execute Python code\n"
                "📋 review <file>     - Review file for issues\n"
                "❓ help              - Show this help\n"
                "🚪 exit              - Return to SOC mode\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                "Or just type naturally: 'show me brain.py', 'what files handle auth?', "
                "'review main.py', 'fix the nmap output formatting'"
            ),
            "files_modified": []
        }

    def _resolve_path(self, path_str: str) -> Path:
        """Resolve a relative path against project root."""
        path = Path(path_str)
        if path.is_absolute():
            return path
        return self.project_root / path_str

    def exit_dev(self) -> str:
        """Return exit message and restore original directory."""
        os.chdir(self.original_cwd)
        return "Exiting Developer Assistant. Back to SOC mode. 🛡️"
