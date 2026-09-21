"""
Developer Assistant Module - Vrindha SOC
A CLI developer assistant that can read, review, and modify the project.
Integrates with brain.py as a 'dev' command mode.
"""
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


class DevAssistant:
    """
    Developer Assistant for Vrindha AI SOC.
    
    Capabilities:
    - Read any file in the project
    - Search/grep across files
    - Edit/patch files with simple commands
    - Git operations (status, diff, log, commit)
    - Run Python commands
    - Project overview/status
    """
    
    def __init__(self):
        """Initialize DevAssistant with project root detection."""
        # Detect project root
        self.project_root = self._detect_project_root()
        self.original_cwd = os.getcwd()
        
    def _detect_project_root(self) -> Path:
        """Detect Vrindha project root by looking for vrin_SOC directory."""
        current = Path.cwd()
        
        # Check current and parent directories
        for path in [current] + list(current.parents):
            if (path / "vrin_SOC").is_dir():
                return path
            if (path / "vrin_SOC" / "main.py").is_file():
                return path
        
        # Fallback to known path
        fallback = Path("/mnt/c/Users/n4ndh/Documents/port/vrind/BACKEND")
        if fallback.exists():
            return fallback
        
        return current
    
    def enter(self) -> str:
        """Return greeting message when entering dev mode."""
        os.chdir(self.project_root)
        
        greeting = (
            "🛡️ Vrindha Developer Assistant 🛡️\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📁 Project Root: {self.project_root}\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "Available commands:\n"
            "  read <file>           - Read a file\n"
            "  grep <pattern>        - Search files for pattern\n"
            "  patch <file>          - Edit a file (interactive)\n"
            "  status                - Project status overview\n"
            "  git [args...]         - Run git commands\n"
            "  run <command>         - Run shell command\n"
            "  python <code>         - Execute Python code\n"
            "  files [pattern]       - List files matching pattern\n"
            "  review <file>         - Review a file with suggestions\n"
            "  exit                  - Return to SOC mode\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        )
        return greeting
    
    def process(self, user_input: str) -> Dict[str, Any]:
        """
        Process a developer command.
        
        Args:
            user_input: The user's command string
            
        Returns:
            Dict with 'output' and 'files_modified' keys
        """
        if not user_input.strip():
            return {"output": "No command provided.", "files_modified": []}
        
        # Parse command
        parts = user_input.strip().split(None, 1)
        command = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        
        # Route to handler
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
        }
        
        handler = handlers.get(command)
        if handler:
            return handler(args)
        else:
            return {
                "output": (
                    f"Unknown command: '{command}'\n"
                    f"Available: read, grep, files, status, patch, git, run, python, review, exit"
                ),
                "files_modified": []
            }
    
    def exit_dev(self) -> str:
        """Return exit message and restore original directory."""
        os.chdir(self.original_cwd)
        return "Exiting Developer Assistant. Back to SOC mode. 🌸"
    
    def _read_file(self, args: str) -> Dict[str, Any]:
        """Read and display a file."""
        if not args:
            return {"output": "Usage: read <file_path>", "files_modified": []}
        
        file_path = self._resolve_path(args)
        
        try:
            if not file_path.exists():
                return {"output": f"File not found: {args}", "files_modified": []}
            
            if not file_path.is_file():
                return {"output": f"Not a file: {args}", "files_modified": []}
            
            content = file_path.read_text(encoding="utf-8", errors="replace")
            
            # Limit output for large files
            lines = content.split("\n")
            if len(lines) > 100:
                truncated = True
                display_lines = lines[:50] + ["... (truncated, use 'read' with line limit) ..."] + lines[-50:]
                content_display = "\n".join(display_lines)
            else:
                truncated = False
                content_display = content
            
            line_info = f" ({len(lines)} lines)" + (" [truncated]" if truncated else "")
            return {
                "output": f"📖 {file_path.relative_to(self.project_root)}{line_info}\n{'='*60}\n{content_display}",
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
                if len(matches) > 50:
                    output = "\n".join(matches[:50]) + f"\n... ({len(matches)} total matches, showing first 50)"
                else:
                    output = result.stdout.strip()
                return {"output": f"🔍 Results for '{pattern}':\n{'='*60}\n{output}", "files_modified": []}
            else:
                return {"output": f"No matches found for '{pattern}'", "files_modified": []}
        except Exception as e:
            return {"output": f"Error searching: {e}", "files_modified": []}
    
    def _list_files(self, args: str) -> Dict[str, Any]:
        """List files matching a pattern."""
        pattern = args if args else "*.py"
        
        try:
            files = list(self.project_root.rglob(pattern))
            # Filter out common non-project dirs
            files = [f for f in files if not any(part.startswith('.') and part != '.venv_kali' for part in f.relative_to(self.project_root).parts)]
            files = [f for f in files if '.venv_kali' not in str(f)]
            files = [f for f in files if '__pycache__' not in str(f)]
            
            if not files:
                return {"output": f"No files matching '{pattern}'", "files_modified": []}
            
            # Sort and group by directory
            files.sort()
            output_lines = [f"📂 Files matching '{pattern}' ({len(files)} total):\n{'='*60}"]
            
            for f in files[:100]:
                rel_path = f.relative_to(self.project_root)
                output_lines.append(f"  {rel_path}")
            
            if len(files) > 100:
                output_lines.append(f"\n... and {len(files) - 100} more")
            
            return {"output": "\n".join(output_lines), "files_modified": []}
        except Exception as e:
            return {"output": f"Error listing files: {e}", "files_modified": []}
    
    def _project_status(self, args: str = "") -> Dict[str, Any]:
        """Show project status overview."""
        try:
            # Git branch
            branch_result = subprocess.run(
                ["git", "branch", "--show-current"],
                capture_output=True, text=True, cwd=self.project_root
            )
            branch = branch_result.stdout.strip() or "unknown"
            
            # Git status
            status_result = subprocess.run(
                ["git", "status", "--porcelain"],
                capture_output=True, text=True, cwd=self.project_root
            )
            changes = [line for line in status_result.stdout.strip().split("\n") if line]
            
            # Recent commits
            log_result = subprocess.run(
                ["git", "log", "--oneline", "-5"],
                capture_output=True, text=True, cwd=self.project_root
            )
            recent_commits = log_result.stdout.strip()
            
            # File counts
            py_files = len(list(self.project_root.rglob("*.py")))
            md_files = len(list(self.project_root.rglob("*.md")))
            
            # venv status
            venv_exists = (self.project_root / ".venv_kali").is_dir()
            
            output = (
                f"📊 Project Status: Vrindha AI SOC\n"
                f"{'='*60}\n"
                f"📁 Root: {self.project_root}\n"
                f"🌿 Branch: {branch}\n"
                f"📝 Uncommitted changes: {len(changes)}\n"
                f"{'─'*40}\n"
                f"📄 Python files: {py_files}\n"
                f"📄 Markdown files: {md_files}\n"
                f"🐍 .venv_kali: {'✅' if venv_exists else '❌'}\n"
                f"{'─'*40}\n"
                f"📜 Recent commits:\n{recent_commits}\n"
            )
            
            if changes:
                output += f"{'─'*40}\n📝 Changed files:\n"
                for change in changes[:10]:
                    output += f"  {change}\n"
                if len(changes) > 10:
                    output += f"  ... and {len(changes) - 10} more\n"
            
            return {"output": output, "files_modified": []}
        except Exception as e:
            return {"output": f"Error getting status: {e}", "files_modified": []}
    
    def _patch_file(self, args: str) -> Dict[str, Any]:
        """Simple file patching - supports line-based edits."""
        if not args:
            return {"output": "Usage: patch <file_path>\nThen provide: <line_number>: <new_content>", "files_modified": []}
        
        file_path = self._resolve_path(args)
        
        if not file_path.exists():
            return {"output": f"File not found: {args}", "files_modified": []}
        
        # Show file content with line numbers
        content = file_path.read_text(encoding="utf-8")
        lines = content.split("\n")
        
        output = f"📝 {file_path.relative_to(self.project_root)} - Enter edits as '<line>: <new_text>'\n"
        output += f"{'='*60}\n"
        for i, line in enumerate(lines, 1):
            output += f"{i:4d} | {line}\n"
        output += f"{'='*60}\n"
        output += "Enter 'done' to apply changes, 'cancel' to abort.\n"
        output += "Format: <line_number>: <new_content>\n"
        
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
            
            new_content = "\n".join(lines)
            path.write_text(new_content, encoding="utf-8")
            
            return {
                "output": f"✅ Applied {len(edits)} edit(s) to {path.relative_to(self.project_root)}",
                "files_modified": [str(path.relative_to(self.project_root))]
            }
        except Exception as e:
            return {"output": f"Error applying patch: {e}", "files_modified": []}
    
    def _git_command(self, args: str) -> Dict[str, Any]:
        """Run a git command."""
        if not args:
            args = "status"
        
        try:
            cmd = ["git"] + shlex.split(args)
            
            # Safety: block dangerous commands
            dangerous = ["push", "reset", "checkout", "branch -D", "clean -f"]
            if any(d in args for d in dangerous):
                return {
                    "output": f"⚠️ Dangerous git command blocked: '{args}'\nUse 'run' for raw git access.",
                    "files_modified": []
                }
            
            result = subprocess.run(
                cmd, capture_output=True, text=True, cwd=self.project_root
            )
            
            output = result.stdout
            if result.stderr:
                output += f"\n{result.stderr}"
            
            return {"output": f"🌿 git {args}:\n{'='*60}\n{output}", "files_modified": []}
        except Exception as e:
            return {"output": f"Error running git: {e}", "files_modified": []}
    
    def _run_command(self, args: str) -> Dict[str, Any]:
        """Run a shell command."""
        if not args:
            return {"output": "Usage: run <shell_command>", "files_modified": []}
        
        try:
            # Safety: block dangerous commands
            dangerous = ["rm -rf /", "mkfs", "dd if=/dev/zero", "sudo rm"]
            if any(d in args for d in dangerous):
                return {"output": f"⚠️ Dangerous command blocked: '{args}'", "files_modified": []}
            
            result = subprocess.run(
                args, shell=True, capture_output=True, text=True, cwd=self.project_root
            )
            
            output = result.stdout
            if result.stderr:
                output += f"\n{result.stderr}"
            
            return {"output": f"💻 {args}:\n{'='*60}\n{output}", "files_modified": []}
        except Exception as e:
            return {"output": f"Error running command: {e}", "files_modified": []}
    
    def _run_python(self, args: str) -> Dict[str, Any]:
        """Execute Python code."""
        if not args:
            return {"output": "Usage: python <code>", "files_modified": []}
        
        try:
            result = subprocess.run(
                [self._get_python_path(), "-c", args],
                capture_output=True, text=True, cwd=self.project_root
            )
            
            output = result.stdout
            if result.stderr:
                output += f"\nError: {result.stderr}"
            
            return {"output": f"🐍 Python:\n{'='*60}\n{output}", "files_modified": []}
        except Exception as e:
            return {"output": f"Error running Python: {e}", "files_modified": []}
    
    def _review_file(self, args: str) -> Dict[str, Any]:
        """Review a file and provide suggestions."""
        if not args:
            return {"output": "Usage: review <file_path>", "files_modified": []}
        
        file_path = self._resolve_path(args)
        
        if not file_path.exists():
            return {"output": f"File not found: {args}", "files_modified": []}
        
        content = file_path.read_text(encoding="utf-8", errors="replace")
        lines = content.split("\n")
        
        # Simple review heuristics
        issues = []
        suggestions = []
        
        # Check for common issues
        for i, line in enumerate(lines, 1):
            if "print(" in line and "debug" not in line.lower():
                suggestions.append(f"Line {i}: Consider using logging instead of print()")
            if "TODO" in line or "FIXME" in line:
                issues.append(f"Line {i}: {line.strip()}")
            if "except:" in line and "except Exception" not in line:
                issues.append(f"Line {i}: Bare except clause - be specific")
            if "import *" in line:
                issues.append(f"Line {i}: Wildcard import - use specific imports")
        
        # Check file structure
        if file_path.suffix == ".py":
            has_docstring = content.strip().startswith('"""') or content.strip().startswith("'''")
            if not has_docstring and len(lines) > 5:
                suggestions.append("Consider adding a module docstring")
        
        # Generate review report
        output = f"📋 Review: {file_path.relative_to(self.project_root)}\n"
        output += f"{'='*60}\n"
        output += f"📊 Stats: {len(lines)} lines, {len(content)} chars\n"
        
        if issues:
            output += f"\n⚠️ Issues ({len(issues)}):\n"
            for issue in issues[:10]:
                output += f"  • {issue}\n"
            if len(issues) > 10:
                output += f"  ... and {len(issues) - 10} more\n"
        else:
            output += "\n✅ No obvious issues found!\n"
        
        if suggestions:
            output += f"\n💡 Suggestions ({len(suggestions)}):\n"
            for suggestion in suggestions[:10]:
                output += f"  • {suggestion}\n"
            if len(suggestions) > 10:
                output += f"  ... and {len(suggestions) - 10} more\n"
        
        return {"output": output, "files_modified": []}
    
    def _resolve_path(self, path_str: str) -> Path:
        """Resolve a relative path against project root."""
        path = Path(path_str)
        if path.is_absolute():
            return path
        return self.project_root / path_str
    
    def _get_python_path(self) -> str:
        """Get the path to the project's Python interpreter."""
        venv_python = self.project_root / ".venv_kali" / "bin" / "python"
        if venv_python.exists():
            return str(venv_python)
        return "python3"
