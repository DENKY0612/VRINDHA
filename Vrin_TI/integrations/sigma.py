"""Official Sigma-shaped YAML metadata loader for SOC correlation."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List
import re

ATTACK_TAG = re.compile(r"^attack\.(?:t\d{4}(?:\.\d{3})?|[a-z0-9_-]+)$", re.I)


class SigmaRuleError(ValueError):
    pass


class SigmaRuleLoader:
    REQUIRED = {"title", "logsource", "detection"}

    def __init__(self, rules_path: str):
        self.rules_path = Path(rules_path).expanduser().resolve()

    def parse(self, text: str, source: str = "memory") -> Dict[str, Any]:
        if len(text.encode("utf-8")) > 1_000_000:
            raise SigmaRuleError("Sigma rule exceeds 1 MiB")
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise SigmaRuleError("PyYAML is required for Sigma") from exc
        try:
            value = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise SigmaRuleError("malformed Sigma YAML") from exc
        if not isinstance(value, dict) or not self.REQUIRED.issubset(value):
            raise SigmaRuleError("Sigma rule requires title, logsource and detection")
        if not isinstance(value["logsource"], dict) or not isinstance(value["detection"], dict):
            raise SigmaRuleError("Sigma logsource and detection must be mappings")
        condition = value["detection"].get("condition")
        if not isinstance(condition, str) or len(condition) > 4096:
            raise SigmaRuleError("Sigma detection.condition is required")
        tags = [str(item) for item in value.get("tags", []) if isinstance(item, str)]
        return {"title": str(value["title"])[:256], "id": value.get("id"), "status": value.get("status", "experimental"),
                "description": str(value.get("description", ""))[:4096], "author": value.get("author"),
                "date": value.get("date"), "modified": value.get("modified"), "references": value.get("references", []),
                "logsource": value["logsource"], "detection": value["detection"], "falsepositives": value.get("falsepositives", []),
                "level": value.get("level", "medium"), "tags": tags,
                "mitre_attack_ids": sorted({tag.split(".", 1)[1].upper() for tag in tags if re.fullmatch(r"attack\.t\d{4}(?:\.\d{3})?", tag, re.I)}),
                "source": source}

    def load(self) -> List[Dict[str, Any]]:
        if not self.rules_path.exists():
            return []
        files = [self.rules_path] if self.rules_path.is_file() else list(self.rules_path.rglob("*.yml")) + list(self.rules_path.rglob("*.yaml"))
        rules = []
        for path in files[:10_000]:
            try:
                rules.append(self.parse(path.read_text(encoding="utf-8"), str(path)))
            except (OSError, UnicodeError, SigmaRuleError):
                continue
        return rules

    def status(self) -> Dict[str, Any]:
        try:
            rules = self.load()
            return {"status": "installed" if rules else ("disabled" if not self.rules_path.exists() else "degraded"),
                    "rules": len(rules), "path": str(self.rules_path)}
        except SigmaRuleError as exc:
            return {"status": "missing", "detail": str(exc)}
