"""Safe local YARA classification; samples are read, never executed."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable
from datetime import datetime, timezone

from ..security import validate_local_file


class YARAIntegration:
    def __init__(self, rules_path: str, allowed_roots: Iterable[str]):
        self.rules_path = Path(rules_path).expanduser().resolve() if rules_path else None
        self.allowed_roots = list(allowed_roots)

    def status(self) -> Dict[str, Any]:
        try:
            import yara  # type: ignore # noqa: F401
        except ImportError:
            return {"status": "missing", "detail": "python-yara is not installed"}
        if not self.rules_path:
            return {"status": "disabled", "detail": "YARA_RULES_PATH is not configured"}
        if not self.rules_path.is_file():
            return {"status": "error", "detail": "configured YARA rules file does not exist"}
        return {"status": "installed", "rules_path": str(self.rules_path)}

    def scan(self, path: str) -> Dict[str, Any]:
        state = self.status()
        if state["status"] != "installed":
            return state
        try:
            sample = validate_local_file(path, self.allowed_roots)
            import yara  # type: ignore
            rules = yara.compile(filepath=str(self.rules_path))
            matches = rules.match(filepath=str(sample), timeout=10)
            return {"status": "success", "file": str(sample), "matches": [{"rule": item.rule, "namespace": item.namespace,
                    "tags": list(item.tags), "meta": dict(item.meta)} for item in matches],
                    "confidence": 0.9 if matches else 0.5, "timestamp": datetime.now(timezone.utc).isoformat(),
                    "executed_sample": False}
        except Exception as exc:
            # Includes path policy, malformed rule and YARA timeout errors. The
            # sample is never imported or executed.
            return {"status": "error", "error": str(exc)[:512], "executed_sample": False}
