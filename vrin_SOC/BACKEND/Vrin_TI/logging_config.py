"""Structured rotating TI logs with basic secret redaction."""
from __future__ import annotations

from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any
import json
import logging
import re

SECRET_PATTERN = re.compile(r"(?i)(api[_-]?key|token|password|authorization)([\"'=:\s]+)([^\s,}\"]+)")


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        message = SECRET_PATTERN.sub(r"\1\2***", record.getMessage())
        value: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": message,
        }
        for key in ("event_type", "event_id", "correlation_id", "source", "outcome"):
            if hasattr(record, key):
                value[key] = getattr(record, key)
        if record.exc_info:
            value["exception"] = self.formatException(record.exc_info)[:8192]
        return json.dumps(value, ensure_ascii=False)


def configure_logging(directory: str | Path, level: str = "INFO") -> logging.Logger:
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("vrindha.ti")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not any(isinstance(item, RotatingFileHandler) and Path(item.baseFilename).parent == path for item in logger.handlers):
        handler = RotatingFileHandler(path / "threat_intelligence.jsonl", maxBytes=10_000_000, backupCount=10, encoding="utf-8")
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
    return logger
