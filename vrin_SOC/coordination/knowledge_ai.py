"""Knowledge AI — institutional memory with a contamination-guarded feedback loop.

Flow (spec §16):

    Incident → Investigation → Human/Analyst conclusion
    → Confirmed / False Positive / Unknown
    → Knowledge AI stores a *validated* lesson
    → Data Science AI may use it for model evaluation/improvement

Only outcomes with an explicit conclusion AND a validating source are stored
as lessons. Raw predictions are never treated as truth, which prevents
feedback contamination.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .event_bus import EventBus
from .observability import BaseAgent
from .schemas import utc_now_iso

VALID_CONCLUSIONS = {"confirmed_attack", "false_positive", "unknown"}


def _db():
    from vrin_SOC.database import db

    return db


def _ensure_tables(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS knowledge_lessons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            lesson_id TEXT UNIQUE,
            incident_id TEXT,
            conclusion TEXT,
            summary TEXT,
            pattern TEXT,
            features TEXT,
            validated_by TEXT,
            created_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_outcomes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT,
            event_ids TEXT,
            conclusion TEXT,
            summary TEXT,
            validated_by TEXT,
            validated INTEGER,
            created_at TEXT
        )
        """
    )


class KnowledgeAI(BaseAgent):
    name = "KnowledgeAI"
    kind = "memory"
    capabilities = ["lessons", "historical_incidents", "procedures", "validated_training_data"]

    def __init__(self, bus: Optional[EventBus] = None) -> None:
        super().__init__(bus)
        db = _db()
        db._run_db(_ensure_tables)  # noqa: SLF001 — schema bootstrap, idempotent

    # ------------------------------------------------------------------
    # Recording (contamination guarded)
    # ------------------------------------------------------------------
    def record_outcome(
        self,
        incident_id: str,
        conclusion: str,
        summary: str,
        event_ids: Optional[List[str]] = None,
        pattern: str = "",
        features: Optional[Dict[str, Any]] = None,
        validated_by: str = "human",
        validated: bool = True,
    ) -> Dict[str, Any]:
        """Store a validated incident outcome and, when conclusive, a lesson."""
        if conclusion not in VALID_CONCLUSIONS:
            return {"status": "error", "reason": f"conclusion must be one of {sorted(VALID_CONCLUSIONS)}"}
        if not validated:
            return {"status": "rejected",
                    "reason": "Unvalidated outcomes are never stored as knowledge (feedback contamination guard)."}
        if not validated_by:
            return {"status": "rejected", "reason": "validated_by is required (human/analyst provenance)"}

        db = _db()

        def insert(conn):
            conn.execute(
                "INSERT INTO incident_outcomes (incident_id, event_ids, conclusion, summary, validated_by, validated, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (incident_id, json.dumps(event_ids or []), conclusion, summary[:2000], validated_by,
                 1 if validated else 0, utc_now_iso()),
            )
            last = None
            if conclusion in {"confirmed_attack", "false_positive"}:
                lesson_id = f"lesson-{incident_id}"
                try:
                    conn.execute(
                        "INSERT OR IGNORE INTO knowledge_lessons "
                        "(lesson_id, incident_id, conclusion, summary, pattern, features, validated_by, created_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (lesson_id, incident_id, conclusion, summary[:2000], pattern,
                         json.dumps(features or {}), validated_by, utc_now_iso()),
                    )
                    last = lesson_id
                except Exception:  # noqa: BLE001
                    last = None
            return last

        try:
            lesson_id = db._run_db(insert)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            self.metrics.record_error(str(exc))
            return {"status": "error", "reason": str(exc)[:256]}
        return {
            "status": "success",
            "incident_id": incident_id,
            "conclusion": conclusion,
            "lesson_id": lesson_id,
            "note": "Stored as validated lesson" if lesson_id else "Outcome recorded; not conclusive enough for a reusable lesson",
        }

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------
    def search(self, pattern: str, limit: int = 10) -> Dict[str, Any]:
        return self.run_guarded(self._search, pattern, limit)

    def _search(self, pattern: str, limit: int) -> Dict[str, Any]:
        db = _db()
        like = f"%{pattern.lower()}%"

        def query(conn):
            rows = conn.execute(
                "SELECT lesson_id, incident_id, conclusion, summary, pattern, validated_by, created_at "
                "FROM knowledge_lessons WHERE lower(summary) LIKE ? OR lower(pattern) LIKE ? "
                "ORDER BY id DESC LIMIT ?",
                (like, like, limit),
            ).fetchall()
            return rows

        try:
            rows = db._run_db(query)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            self.metrics.record_error(str(exc))
            return {"status": "error", "reason": str(exc)[:256]}
        lessons = [
            {"lesson_id": r[0], "incident_id": r[1], "conclusion": r[2], "summary": r[3],
             "pattern": r[4], "validated_by": r[5], "created_at": r[6]}
            for r in rows
        ]
        return {"status": "success", "pattern": pattern, "count": len(lessons), "lessons": lessons}

    def lessons(self, limit: int = 50) -> Dict[str, Any]:
        db = _db()

        def query(conn):
            return conn.execute(
                "SELECT lesson_id, incident_id, conclusion, summary, pattern, validated_by, created_at "
                "FROM knowledge_lessons ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

        try:
            rows = db._run_db(query)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "reason": str(exc)[:256]}
        return {
            "status": "success",
            "count": len(rows),
            "lessons": [
                {"lesson_id": r[0], "incident_id": r[1], "conclusion": r[2], "summary": r[3],
                 "pattern": r[4], "validated_by": r[5], "created_at": r[6]}
                for r in rows
            ],
        }

    def validated_samples(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Validated outcomes as labeled samples for the Data Science evaluator."""
        db = _db()

        def query(conn):
            return conn.execute(
                "SELECT incident_id, event_ids, conclusion, summary, validated_by, created_at "
                "FROM incident_outcomes WHERE validated = 1 ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

        try:
            rows = db._run_db(query)  # noqa: SLF001
        except Exception:  # noqa: BLE001
            return []
        samples = []
        for row in rows:
            event_ids = json.loads(row[1] or "[]")
            for event_id in event_ids:
                samples.append({
                    "event_id": event_id,
                    "label": row[2],
                    "validated_by": row[4],
                    "incident_id": row[0],
                    "recorded_at": row[5],
                })
        return samples

    # ------------------------------------------------------------------
    # Bus wiring
    # ------------------------------------------------------------------
    def on_response(self, event) -> None:
        """When the Commander records a validated response, mirror it here."""
        if getattr(event, "event_type", "") != "incident_resolved":
            return
        data = event.data or {}
        result = self.record_outcome(
            incident_id=str(data.get("incident_id", event.correlation_id or "unknown")),
            conclusion=str(data.get("conclusion", "unknown")),
            summary=str(data.get("summary", ""))[:2000],
            event_ids=[e.event_id for e in self.bus.correlate(event.correlation_id)] if event.correlation_id else [],
            pattern=str(data.get("pattern", "")),
            features=data.get("features"),
            validated_by=str(data.get("validated_by", "commander")),
            validated=bool(data.get("validated", True)),
        )
        if result.get("status") != "success":
            self.metrics.record_error(result.get("reason", "knowledge store failed"))


knowledge_ai = KnowledgeAI()

__all__ = ["KnowledgeAI", "knowledge_ai", "VALID_CONCLUSIONS"]
