"""
Rollback System for Controlled Response engine.

Implements §9: RollbackRecord rows for every state change; rollback execution.
Every state-changing action creates a rollback record for audit and potential reversal.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .schemas import RollbackRecord, utc_now_iso


# ---------------------------------------------------------------------------
# Rollback Database
# ---------------------------------------------------------------------------
class RollbackDB:
    """Thread-safe rollback record persistence."""

    def __init__(self, db_path: Optional[str | Path] = None) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        self.db_path = Path(db_path) if db_path else repo_root / "vrin_SOC" / "database" / "rollbacks.db"
        self._lock = threading.RLock()
        self._ensure_tables()

    def _ensure_tables(self) -> None:
        with self._lock:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS rollback_records (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        action_id TEXT NOT NULL UNIQUE,
                        action TEXT NOT NULL,
                        target TEXT NOT NULL,
                        target_kind TEXT NOT NULL,
                        executed_by TEXT NOT NULL,
                        executed_at TEXT NOT NULL,
                        expires_at TEXT,
                        reversible BOOLEAN NOT NULL,
                        reversible_alternative TEXT,
                        rollback_data TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'active',
                        rolled_back_at TEXT,
                        rolled_back_by TEXT,
                        rollback_reason TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_rollback_action_id ON rollback_records(action_id)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_rollback_status ON rollback_records(status)
                """)
                conn.commit()

    def create(self, record: RollbackRecord) -> RollbackRecord:
        """Insert a new rollback record."""
        with self._lock:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("""
                    INSERT INTO rollback_records (
                        action_id, action, target, target_kind, executed_by,
                        executed_at, expires_at, reversible, reversible_alternative,
                        rollback_data, status, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    record.action_id,
                    record.action,
                    record.target,
                    record.target_kind,
                    record.executed_by,
                    record.executed_at,
                    record.expires_at,
                    record.reversible,
                    record.reversible_alternative,
                    json.dumps(record.rollback_data),
                    record.status,
                    utc_now_iso(),
                    utc_now_iso(),
                ))
                conn.commit()
        return record

    def get(self, action_id: str) -> Optional[RollbackRecord]:
        """Retrieve a rollback record by action_id."""
        with self._lock:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT * FROM rollback_records WHERE action_id = ?",
                    (action_id,)
                ).fetchone()
                if not row:
                    return None
                return self._row_to_record(row)

    def list(self, limit: int = 50, active_only: bool = False) -> List[RollbackRecord]:
        """List rollback records, optionally only active ones."""
        with self._lock:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                if active_only:
                    rows = conn.execute(
                        "SELECT * FROM rollback_records WHERE status = 'active' ORDER BY created_at DESC LIMIT ?",
                        (limit,)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM rollback_records ORDER BY created_at DESC LIMIT ?",
                        (limit,)
                    ).fetchall()
                return [self._row_to_record(r) for r in rows]

    def mark_rolled_back(self, action_id: str, by: str, reason: str) -> bool:
        """Mark a record as rolled back."""
        with self._lock:
            with sqlite3.connect(str(self.db_path)) as conn:
                cur = conn.execute("""
                    UPDATE rollback_records
                    SET status = 'rolled_back', rolled_back_at = ?, rolled_back_by = ?, rollback_reason = ?, updated_at = ?
                    WHERE action_id = ? AND status = 'active'
                """, (utc_now_iso(), by, reason, utc_now_iso(), action_id))
                conn.commit()
                return cur.rowcount > 0

    def mark_expired(self, action_id: str) -> bool:
        """Mark a record as expired."""
        with self._lock:
            with sqlite3.connect(str(self.db_path)) as conn:
                cur = conn.execute("""
                    UPDATE rollback_records
                    SET status = 'expired', updated_at = ?
                    WHERE action_id = ? AND status = 'active'
                """, (utc_now_iso(), action_id))
                conn.commit()
                return cur.rowcount > 0

    def _row_to_record(self, row: sqlite3.Row) -> RollbackRecord:
        import json as _json
        return RollbackRecord(
            action_id=row["action_id"],
            action=row["action"],
            target=row["target"],
            target_kind=row["target_kind"],
            executed_by=row["executed_by"],
            executed_at=row["executed_at"],
            expires_at=row["expires_at"],
            reversible=bool(row["reversible"]),
            reversible_alternative=row["reversible_alternative"],
            rollback_data=_json.loads(row["rollback_data"]),
            status=row["status"],
            rolled_back_at=row["rolled_back_at"],
            rolled_back_by=row["rolled_back_by"],
            rollback_reason=row["rollback_reason"],
        )


# Module-level singleton
_rollback_db = RollbackDB()


def get_rollback_db() -> RollbackDB:
    return _rollback_db