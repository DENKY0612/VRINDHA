import sqlite3
from datetime import datetime
from typing import Dict, Optional
from database.db import get_connection


class AutonomousStateManager:
    def __init__(self):
        self._init_state_table()

    def _get_connection(self):
        conn = get_connection()
        conn.row_factory = sqlite3.Row
        return conn

    def _init_state_table(self):
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS autonomous_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                active INTEGER DEFAULT 0,
                emergency_stopped INTEGER DEFAULT 0,
                last_heartbeat TEXT,
                current_mode TEXT DEFAULT 'defensive',
                updated_at TEXT
            )
            """
        )
        cur.execute("INSERT OR IGNORE INTO autonomous_state (id, active, emergency_stopped, last_heartbeat, current_mode, updated_at) VALUES (1, 0, 0, NULL, 'defensive', ?)", (datetime.now().isoformat(),))
        conn.commit()
        conn.close()

    def get_state(self) -> Dict[str, Optional[str]]:
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM autonomous_state WHERE id = 1")
        row = cur.fetchone()
        conn.close()
        if not row:
            return {
                "active": False,
                "emergency_stopped": False,
                "last_heartbeat": None,
                "current_mode": "defensive",
                "updated_at": None,
            }
        return {
            "active": bool(row["active"]),
            "emergency_stopped": bool(row["emergency_stopped"]),
            "last_heartbeat": row["last_heartbeat"],
            "current_mode": row["current_mode"],
            "updated_at": row["updated_at"],
        }

    def update_state(self, active: Optional[bool] = None, emergency_stopped: Optional[bool] = None, last_heartbeat: Optional[str] = None, current_mode: Optional[str] = None) -> Dict[str, Optional[str]]:
        state = self.get_state()
        if active is not None:
            state["active"] = active
        if emergency_stopped is not None:
            state["emergency_stopped"] = emergency_stopped
        if last_heartbeat is not None:
            state["last_heartbeat"] = last_heartbeat
        if current_mode is not None:
            state["current_mode"] = current_mode
        state["updated_at"] = datetime.now().isoformat()

        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE autonomous_state SET active = ?, emergency_stopped = ?, last_heartbeat = ?, current_mode = ?, updated_at = ? WHERE id = 1",
            (
                int(state["active"]),
                int(state["emergency_stopped"]),
                state["last_heartbeat"],
                state["current_mode"],
                state["updated_at"],
            ),
        )
        conn.commit()
        conn.close()
        return state


state_manager = AutonomousStateManager()
