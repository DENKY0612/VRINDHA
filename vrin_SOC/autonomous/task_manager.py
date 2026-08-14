import json
import sqlite3
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime
from database.db import get_connection
from .models import GoalRecord, TaskRecord, GoalStatus, TaskStatus, RiskLevel
from .policy import AutonomyPolicy


class TaskManager:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        if self.db_path:
            conn = sqlite3.connect(self.db_path, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            return conn
        return get_connection()

    def _init_db(self):
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS autonomous_goals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                goal_text TEXT,
                category TEXT,
                priority TEXT,
                autonomy_level TEXT,
                scope TEXT,
                requires_confirmation INTEGER,
                status TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS autonomous_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT UNIQUE,
                goal_id INTEGER,
                description TEXT,
                action_type TEXT,
                tool TEXT,
                arguments TEXT,
                risk TEXT,
                requires_approval INTEGER,
                rollback_strategy TEXT,
                verification TEXT,
                timeout INTEGER,
                status TEXT,
                created_at TEXT,
                updated_at TEXT,
                FOREIGN KEY(goal_id) REFERENCES autonomous_goals(id) ON DELETE CASCADE
            )
        """)
        conn.commit()
        conn.close()

    def create_goal(self, goal_meta: Dict) -> Dict:
        record = GoalRecord(
            goal_text=goal_meta["goal"],
            category=goal_meta["category"],
            priority=goal_meta["priority"],
            autonomy_level=goal_meta["autonomy_level"],
            scope=goal_meta["scope"],
            requires_confirmation=goal_meta["requires_confirmation"],
            status=GoalStatus.PLANNED.value,
        )
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO autonomous_goals (goal_text, category, priority, autonomy_level, scope, requires_confirmation, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (record.goal_text, record.category, record.priority, record.autonomy_level, record.scope, int(record.requires_confirmation), record.status, record.created_at, record.updated_at),
        )
        conn.commit()
        record.id = cur.lastrowid
        conn.close()
        return record.to_dict()

    def create_tasks(self, goal_id: int, tasks: List[Dict]) -> List[Dict]:
        stored = []
        conn = self._get_connection()
        cur = conn.cursor()
        for task in tasks:
            status = TaskStatus.WAITING_APPROVAL.value if task.get("requires_approval", False) else TaskStatus.PLANNED.value
            record = TaskRecord(
                task_id=task["task_id"],
                goal_id=goal_id,
                description=task["description"],
                action_type=task["action_type"],
                tool=task["tool"],
                arguments=task.get("arguments", {}),
                risk=task.get("risk", RiskLevel.LOW.value),
                requires_approval=task.get("requires_approval", False),
                rollback_strategy=task.get("rollback_strategy", "none"),
                verification=task.get("verification", "none"),
                timeout=task.get("timeout", 30),
                status=status,
            )
            cur.execute(
                "INSERT INTO autonomous_tasks (task_id, goal_id, description, action_type, tool, arguments, risk, requires_approval, rollback_strategy, verification, timeout, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.task_id,
                    record.goal_id,
                    record.description,
                    record.action_type,
                    record.tool,
                    json.dumps(record.arguments),
                    record.risk,
                    int(record.requires_approval),
                    record.rollback_strategy,
                    record.verification,
                    record.timeout,
                    record.status,
                    record.created_at,
                    record.updated_at,
                ),
            )
            record.id = cur.lastrowid
            stored.append(record.to_dict())
        conn.commit()
        conn.close()
        return stored

    def list_goals(self) -> List[Dict]:
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM autonomous_goals ORDER BY id DESC")
        rows = [dict(row) for row in cur.fetchall()]
        conn.close()
        return rows

    def _decode_task_row(self, row: sqlite3.Row) -> Dict:
        task = dict(row)
        try:
            task["arguments"] = json.loads(task.get("arguments") or "{}")
        except Exception:
            task["arguments"] = {}
        return task

    def list_tasks(self, goal_id: Optional[int] = None) -> List[Dict]:
        conn = self._get_connection()
        cur = conn.cursor()
        if goal_id is not None:
            cur.execute("SELECT * FROM autonomous_tasks WHERE goal_id = ? ORDER BY id", (goal_id,))
        else:
            cur.execute("SELECT * FROM autonomous_tasks ORDER BY id DESC")
        rows = [self._decode_task_row(row) for row in cur.fetchall()]
        conn.close()
        return rows

    def get_task(self, task_id: str) -> Optional[Dict]:
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM autonomous_tasks WHERE task_id = ?", (task_id,))
        row = cur.fetchone()
        conn.close()
        return self._decode_task_row(row) if row else None

    def update_task_status(self, task_id: str, status: str) -> Optional[Dict]:
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("UPDATE autonomous_tasks SET status = ?, updated_at = ? WHERE task_id = ?", (status, datetime.now().isoformat(), task_id))
        conn.commit()
        cur.execute("SELECT * FROM autonomous_tasks WHERE task_id = ?", (task_id,))
        row = cur.fetchone()
        conn.close()
        return self._decode_task_row(row) if row else None

    def update_goal_status(self, goal_id: int, status: str) -> Optional[Dict]:
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("UPDATE autonomous_goals SET status = ?, updated_at = ? WHERE id = ?", (status, datetime.now().isoformat(), goal_id))
        conn.commit()
        cur.execute("SELECT * FROM autonomous_goals WHERE id = ?", (goal_id,))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_goal(self, goal_id: int) -> Optional[Dict]:
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM autonomous_goals WHERE id = ?", (goal_id,))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None

    def get_tasks_by_status(self, statuses: List[str]) -> List[Dict]:
        if not statuses:
            return []
        conn = self._get_connection()
        cur = conn.cursor()
        placeholders = ",".join(["?" for _ in statuses])
        cur.execute(f"SELECT * FROM autonomous_tasks WHERE status IN ({placeholders}) ORDER BY id", tuple(statuses))
        rows = []
        for row in cur.fetchall():
            task = dict(row)
            try:
                task["arguments"] = json.loads(task.get("arguments") or "{}")
            except Exception:
                task["arguments"] = {}
            rows.append(task)
        conn.close()
        return rows

    def recover_unfinished_tasks(self) -> List[Dict]:
        conn = self._get_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM autonomous_tasks WHERE status IN (?, ?, ?, ?) ORDER BY id",
            (TaskStatus.PLANNED.value, TaskStatus.VALIDATING.value, TaskStatus.WAITING_APPROVAL.value, TaskStatus.RUNNING.value),
        )
        rows = []
        for row in cur.fetchall():
            task = dict(row)
            try:
                task["arguments"] = json.loads(task.get("arguments") or "{}")
            except Exception:
                task["arguments"] = {}
            rows.append(task)
        conn.close()
        return rows


task_manager = TaskManager()
