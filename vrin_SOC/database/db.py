"""
Database & Logging Prompt per START UP.pdf and DAY 27-28
Design logging system for cybersecurity events
Database: SQLite (initial) -> PostgreSQL (later)
Tables: logs(id, timestamp, action, result, risk_level) plus command etc
Features: Store all AI actions, store tool outputs, enable querying logs
Provide: Python DB connection, insert log function, fetch logs function
"""
import sqlite3
import time
from pathlib import Path
from datetime import datetime
from typing import Callable, List, Dict, TypeVar
from vrin_SOC.core.error_handler import ErrorHandler

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PACKAGE_ROOT / "database" / "vrindha.db"
LOG_FILE = PACKAGE_ROOT / "logs" / "log.txt"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

# SQLite is still the lightweight default, but a short-lived connection per
# operation must tolerate other API/CLI requests writing at the same time.
SQLITE_TIMEOUT_SECONDS = 30
SQLITE_BUSY_TIMEOUT_MS = 30_000
SQLITE_RETRIES = 5
T = TypeVar("T")


def get_connection():
    conn = None
    try:
        conn = sqlite3.connect(str(DB_PATH), timeout=SQLITE_TIMEOUT_SECONDS)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn
    except Exception:
        if conn is not None:
            conn.close()
        raise


def _run_db(operation: Callable[[sqlite3.Connection], T]) -> T:
    """Run one DB operation with guaranteed cleanup and locked-db retries.

    The old implementation only closed connections on the success path. A
    failed write could therefore keep a handle alive and make the next API
    request report ``database is locked``. Retrying the complete operation is
    safe because callers only use INSERT/SELECT statements and the connection
    is rolled back before each retry.
    """
    for attempt in range(SQLITE_RETRIES):
        conn = None
        try:
            conn = get_connection()
            value = operation(conn)
            conn.commit()
            return value
        except sqlite3.OperationalError as exc:
            message = str(exc).lower()
            if "locked" not in message and "busy" not in message:
                raise
            if attempt == SQLITE_RETRIES - 1:
                raise
            # Keep the retry bounded while giving a competing writer time to
            # commit. busy_timeout handles normal contention; this covers a
            # lock acquired between statements or during WAL setup.
            time.sleep(0.05 * (2 ** attempt))
        finally:
            if conn is not None:
                conn.close()
    raise RuntimeError("database operation could not be completed")


def init_db():
    try:
        def create_tables(conn):
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    command TEXT,
                    result TEXT,
                    risk_level TEXT,
                    action TEXT,
                    mode TEXT
                )
            """)
            # Additional tables per advanced blueprint
            cur.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    threat_type TEXT,
                    source_ip TEXT,
                    risk_level TEXT,
                    description TEXT
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE,
                    reason TEXT,
                    timestamp TEXT
                )
            """)

        _run_db(create_tables)
        print(f"[DB] Initialized at {DB_PATH}")
    except Exception as e:
        ErrorHandler.handle_exception(e, "init_db")


def add_log(command: str, result: str, risk_level: str = "Low", action: str = "", mode: str = "") -> Dict:
    try:
        def insert(conn):
            conn.execute("""
                INSERT INTO logs (timestamp, command, result, risk_level, action, mode)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (datetime.now().isoformat(), command, result[:5000], risk_level, action, mode))

        _run_db(insert)

        # Also write to file per Day 18
        try:
            LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().isoformat()}] COMMAND: {command} | RISK: {risk_level} | RESULT: {result[:200]}\n")
        except OSError:
            pass

        return {"status": "success", "message": "Log added"}
    except Exception as e:
        return ErrorHandler.handle_exception(e, "add_log")


def get_logs(limit: int = 50) -> List[Dict]:
    try:
        rows = _run_db(lambda conn: conn.execute(
            "SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall())
        return [dict(row) for row in rows]
    except Exception as e:
        ErrorHandler.handle_exception(e, "get_logs")
        return []


def add_blocked_ip(ip: str, reason: str = "") -> Dict:
    try:
        def insert(conn):
            conn.execute(
                """
                INSERT INTO blocked_ips (ip, reason, timestamp)
                VALUES (?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason, timestamp=excluded.timestamp
                """,
                (ip, reason[:500], datetime.now().isoformat()),
            )

        _run_db(insert)
        return {"status": "success", "ip": ip, "reason": reason}
    except Exception as e:
        return ErrorHandler.handle_exception(e, "add_blocked_ip")


def get_blocked_ips(limit: int = 100) -> List[Dict]:
    try:
        rows = _run_db(lambda conn: conn.execute(
            "SELECT * FROM blocked_ips ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall())
        return [dict(row) for row in rows]
    except Exception as e:
        ErrorHandler.handle_exception(e, "get_blocked_ips")
        return []


def add_threat(threat_type: str, source_ip: str = "", risk_level: str = "Low", description: str = "") -> Dict:
    try:
        def insert(conn):
            conn.execute(
                """
                INSERT INTO threats (timestamp, threat_type, source_ip, risk_level, description)
                VALUES (?, ?, ?, ?, ?)
                """,
                (datetime.now().isoformat(), threat_type[:128], source_ip[:64], risk_level[:32], description[:2000]),
            )

        _run_db(insert)
        return {"status": "success", "threat_type": threat_type, "source_ip": source_ip, "risk_level": risk_level}
    except Exception as e:
        return ErrorHandler.handle_exception(e, "add_threat")


def get_threats(limit: int = 50) -> List[Dict]:
    try:
        rows = _run_db(lambda conn: conn.execute(
            "SELECT * FROM threats ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall())
        return [dict(row) for row in rows]
    except Exception as e:
        ErrorHandler.handle_exception(e, "get_threats")
        return []


def get_logs_by_risk(risk_level: str) -> List[Dict]:
    try:
        rows = _run_db(lambda conn: conn.execute(
            "SELECT * FROM logs WHERE risk_level=? ORDER BY id DESC", (risk_level,)
        ).fetchall())
        return [dict(row) for row in rows]
    except Exception as e:
        ErrorHandler.handle_exception(e, "get_logs_by_risk")
        return []


# Initialize on import
init_db()
