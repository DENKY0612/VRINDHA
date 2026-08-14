"""
Memory System Prompt - Super Intelligence Layer
Features: Store threats, actions, outcomes, retrieve similar past cases, improve decision-making
Implementation: Use simple DB + vector-like similarity initially (keyword matching), later FAISS
"""
import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict
from .error_handler import ErrorHandler

class MemorySystem:
    def __init__(self, db_path: str = "database/memory.db"):
        self.db_path = Path(db_path)
        if not self.db_path.exists():
            # Try alternative locations
            alt = Path("vrindha/database/memory.db")
            if alt.parent.exists():
                self.db_path = alt
            else:
                alt2 = Path("/home/user/vrindha/database/memory.db")
                if alt2.parent.exists():
                    self.db_path = alt2
        
        self.init_db()
    
    def init_db(self):
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS memories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    event_type TEXT,
                    threat TEXT,
                    action_taken TEXT,
                    outcome TEXT,
                    risk_level TEXT,
                    embedding TEXT,
                    raw JSON
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            ErrorHandler.handle_exception(e, "MemorySystem.init_db")
    
    def save_memory(self, event: Dict) -> Dict:
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO memories (timestamp, event_type, threat, action_taken, outcome, risk_level, embedding, raw)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.get("timestamp", datetime.now().isoformat()),
                event.get("event_type", "generic"),
                event.get("threat", ""),
                event.get("action_taken", ""),
                event.get("outcome", ""),
                event.get("risk_level", "Low"),
                event.get("embedding", ""),  # placeholder for vector embedding
                json.dumps(event)
            ))
            conn.commit()
            conn.close()
            return {"status": "success", "message": "Memory saved"}
        except Exception as e:
            return ErrorHandler.handle_exception(e, "MemorySystem.save_memory")
    
    def retrieve_similar(self, query: str, limit: int = 5) -> Dict:
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            # Simple keyword matching for MVP - later use embeddings FAISS
            cur.execute("SELECT * FROM memories ORDER BY id DESC LIMIT 100")
            rows = cur.fetchall()
            conn.close()
            
            query_lower = query.lower()
            scored = []
            for row in rows:
                raw_json = row[8]
                try:
                    data = json.loads(raw_json)
                    text = f"{data.get('threat','')} {data.get('action_taken','')} {data.get('event_type','')}".lower()
                    # Simple scoring: count matching words
                    score = sum(1 for word in query_lower.split() if word in text)
                    if score > 0:
                        scored.append((score, data))
                except:
                    continue
            
            scored.sort(key=lambda x: x[0], reverse=True)
            similar = [item[1] for item in scored[:limit]]
            
            return {"status": "success", "query": query, "count": len(similar), "results": similar}
        except Exception as e:
            return ErrorHandler.handle_exception(e, "MemorySystem.retrieve_similar")
    
    def get_stats(self) -> Dict:
        try:
            conn = sqlite3.connect(str(self.db_path))
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*), risk_level FROM memories GROUP BY risk_level")
            rows = cur.fetchall()
            cur.execute("SELECT COUNT(*) FROM memories")
            total = cur.fetchone()[0]
            conn.close()
            return {"total_memories": total, "by_risk": dict(rows) if rows else {}}
        except Exception as e:
            return ErrorHandler.handle_exception(e, "MemorySystem.get_stats")

memory_system = MemorySystem()
