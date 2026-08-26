"""
Data Pipeline - Phase 1: Data Foundation (from work for AI ML.pdf, work for data science.pdf)
Collect data from system: Logs (commands, outputs), network scans, threat detections
Convert into structured format JSON
Tools: Pandas, CSV/SQLite
"""
import json
import csv
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import List, Dict
from vrin_SOC.core.error_handler import ErrorHandler

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

PACKAGE_ROOT = Path(__file__).resolve().parent.parent


class DataPipeline:
    def __init__(self, db_path: str = None):
        candidate = Path(db_path) if db_path else PACKAGE_ROOT / "database" / "vrindha.db"
        self.db_path = candidate if candidate.is_absolute() else PACKAGE_ROOT / candidate
    
    def collect_logs(self) -> List[Dict]:
        try:
            if not self.db_path.exists():
                return []
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("SELECT * FROM logs")
            rows = cur.fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except Exception as e:
            ErrorHandler.handle_exception(e, "DataPipeline.collect_logs")
            return []
    
    def to_structured_json(self) -> List[Dict]:
        logs = self.collect_logs()
        structured = []
        for log in logs:
            structured.append({
                "timestamp": log.get("timestamp"),
                "command": log.get("command"),
                "result": log.get("result","")[:500],
                "risk_level": log.get("risk_level","Low")
            })
        return structured
    
    def to_csv(self, output_path: str = None) -> Dict:
        try:
            data = self.to_structured_json()
            destination = Path(output_path) if output_path else PACKAGE_ROOT / "data" / "training_data.csv"
            if not destination.is_absolute():
                destination = PACKAGE_ROOT / destination
            destination.parent.mkdir(parents=True, exist_ok=True)
            output_path = str(destination)
            if not data:
                # Create sample data for demonstration
                data = [
                    {"timestamp": datetime.now().isoformat(), "command": "scan network 127.0.0.1", "result": "open ports 22,80", "risk_level": "Low"},
                    {"timestamp": datetime.now().isoformat(), "command": "detect threats", "result": "multiple failed logins", "risk_level": "High"},
                ]
            
            if PANDAS_AVAILABLE:
                df = pd.DataFrame(data)
                df.to_csv(output_path, index=False)
            else:
                with open(output_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=["timestamp","command","result","risk_level"])
                    writer.writeheader()
                    for row in data:
                        writer.writerow(row)
            
            return {"status": "success", "path": output_path, "count": len(data), "pandas_used": PANDAS_AVAILABLE}
        except Exception as e:
            return ErrorHandler.handle_exception(e, "DataPipeline.to_csv")
    
    def clean_data(self) -> Dict:
        """Data cleaning per data science role"""
        try:
            data = self.to_structured_json()
            # Simple cleaning: remove empty, deduplicate commands
            cleaned = []
            seen = set()
            for d in data:
                cmd = d.get("command","").strip()
                if not cmd or cmd in seen:
                    continue
                seen.add(cmd)
                cleaned.append(d)
            return {"status": "success", "original": len(data), "cleaned": len(cleaned), "data": cleaned[:10]}
        except Exception as e:
            return ErrorHandler.handle_exception(e, "DataPipeline.clean_data")

data_pipeline = DataPipeline()
