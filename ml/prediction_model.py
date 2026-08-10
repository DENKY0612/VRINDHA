"""
Prediction Model (Advanced) - Phase 5 per AI ML pdf
Predict future threats using historical logs, behavior trends
Tools: TensorFlow or PyTorch (placeholder for MVP - rule based + optional sklearn)
Instead of "Attack detected" -> "Attack likely to happen"
"""
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from core.error_handler import ErrorHandler
from database.db import get_logs
import re

try:
    import sklearn
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

class PredictionModel:
    def __init__(self):
        self.name = "ThreatPrediction"

    def _normalize_risk(self, risk_level: Optional[str]) -> float:
        if not risk_level:
            return 0.2
        r = risk_level.lower()
        if "critical" in r:
            return 1.0
        if "high" in r:
            return 0.75
        if "medium" in r:
            return 0.5
        if "low" in r:
            return 0.25
        return 0.3

    def _extract_metrics(self, logs: List[Dict]) -> Dict:
        metrics = {
            "failed_logins": 0,
            "scan_events": 0,
            "high_risk_events": 0,
            "critical_risk_events": 0,
            "recent_ips": {},
            "total": len(logs),
            "risk_score_avg": 0.0,
        }
        total_risk = 0.0
        for log in logs:
            cmd = str(log.get("command", "")) + " " + str(log.get("result", ""))
            text = cmd.lower()
            if "failed" in text or "login" in text and "fail" in text:
                metrics["failed_logins"] += 1
            if any(k in text for k in ["scan", "nmap", "recon", "port", "attack", "breach", "malware", "rootkit"]):
                metrics["scan_events"] += 1
            risk = self._normalize_risk(log.get("risk_level"))
            total_risk += risk
            if risk >= 0.75:
                metrics["high_risk_events"] += 1
            if risk >= 0.95:
                metrics["critical_risk_events"] += 1
            # Extract IPs for trending insights
            ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
            for ip in ips:
                metrics["recent_ips"][ip] = metrics["recent_ips"].get(ip, 0) + 1
        metrics["risk_score_avg"] = (total_risk / len(logs)) if logs else 0.0
        return metrics

    def _make_prediction(self, metrics: Dict) -> List[Dict]:
        predictions = []
        if metrics["critical_risk_events"] >= 1:
            predictions.append({
                "threat": "Critical intrusion likely",
                "probability": min(0.95, 0.5 + 0.1 * metrics["critical_risk_events"]),
                "reason": "Critical/high-risk events detected in recent logs",
                "timeframe": "next 12h"
            })
        if metrics["failed_logins"] >= 2:
            predictions.append({
                "threat": "Brute force attack likely",
                "probability": min(0.9, 0.45 + 0.1 * metrics["failed_logins"]),
                "reason": "Multiple failed login patterns in history",
                "timeframe": "next 24h"
            })
        if metrics["scan_events"] >= 3:
            predictions.append({
                "threat": "Reconnaissance activity likely to continue",
                "probability": min(0.85, 0.4 + 0.08 * metrics["scan_events"]),
                "reason": "Multiple scan or reconnaissance log entries",
                "timeframe": "next 24h"
            })
        if not predictions:
            predictions.append({
                "threat": "No imminent threat predicted",
                "probability": 0.2,
                "reason": "Historical logs do not exhibit strong risk patterns",
                "timeframe": "next 24h"
            })
        return predictions

    def _build_insights(self, metrics: Dict) -> Dict:
        top_ips = sorted(metrics["recent_ips"].items(), key=lambda x: x[1], reverse=True)[:3]
        return {
            "failed_logins": metrics["failed_logins"],
            "scan_events": metrics["scan_events"],
            "high_risk_events": metrics["high_risk_events"],
            "critical_risk_events": metrics["critical_risk_events"],
            "risk_score_avg": round(metrics["risk_score_avg"] * 100, 1),
            "top_source_ips": [ip for ip, _ in top_ips],
        }

    def predict(self, historical_logs: List[Dict] = None) -> Dict:
        try:
            if historical_logs is None:
                historical_logs = get_logs(100)
            predictions = []
            metrics = self._extract_metrics(historical_logs)
            predictions = self._make_prediction(metrics)

            return {
                "status": "success",
                "model": "Heuristic threat prediction with log-driven signals",
                "predictions": predictions,
                "historical_count": len(historical_logs),
                "insights": self._build_insights(metrics),
                "timestamp": datetime.now().isoformat(),
                "note": "Phase 5 threat prediction; future improvement: TensorFlow/PyTorch time-series model on historical events"
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "PredictionModel.predict")

    def train_placeholder(self):
        return {"status": "placeholder", "message": "Training with TensorFlow/PyTorch to be implemented after data collection phase"}

prediction_model = PredictionModel()
