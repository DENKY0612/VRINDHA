"""
Anomaly Detection (Core AI) - Phase 3 from AI ML pdf
Build model using Scikit-learn
Examples: Detect unusual traffic, abnormal commands
Models: Isolation Forest, K-Means clustering
Output: {event, anomaly_score, status: suspicious}
Also: Data science role - unusual login detection, suspicious traffic, attack pattern recognition
"""
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.error_handler import ErrorHandler
from datetime import datetime
from typing import Dict, List
import random

# Try sklearn
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import KMeans
    import numpy as np
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

class AnomalyDetector:
    def __init__(self):
        self.name = "AnomalyDetector"
        # Dummy training data for MVP
        self.model_trained = False
        self.isolation_forest = None
        if SKLEARN_AVAILABLE:
            try:
                # Train on some dummy normal behavior
                X = np.array([[1, 2], [2, 3], [3, 3], [2, 2], [1, 1], [2, 1]] * 10)
                self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
                self.isolation_forest.fit(X)
                self.model_trained = True
            except Exception as e:
                print(f"[AnomalyDetector] Model train failed: {e}")
    
    def extract_features(self, event: Dict) -> List[float]:
        """Extract simple features from event for ML model"""
        # For MVP: command length, risk level encoded, time etc
        cmd = event.get("command", "") if isinstance(event, dict) else str(event)
        risk_map = {"Low": 1, "Medium": 2, "High": 3}
        risk_val = risk_map.get(event.get("risk_level","Low") if isinstance(event, dict) else "Low", 1)
        return [len(cmd) % 10, risk_val]
    
    def detect(self, event: Dict) -> Dict:
        try:
            if isinstance(event, str):
                event = {"command": event, "raw": event}
            
            command = event.get("command","") if isinstance(event, dict) else str(event)
            
            # Rule-based fallback
            suspicious_keywords = ["attack", "breach", "malware", "unauthorized", "rootkit", "injection"]
            is_suspicious_by_rule = any(kw in command.lower() for kw in suspicious_keywords)
            
            anomaly_score = 0.9 if is_suspicious_by_rule else random.uniform(0.1, 0.4)
            status = "suspicious" if anomaly_score > 0.7 else "normal"
            
            # ML model if available
            ml_score = None
            if SKLEARN_AVAILABLE and self.model_trained:
                try:
                    features = self.extract_features(event)
                    # IsolationForest: -1 for anomaly, 1 for normal
                    X_test = np.array([features])
                    pred = self.isolation_forest.decision_function(X_test)
                    # Convert to 0-1 anomaly score (lower decision = more anomalous)
                    ml_score = float(1 - (pred[0] + 0.5))  # normalize roughly
                    # Combine rule and ML
                    anomaly_score = (anomaly_score + ml_score) / 2
                    status = "suspicious" if anomaly_score > 0.6 else "normal"
                except Exception as e:
                    ml_score = None
            
            return {
                "event": command[:100],
                "anomaly_score": round(anomaly_score, 3),
                "ml_score": ml_score,
                "status": status,
                "model_used": "IsolationForest" if SKLEARN_AVAILABLE else "Rule-based",
                "timestamp": datetime.now().isoformat(),
                "details": {
                    "rule_triggered": is_suspicious_by_rule,
                    "features": self.extract_features(event)
                },
                "confidence": "high" if anomaly_score > 0.8 else "medium"
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "AnomalyDetector.detect")
    
    def detect_batch(self, events: List[Dict]) -> Dict:
        try:
            results = [self.detect(ev) for ev in events]
            suspicious = [r for r in results if r.get("status")=="suspicious"]
            return {
                "total": len(results),
                "suspicious_count": len(suspicious),
                "results": results,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "AnomalyDetector.detect_batch")

anomaly_detector = AnomalyDetector()
