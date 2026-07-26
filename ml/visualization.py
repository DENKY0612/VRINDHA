"""
Dashboard Intelligence - Phase 6 and Data Science #5 Data Visualization
Create graphs: Attack trends, Risk over time, Alerts
This is what users will SEE - very important for startup per AI ML pdf
Using Charts, Graphs, Trends to show Attack frequency, Most targeted ports, Risk trends
"""
from datetime import datetime, timedelta
from typing import Dict, List
import random
from core.error_handler import ErrorHandler

class VisualizationEngine:
    def __init__(self):
        self.name = "VisualizationEngine"
    
    def generate_attack_trends(self, days: int = 7) -> Dict:
        try:
            # Generate simulated trend data for dashboard
            trends = []
            base_date = datetime.now()
            for i in range(days):
                date = (base_date - timedelta(days=i)).strftime("%Y-%m-%d")
                trends.append({
                    "date": date,
                    "attacks": random.randint(0, 10),
                    "blocked": random.randint(0, 8),
                    "risk_avg": random.randint(20, 90)
                })
            trends.reverse()
            
            return {
                "type": "attack_trends",
                "data": trends,
                "chart_type": "line",
                "title": "Attack Trends Over Time",
                "x_axis": "date",
                "y_axis": "count / risk"
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "VisualizationEngine.generate_attack_trends")
    
    def generate_port_stats(self) -> Dict:
        try:
            ports = [
                {"port": 22, "service": "ssh", "hits": random.randint(10, 100)},
                {"port": 80, "service": "http", "hits": random.randint(20, 150)},
                {"port": 443, "service": "https", "hits": random.randint(15, 120)},
                {"port": 445, "service": "smb", "hits": random.randint(0, 50)},
                {"port": 3306, "service": "mysql", "hits": random.randint(0, 30)},
            ]
            return {
                "type": "port_frequency",
                "data": ports,
                "chart_type": "bar",
                "title": "Most Targeted Ports"
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "VisualizationEngine.generate_port_stats")
    
    def generate_risk_over_time(self) -> Dict:
        try:
            data = []
            for i in range(24):
                data.append({"hour": f"{i}:00", "risk": random.randint(10, 95)})
            return {
                "type": "risk_over_time",
                "data": data,
                "chart_type": "area",
                "title": "Risk Score Over Time (24h)"
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "VisualizationEngine.generate_risk_over_time")
    
    def get_all_dashboard_data(self) -> Dict:
        try:
            return {
                "attack_trends": self.generate_attack_trends(),
                "port_stats": self.generate_port_stats(),
                "risk_trends": self.generate_risk_over_time(),
                "alerts": [{"time": datetime.now().isoformat(), "message": "Sample alert - High risk IP blocked", "level": "High"}],
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "VisualizationEngine.get_all_dashboard_data")

visualization_engine = VisualizationEngine()
