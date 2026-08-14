"""Dependency-free metric registry with Prometheus text export."""
from __future__ import annotations

from collections import defaultdict
from threading import Lock
from typing import Dict


class Metrics:
    NAMES = {
        "indicators_total", "indicators_active", "indicators_expired", "ioc_matches_total",
        "correlations_total", "high_risk_iocs", "critical_iocs", "feed_success_total",
        "feed_failure_total", "enrichment_seconds_total", "enrichment_total",
        "soc_messages_received", "soc_messages_sent", "queue_depth", "external_api_errors",
    }

    def __init__(self):
        self._values: Dict[str, float] = defaultdict(float)
        self._lock = Lock()

    def inc(self, name: str, amount: float = 1) -> None:
        if name not in self.NAMES:
            raise KeyError(name)
        with self._lock:
            self._values[name] += amount

    def set(self, name: str, value: float) -> None:
        if name not in self.NAMES:
            raise KeyError(name)
        with self._lock:
            self._values[name] = value

    def snapshot(self) -> Dict[str, float]:
        with self._lock:
            values = {name: self._values.get(name, 0.0) for name in sorted(self.NAMES)}
        success, failure = values["feed_success_total"], values["feed_failure_total"]
        total = success + failure
        values["feed_success_rate"] = success / total if total else 0
        values["feed_failure_rate"] = failure / total if total else 0
        values["average_enrichment_time"] = values["enrichment_seconds_total"] / values["enrichment_total"] if values["enrichment_total"] else 0
        return values

    def prometheus(self) -> str:
        return "\n".join(f"vrindha_ti_{name} {value}" for name, value in self.snapshot().items()) + "\n"


metrics = Metrics()
