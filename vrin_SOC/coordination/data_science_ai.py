"""Data Science AI — the analytical brain of Vrindha AI.

Pipeline (spec §5):

    DATA INGESTION → VALIDATION → CLEANING → INTEGRATION
    → FEATURE ENGINEERING (time windows, no leakage)
    → ANOMALY DETECTION (z-score + rolling baseline, Isolation Forest optional)
    → RISK ENGINE (documented, configurable, explainable factors)
    → MODEL EVALUATION / METRICS
    → FEEDBACK LEARNING (only validated outcomes — contamination guarded)

The agent NEVER executes defensive actions; it converts raw security data
into reliable analytical intelligence and publishes results on the event bus.

No fabrication: every model result carries model + model_version, and fallback
mode is explicitly flagged.
"""
from __future__ import annotations

import hashlib
import math
import statistics
import threading
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from .event_bus import EventBus
from .observability import BaseAgent
from .schemas import (
    AnomalyResult,
    DataQualityReport,
    EventMode,
    ModelMetadata,
    RiskFactor,
    RiskResult,
    SecurityEvent,
    utc_now_iso,
)

try:
    from sklearn.ensemble import IsolationForest

    _SKLEARN = True
except ImportError:  # pragma: no cover
    _SKLEARN = False


# ----------------------------------------------------------------------
# Configuration (documented weights — nothing arbitrary is hidden)
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class RiskConfig:
    """Risk engine configuration.

    Weights are deliberately simple and documented (spec §13: "Do NOT invent
    arbitrary weights without documenting them"). They are normalized before
    use, so relative magnitudes matter, not absolute values.
    """

    w_anomaly: float = 0.35          # anomaly score from Data Science layer
    w_threat_intel: float = 0.25     # confirmed malicious IOC via TI
    w_event_severity: float = 0.20   # raw event severity (low/medium/high/critical)
    w_auth_anomaly: float = 0.15     # authentication anomalies (failed logins etc.)
    w_network_anomaly: float = 0.05  # unusual network patterns (ports/volumes)

    severity_thresholds: Tuple[Tuple[float, str], ...] = (
        (0.80, "critical"),
        (0.60, "high"),
        (0.30, "medium"),
    )
    #: Minimum number of baseline samples before the rolling baseline is used.
    baseline_min_samples: int = 5
    #: Rolling baseline window for z-score features.
    baseline_window: int = 200


_SEVERITY_VALUE = {"low": 0.1, "medium": 0.45, "high": 0.75, "critical": 1.0}

#: Feature names, in fixed order (stable feature vector for models).
FEATURE_NAMES = (
    "failed_login_count",
    "successful_login_count",
    "unique_source_ips",
    "connection_count",
    "unusual_port_count",
    "bytes_sent_kb",
    "bytes_received_kb",
    "process_count",
    "new_process_count",
    "cpu_usage",
    "memory_usage",
    "disk_usage",
    "authentication_frequency",
    "hour_of_day",
    "is_weekend",
)

UNUSUAL_PORTS = {4444, 6666, 1337, 31337, 31338}


class _FeatureWindow:
    """Bounded ring of (timestamp, features) per entity for windowed features."""

    def __init__(self, maxlen: int = 20000) -> None:
        self._rows: "deque[Tuple[datetime, Dict[str, float]]]" = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def add(self, ts: datetime, features: Dict[str, float]) -> None:
        with self._lock:
            self._rows.append((ts, features))

    def window(self, ts: datetime, minutes: int) -> List[Dict[str, float]]:
        """Rows strictly *before* ``ts`` inside the window (no data leakage)."""
        cutoff = ts - timedelta(minutes=minutes)
        with self._lock:
            return [f for t, f in self._rows if cutoff <= t < ts]

    def __len__(self) -> int:
        with self._lock:
            return len(self._rows)


class _ModelRegistry:
    """Versioned model metadata — production models are never silently replaced."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._models: Dict[Tuple[str, str], ModelMetadata] = {}
        self._production: Dict[str, str] = {}

    def register(self, meta: ModelMetadata) -> ModelMetadata:
        with self._lock:
            existing = self._models.get((meta.model_name, meta.model_version))
            if existing is not None:
                # Re-registration of the same version must not silently change
                # the production artifact: reject conflicting content.
                if existing.model_dump() != meta.model_dump():
                    raise ValueError(
                        f"Model {meta.model_name}@{meta.model_version} already registered with different metadata"
                    )
            else:
                self._models[(meta.model_name, meta.model_version)] = meta
                if meta.status == "production" and meta.model_name not in self._production:
                    # Seeded production model becomes the active production version.
                    self._production[meta.model_name] = meta.model_version
            return meta

    def promote(self, model_name: str, model_version: str) -> ModelMetadata:
        with self._lock:
            meta = self._models.get((model_name, model_version))
            if meta is None:
                raise KeyError(f"model {model_name}@{model_version} not registered")
            for key, registered in self._models.items():
                if key[0] == model_name and key[1] != model_version and registered.status == "production":
                    registered.status = "retired"
            meta.status = "production"
            self._production[model_name] = model_version
            return meta

    def production(self, model_name: str) -> Optional[ModelMetadata]:
        with self._lock:
            version = self._production.get(model_name)
            return self._models.get((model_name, version)) if version else None

    def all(self) -> List[ModelMetadata]:
        with self._lock:
            return [m.model_copy(deep=True) for m in self._models.values()]


class DataScienceAI(BaseAgent):
    name = "DataScienceAI"
    kind = "ml"
    capabilities = [
        "data_ingestion", "validation", "cleaning", "feature_engineering",
        "anomaly_detection", "risk_modeling", "model_evaluation", "explainability",
        "feedback_learning",
    ]
    agent_version = "1.0"

    def __init__(self, bus: Optional[EventBus] = None, config: Optional[RiskConfig] = None) -> None:
        super().__init__(bus)
        self.config = config or RiskConfig()
        self.registry = _ModelRegistry()
        self._seen_ids: "deque[str]" = deque(maxlen=50000)
        self._seen_hashes: "deque[str]" = deque(maxlen=50000)
        self._windows: Dict[str, _FeatureWindow] = defaultdict(_FeatureWindow)
        self._rejected: "deque[Dict[str, Any]]" = deque(maxlen=500)
        self._label_store: Dict[str, Dict[str, Any]] = {}  # event_id → validated label
        self._anomaly_threshold = 0.6
        self._seed_registry()
        # Subscribe to analytical interest: consume enriched events.
        self.bus.subscribe("security_event", self.on_enriched_event, subscriber=self.name)
        self.bus.subscribe("telemetry", self.on_enriched_event, subscriber=self.name)

    # ------------------------------------------------------------------
    # Model registry bootstrap (documented default models)
    # ------------------------------------------------------------------
    def _seed_registry(self) -> None:
        anomaly_meta = ModelMetadata(
            model_name="anomaly",
            model_version="v1",
            algorithm="z-score + rolling baseline (+ IsolationForest when sklearn present)",
            features=list(FEATURE_NAMES),
            hyperparameters={"baseline_window": self.config.baseline_window,
                             "threshold": self._anomaly_threshold},
            status="production",
            training_date=utc_now_iso(),
            training_dataset="rolling operational baseline (no external labels required)",
        )
        risk_meta = ModelMetadata(
            model_name="risk",
            model_version="v1",
            algorithm="documented weighted linear combination of explainable factors",
            hyperparameters={k: getattr(self.config, k) for k in
                             ("w_anomaly", "w_threat_intel", "w_event_severity",
                              "w_auth_anomaly", "w_network_anomaly")},
            status="production",
            training_date=utc_now_iso(),
            training_dataset="rule documentation (deterministic, no learned weights)",
        )
        self.registry.register(anomaly_meta)
        self.registry.register(risk_meta)

    # ------------------------------------------------------------------
    # 1) Ingestion + validation + data quality
    # ------------------------------------------------------------------
    def ingest(self, payload: Dict[str, Any]) -> Tuple[Optional[SecurityEvent], DataQualityReport]:
        """Validate raw input → SecurityEvent or a *recorded* rejection."""
        report = DataQualityReport(accepted=False)
        checked: List[str] = []

        def fail(reason: str) -> Tuple[Optional[SecurityEvent], DataQualityReport]:
            report.accepted = False
            report.issues.append(reason)
            report.rejected_records.append({"payload_excerpt": str(payload)[:500], "reason": reason,
                                            "at": utc_now_iso()})
            self._rejected.append({"payload_excerpt": str(payload)[:500], "reason": reason, "at": utc_now_iso()})
            self.metrics.record_error(f"ingest rejected: {reason}")
            return None, report

        if not isinstance(payload, dict):
            return fail("payload must be an object")
        checked.append("type_check")

        event_type = payload.get("event_type")
        if not event_type or not isinstance(event_type, str):
            return fail("missing or invalid event_type")
        checked.append("event_type")

        timestamp = payload.get("timestamp")
        if timestamp:
            try:
                parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            except ValueError:
                return fail(f"invalid timestamp: {str(timestamp)[:64]}")
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            if parsed > datetime.now(timezone.utc) + timedelta(minutes=5):
                return fail("timestamp more than 5 minutes in the future (clock skew or bad data)")
            payload["timestamp"] = parsed.isoformat()
        checked.append("timestamp")

        severity = (payload.get("severity") or "low").lower()
        if severity not in _SEVERITY_VALUE:
            return fail(f"invalid severity: {severity!r}")
        payload["severity"] = severity
        checked.append("severity")

        entity_raw = payload.get("entity") or {}
        if isinstance(entity_raw, dict) and entity_raw.get("ip"):
            import ipaddress

            try:
                ipaddress.ip_address(str(entity_raw["ip"]))
            except ValueError:
                return fail(f"malformed IP in entity: {entity_raw.get('ip')!r}")
        checked.append("entity")

        try:
            event = SecurityEvent.model_validate(payload)
        except Exception as exc:  # pydantic ValidationError and friends
            first_error = str(exc).split("\n")[0][:256]
            return fail(f"schema validation failed: {first_error}")
        checked.append("schema")

        # Deduplication: explicit event_id or stable content hash.
        digest = hashlib.sha256(
            f"{event.event_type}|{event.entity.primary() or ''}|{event.timestamp}|{_flatten(event.data)}".encode()
        ).hexdigest()
        if event.event_id in self._seen_ids or digest in self._seen_hashes:
            report.duplicates += 1
            return fail(f"duplicate event (id={event.event_id}, hash={digest[:12]})")
        self._seen_ids.append(event.event_id)
        self._seen_hashes.append(digest)
        checked.append("deduplication")

        report.accepted = True
        report.checked = len(checked)
        event.status = _advance(event.status, "ingested")
        self.metrics.record(True, 0.0)
        return event, report

    # ------------------------------------------------------------------
    # 2) Feature engineering (windowed, leakage-free)
    # ------------------------------------------------------------------
    def extract_features(self, event: SecurityEvent) -> Dict[str, float]:
        data = event.data or {}
        ts = _parse_ts(event.timestamp)

        auth = data.get("authentication") if isinstance(data.get("authentication"), dict) else {}
        network = data.get("network") if isinstance(data.get("network"), dict) else {}
        cpu = data.get("cpu") if isinstance(data.get("cpu"), dict) else {}
        mem = data.get("memory") if isinstance(data.get("memory"), dict) else {}
        disk = data.get("disk") if isinstance(data.get("disk"), dict) else {}
        proc = data.get("processes") if isinstance(data.get("processes"), dict) else {}

        failed = _num(auth.get("failed_login_count"))
        successful = _num(auth.get("successful_login_count"))
        connections = _num(network.get("connection_count"))
        ports = network.get("ports") if isinstance(network.get("ports"), list) else []
        unusual_ports = sum(1 for p in ports if _num(p) in UNUSUAL_PORTS)
        source_ips = network.get("source_ips") if isinstance(network.get("source_ips"), list) else []
        if failed and not source_ips and event.entity and event.entity.ip:
            source_ips = [event.entity.ip]

        window_1h = self._windows_for(event)
        recent = window_1h.window(ts, 60)
        recent_failed = sum(_num(r.get("failed_login_count", 0)) for r in recent[-10:])
        auth_frequency = len(recent) / 60.0  # events per minute over last hour

        features = {
            "failed_login_count": failed + recent_failed,
            "successful_login_count": successful,
            "unique_source_ips": len({str(s) for s in source_ips}) or (1 if failed else 0),
            "connection_count": connections,
            "unusual_port_count": unusual_ports,
            "bytes_sent_kb": _num(network.get("bytes_sent_kb")),
            "bytes_received_kb": _num(network.get("bytes_received_kb")),
            "process_count": _num(proc.get("process_count")),
            "new_process_count": _num(proc.get("new_process_count")),
            "cpu_usage": _num(cpu.get("cpu_usage_percent")),
            "memory_usage": _num(mem.get("memory_usage_percent")),
            "disk_usage": _num(disk.get("disk_usage_percent")),
            "authentication_frequency": round(auth_frequency, 4),
            "hour_of_day": float(ts.hour),
            "is_weekend": 1.0 if ts.weekday() >= 5 else 0.0,
        }
        return features

    def _windows_for(self, event: SecurityEvent) -> _FeatureWindow:
        key = str((event.entity and (event.entity.host or event.entity.ip)) or "global")
        return self._windows[key]

    def build_features(self, event: SecurityEvent) -> Dict[str, Any]:
        """Extract, store, and return the feature vector for one event."""
        features = self.extract_features(event)
        window = self._windows_for(event)
        window.add(_parse_ts(event.timestamp), features)
        vector = [features[name] for name in FEATURE_NAMES]
        return {
            "features": features,
            "vector": vector,
            "feature_names": list(FEATURE_NAMES),
            "windows": {
                "last_1_minute": len(window.window(_parse_ts(event.timestamp), 1)),
                "last_5_minutes": len(window.window(_parse_ts(event.timestamp), 5)),
                "last_15_minutes": len(window.window(_parse_ts(event.timestamp), 15)),
                "last_1_hour": len(window.window(_parse_ts(event.timestamp), 60)),
                "last_24_hours": len(window.window(_parse_ts(event.timestamp), 1440)),
            },
        }

    # ------------------------------------------------------------------
    # 3) Anomaly detection (interpretable first; clearly labeled fallback)
    # ------------------------------------------------------------------
    def detect_anomaly(self, event: SecurityEvent, features: Optional[Dict[str, float]] = None) -> AnomalyResult:
        if features is None:
            features = self.extract_features(event)
        vector = [features[n] for n in FEATURE_NAMES]
        window = self._windows_for(event)
        baseline_rows = window.window(_parse_ts(event.timestamp), 60)
        explanation: List[str] = []

        # 3a. Rolling baseline z-score over the operationally relevant features.
        z_scores: Dict[str, float] = {}
        if len(baseline_rows) >= self.config.baseline_min_samples:
            for name in FEATURE_NAMES:
                values = [r.get(name, 0.0) for r in baseline_rows]
                mean = statistics.fmean(values)
                stdev = statistics.pstdev(values)
                if stdev > 1e-9:
                    z_scores[name] = (features[name] - mean) / stdev
            top = sorted(((abs(z), name) for name, z in z_scores.items()), reverse=True)[:5]
            for abs_z, name in top:
                if abs_z >= 3.0:
                    explanation.append(f"{name}={features[name]:.2f} deviates {abs_z:.1f}σ from rolling baseline")
            z_anomaly = min(1.0, max((abs(z) for z in z_scores.values()), default=0.0) / 5.0)
        else:
            z_anomaly = 0.0
            explanation.append("baseline too small for z-score; using rule signals only")

        # 3b. Deterministic rule signals (interpretable, no model needed).
        rule_signals = 0.0
        if features["failed_login_count"] >= 5:
            rule_signals += 0.4
            explanation.append(f"{int(features['failed_login_count'])} failed logins in window")
        if features["unusual_port_count"] >= 1:
            rule_signals += 0.3
            explanation.append("traffic on unusual port(s)")
        if features["authentication_frequency"] >= 20:
            rule_signals += 0.2
            explanation.append("abnormal authentication frequency")
        if _SEVERITY_VALUE.get(event.severity, 0.0) >= 0.75:
            rule_signals += 0.2
            explanation.append(f"event severity is {event.severity}")

        # 3c. Isolation Forest when a real baseline is available.
        ml_score: Optional[float] = None
        model_used = "zscore_baseline+rules"
        if _SKLEARN and len(baseline_rows) >= max(20, self.config.baseline_min_samples):
            try:
                X = [[r.get(n, 0.0) for n in FEATURE_NAMES] for r in baseline_rows[-200:]]
                forest = IsolationForest(contamination="auto", random_state=42, n_estimators=50)
                forest.fit(X)
                decision = float(forest.decision_function([vector])[0])
                # decision_function: negative ≈ anomaly. Normalize to [0, 1].
                ml_score = min(1.0, max(0.0, 0.5 - decision))
                model_used = "isolation_forest+zscore+rules"
            except Exception:  # noqa: BLE001 — model must never take the pipeline down
                ml_score = None

        # 3d. Combine: rules are always present; ML/ z-score add evidence.
        score = rule_signals
        if z_anomaly:
            score = min(1.0, 0.6 * z_anomaly + 0.4 * rule_signals) if z_anomaly > rule_signals else max(score, z_anomaly * 0.6 + rule_signals * 0.4)
        if ml_score is not None:
            score = min(1.0, 0.5 * score + 0.5 * ml_score)
        score = min(1.0, max(0.0, score))

        confidence = 0.5
        if ml_score is not None:
            confidence = 0.8
        elif len(baseline_rows) >= self.config.baseline_min_samples:
            confidence = 0.7
        if not explanation:
            explanation.append("no strong signals; behavior within learned/rule expectations")

        return AnomalyResult(
            anomaly_score=round(score, 4),
            is_anomaly=score >= self._anomaly_threshold,
            confidence=round(confidence, 2),
            model=model_used,
            model_version="v1",
            fallback_mode=ml_score is None and len(baseline_rows) < self.config.baseline_min_samples,
            explanation=explanation,
        )

    # ------------------------------------------------------------------
    # 4) Risk engine (explainable, configurable)
    # ------------------------------------------------------------------
    def score_risk(self, event: SecurityEvent) -> RiskResult:
        anomaly = event.analysis.get("anomaly") or self.detect_anomaly(event).model_dump()
        ti = event.threat_intelligence or {}

        weights = {
            "anomaly": self.config.w_anomaly,
            "threat_intel": self.config.w_threat_intel,
            "event_severity": self.config.w_event_severity,
            "auth_anomaly": self.config.w_auth_anomaly,
            "network_anomaly": self.config.w_network_anomaly,
        }
        total_w = sum(weights.values())
        weights = {k: v / total_w for k, v in weights.items()}

        contributions: Dict[str, float] = {
            "anomaly": float(anomaly.get("anomaly_score", 0.0)),
            "threat_intel": 1.0 if ti.get("malicious_found") else (0.3 if ti.get("mode") == EventMode.UNAVAILABLE.value else 0.0),
            "event_severity": _SEVERITY_VALUE.get(event.severity, 0.0),
            "auth_anomaly": min(1.0, float((event.data or {}).get("authentication", {}).get("failed_login_count", 0) if isinstance((event.data or {}).get("authentication"), dict) else 0) / 10.0),
            "network_anomaly": min(1.0, float((event.data or {}).get("network", {}).get("unusual_port_count", 0) if isinstance((event.data or {}).get("network"), dict) else 0) / 2.0),
        }
        if ti.get("malicious_found"):
            contributions["threat_intel"] = 1.0

        factors: List[RiskFactor] = []
        score = 0.0
        label_map = {
            "anomaly": "anomaly score",
            "threat_intel": "threat intelligence confidence",
            "event_severity": "event severity",
            "auth_anomaly": "authentication anomalies",
            "network_anomaly": "network anomalies",
        }
        for key, value in contributions.items():
            contribution = round(weights[key] * value, 4)
            score += contribution
            if value > 0:
                factors.append(RiskFactor(factor=label_map[key], contribution=contribution))
        factors.sort(key=lambda f: f.contribution, reverse=True)
        score = min(1.0, max(0.0, score))

        severity = "low"
        for threshold, label in self.config.severity_thresholds:
            if score >= threshold:
                severity = label
                break

        explainability = [
            f"{f.factor}: contribution {f.contribution:.3f} (weight {weights[_reverse(label_map, f.factor)]:.3f})"
            for f in factors
        ]
        explainability.append("score = Σ (weight × signal), weights documented in RiskConfig")

        return RiskResult(
            risk_score=round(score, 4),
            severity=severity,
            confidence=round(min(1.0, float(anomaly.get("confidence", 0.5)) + (0.2 if ti.get("malicious_found") else 0.0)), 2),
            factors=factors,
            model="risk-engine",
            model_version="v1",
            explainability=explainability,
        )

    # ------------------------------------------------------------------
    # 5) Full analysis of one event (called by the Commander pipeline)
    # ------------------------------------------------------------------
    def analyze(self, event: SecurityEvent) -> Dict[str, Any]:
        """Feature engineering + anomaly + risk, attached to the event."""
        return self.run_guarded(self._analyze, event)

    def _analyze(self, event: SecurityEvent) -> Dict[str, Any]:
        # Compute features BEFORE storing them in the window so the current
        # event cannot leak into its own baseline (no data leakage).
        pre_features = self.extract_features(event)
        features = self.build_features(event)
        anomaly = self.detect_anomaly(event, features=pre_features)
        event.analysis = {
            **event.analysis,
            "anomaly": anomaly.model_dump(),
            "features": features["features"],
            "feature_windows": features["windows"],
            "mode": EventMode.REAL.value if event.provenance.mode == EventMode.REAL else event.provenance.mode.value,
        }
        risk = self.score_risk(event)
        event.risk = {**event.risk, **risk.model_dump()}
        event.severity = risk.severity
        event.status = _advance(event.status, "risk_assessed")
        return {
            "status": "success",
            "event_id": event.event_id,
            "anomaly": event.analysis["anomaly"],
            "risk": event.risk,
            "features": features["features"],
            "model_versions": {"anomaly": anomaly.model_version, "risk": risk.model_version},
        }

    def on_enriched_event(self, event: SecurityEvent) -> None:
        """Bus subscription: automatically analyze security/telemetry events."""
        if event.source_agent == self.name:
            return
        if event.event_type not in {"security_event", "telemetry"}:
            return
        if "anomaly" in (event.analysis or {}):
            return
        self.run_guarded(self._analyze, event)

    # ------------------------------------------------------------------
    # 6) Feedback loop (validated outcomes only — contamination guarded)
    # ------------------------------------------------------------------
    def record_outcome(self, event_id: str, label: str, validated_by: str, validated: bool = True,
                       detail: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Store a labeled outcome for evaluation.

        Only *validated* outcomes may enter the learning store. Predictions
        without a human/analyst-validated conclusion are rejected, which
        prevents feedback contamination (spec §16).
        """
        if label not in {"confirmed_attack", "false_positive", "unknown"}:
            return {"status": "error", "reason": "label must be confirmed_attack | false_positive | unknown"}
        if not validated:
            return {"status": "rejected",
                    "reason": "unvalidated outcome; only validated historical outcomes may train/evaluate models"}
        if not validated_by:
            return {"status": "rejected", "reason": "validated_by is required (analyst/human provenance)"}
        self._label_store[event_id] = {
            "event_id": event_id,
            "label": label,
            "validated_by": validated_by,
            "detail": detail or {},
            "recorded_at": utc_now_iso(),
        }
        return {"status": "accepted", "event_id": event_id, "label": label}

    def validated_samples(self) -> List[Dict[str, Any]]:
        return list(self._label_store.values())

    # ------------------------------------------------------------------
    # 7) Model evaluation (honest metrics; no accuracy-only reporting)
    # ------------------------------------------------------------------
    def evaluate(self, predictions: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Evaluate predictions against validated labels.

        ``predictions`` items: {"event_id", "anomaly_score" or "risk_score",
        "is_anomaly" (bool)} — when omitted, scores already stored on the bus
        history are used for events that have validated labels.
        """
        samples = self.validated_samples()
        if predictions is None:
            scored: Dict[str, float] = {}
            for event in self.bus._history:  # noqa: SLF001 — same package, deliberate
                if "anomaly" in (event.analysis or {}):
                    scored[event.event_id] = float(event.analysis["anomaly"]["anomaly_score"])
            items = [
                {"event_id": s["event_id"], "score": scored.get(s["event_id"]), "label": s["label"]}
                for s in samples
            ]
        else:
            labels = {s["event_id"]: s["label"] for s in samples}
            items = [
                {
                    "event_id": p.get("event_id"),
                    "score": p.get("anomaly_score", p.get("risk_score")),
                    "label": p.get("label", labels.get(p.get("event_id"))),
                }
                for p in predictions
            ]

        labeled = [i for i in items if i.get("score") is not None and i.get("label") in {"confirmed_attack", "false_positive"}]
        if not labeled:
            return {
                "status": "insufficient_data",
                "labeled_samples": len(labeled),
                "total_validated_outcomes": len(samples),
                "note": "Need validated outcomes (confirmed_attack / false_positive) to compute metrics. "
                        "Metrics are never fabricated.",
                "metrics": {},
            }

        scores = [i["score"] for i in labeled]
        positives = [i["label"] == "confirmed_attack" for i in labeled]
        pos_scores = [s for s, p in zip(scores, positives) if p]
        neg_scores = [s for s, p in zip(scores, positives) if not p]
        metrics: Dict[str, Any] = {
            "labeled_samples": len(labeled),
            "positive_count": len(pos_scores),
            "negative_count": len(neg_scores),
            "score_range": [round(min(scores), 4), round(max(scores), 4)],
            "mean_score_positives": round(statistics.fmean(pos_scores), 4) if pos_scores else None,
            "mean_score_negatives": round(statistics.fmean(neg_scores), 4) if neg_scores else None,
            "separation": None,
        }
        if pos_scores and neg_scores:
            metrics["separation"] = round(metrics["mean_score_positives"] - metrics["mean_score_negatives"], 4)

        # Threshold sweep → precision/recall/F1 at best F1 (no single-accuracy claim).
        best = {"threshold": None, "precision": None, "recall": None, "f1": None}
        for t_index in range(1, 100):
            t = t_index / 100.0
            tp = sum(1 for s, p in zip(scores, positives) if s >= t and p)
            fp = sum(1 for s, p in zip(scores, positives) if s >= t and not p)
            fn = sum(1 for s, p in zip(scores, positives) if s < t and p)
            precision = tp / (tp + fp) if (tp + fp) else 0.0
            recall = tp / (tp + fn) if (tp + fn) else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
            if best["f1"] is None or f1 > best["f1"]:
                best = {"threshold": round(t, 2), "precision": round(precision, 4),
                        "recall": round(recall, 4), "f1": round(f1, 4)}
        metrics["best_threshold"] = best
        metrics["note"] = "Threshold sweep over validated labels; accuracy intentionally not the headline metric."
        return {"status": "ok", "metrics": metrics,
                "model": "anomaly", "model_version": "v1", "evaluated_at": utc_now_iso()}

    # ------------------------------------------------------------------
    # Observability + data quality reporting
    # ------------------------------------------------------------------
    def data_quality(self) -> Dict[str, Any]:
        return {
            "status": "success",
            "seen_events": len(self._seen_ids),
            "rejected_total": len(self._rejected),
            "recent_rejections": list(self._rejected)[-20:],
            "label_samples": len(self._label_store),
        }

    def _model_info(self) -> Dict[str, Any]:
        info = {}
        for meta in self.registry.all():
            info[meta.model_name] = meta.model_dump()
        return info

    def models(self) -> List[Dict[str, Any]]:
        return [m.model_dump() for m in self.registry.all()]


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _num(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _parse_ts(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        parsed = datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _flatten(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(f"{k}={v}" for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return ",".join(str(v) for v in value)
    return str(value) if value is not None else ""


def _reverse(label_map: Dict[str, str], label: str) -> str:
    for key, value in label_map.items():
        if value == label:
            return key
    return "event_severity"


def _advance(status, target: str):
    from .schemas import EventStatus

    order = [EventStatus.NEW, EventStatus.INGESTED, EventStatus.ENRICHED, EventStatus.ANALYZED,
             EventStatus.RISK_ASSESSED, EventStatus.CORRELATED]
    try:
        target_status = EventStatus(target)
    except ValueError:
        return status
    if status in order and target_status in order and order.index(status) < order.index(target_status):
        return target_status
    return status


data_science_ai = DataScienceAI()

__all__ = [
    "RiskConfig",
    "FEATURE_NAMES",
    "DataScienceAI",
    "data_science_ai",
]
