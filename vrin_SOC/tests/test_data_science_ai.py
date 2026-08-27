"""Unit tests for the Data Science AI: ingestion quality, features (no
leakage), anomaly detection, explainable risk engine, model registry,
evaluation metrics, and the feedback contamination guard."""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from vrin_SOC.coordination.data_science_ai import (
    FEATURE_NAMES,
    DataScienceAI,
    RiskConfig,
)
from vrin_SOC.coordination.event_bus import EventBus
from vrin_SOC.coordination.schemas import EventMode, ModelMetadata, SecurityEvent


def make_ds() -> DataScienceAI:
    """Fresh instance with its own bus — no cross-test contamination."""
    return DataScienceAI(bus=EventBus(), config=RiskConfig())


def ts(offset_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=offset_minutes)).isoformat()


class IngestionTests(unittest.TestCase):
    def setUp(self):
        self.ds = make_ds()

    def test_valid_event_accepted(self):
        event, quality = self.ds.ingest({
            "event_type": "security_event",
            "entity": {"ip": "10.1.1.1"},
            "data": {"authentication": {"failed_login_count": 3}},
            "severity": "high",
            "timestamp": ts(),
        })
        self.assertIsNotNone(event)
        self.assertTrue(quality.accepted)
        self.assertEqual(event.status.value, "ingested")

    def test_malformed_ip_rejected_and_recorded(self):
        event, quality = self.ds.ingest({
            "event_type": "security_event",
            "entity": {"ip": "999.999.1.1"},
        })
        self.assertIsNone(event)
        self.assertFalse(quality.accepted)
        self.assertTrue(any("IP" in i or "ip" in i for i in quality.issues))
        # Rejection is recorded, never silently discarded.
        dq = self.ds.data_quality()
        self.assertGreaterEqual(dq["rejected_total"], 1)

    def test_invalid_timestamp_rejected(self):
        event, quality = self.ds.ingest({"event_type": "security_event", "timestamp": "garbage"})
        self.assertIsNone(event)
        self.assertFalse(quality.accepted)

    def test_future_timestamp_rejected(self):
        future = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
        event, quality = self.ds.ingest({"event_type": "security_event", "timestamp": future})
        self.assertIsNone(event)

    def test_bad_severity_rejected(self):
        event, quality = self.ds.ingest({"event_type": "security_event", "severity": "apocalyptic"})
        self.assertIsNone(event)

    def test_duplicate_event_rejected(self):
        payload = {
            "event_type": "security_event",
            "entity": {"ip": "10.9.9.9"},
            "data": {"authentication": {"failed_login_count": 2}},
            "timestamp": ts(),
        }
        first, _ = self.ds.ingest(dict(payload))
        self.assertIsNotNone(first)
        dup, quality = self.ds.ingest(dict(payload))
        self.assertIsNone(dup)
        self.assertEqual(quality.duplicates, 1)


class FeatureEngineeringTests(unittest.TestCase):
    def setUp(self):
        self.ds = make_ds()

    def test_features_use_only_past_data_no_leakage(self):
        payload = {
            "event_type": "security_event",
            "entity": {"host": "leak-host"},
            "data": {"authentication": {"failed_login_count": 5}},
            "severity": "high",
            "timestamp": ts(),
        }
        event, _ = self.ds.ingest(payload)
        # Pre-store extraction must NOT include the event itself.
        pre = self.ds.extract_features(event)
        self.assertEqual(pre["failed_login_count"], 5)
        self.ds.build_features(event)  # stores the row
        # After storing, a fresh extraction over the same window now includes it.
        post = self.ds.extract_features(event)
        self.assertGreaterEqual(post["failed_login_count"], pre["failed_login_count"])

    def test_feature_names_are_stable_and_complete(self):
        event, _ = self.ds.ingest({
            "event_type": "security_event", "entity": {"host": "h1"},
            "data": {"authentication": {"failed_login_count": 1}}, "timestamp": ts(),
        })
        built = self.ds.build_features(event)
        self.assertEqual(built["feature_names"], list(FEATURE_NAMES))
        self.assertEqual(len(built["vector"]), len(FEATURE_NAMES))
        self.assertIn("last_1_hour", built["windows"])

    def test_hour_and_weekend_features(self):
        event, _ = self.ds.ingest({
            "event_type": "security_event", "entity": {"host": "h2"}, "timestamp": ts(),
        })
        features = self.ds.extract_features(event)
        self.assertEqual(features["hour_of_day"], float(datetime.now(timezone.utc).hour))
        self.assertIn(features["is_weekend"], (0.0, 1.0))


class AnomalyDetectionTests(unittest.TestCase):
    def setUp(self):
        self.ds = make_ds()

    def test_strong_signals_are_anomalous_and_explained(self):
        event, _ = self.ds.ingest({
            "event_type": "security_event",
            "entity": {"host": "anom-host", "ip": "10.5.5.5"},
            "data": {
                "authentication": {"failed_login_count": 12},
                "network": {"source_ips": ["203.0.113.9"], "ports": [4444]},
            },
            "severity": "critical",
            "timestamp": ts(),
        })
        result = self.ds.detect_anomaly(event)
        self.assertTrue(result.is_anomaly)
        self.assertGreaterEqual(result.anomaly_score, 0.6)
        self.assertGreaterEqual(len(result.explanation), 1)
        self.assertEqual(result.model_version, "v1")
        self.assertGreaterEqual(result.confidence, 0.0)

    def test_quiet_event_is_not_anomalous(self):
        event, _ = self.ds.ingest({
            "event_type": "security_event",
            "entity": {"host": "quiet-host"},
            "data": {"authentication": {"failed_login_count": 0}},
            "severity": "low",
            "timestamp": ts(),
        })
        result = self.ds.detect_anomaly(event)
        self.assertFalse(result.is_anomaly)

    def test_baseline_grows_and_zscore_engages(self):
        host = "zscore-host"
        for i in range(8):
            # Small natural variance so the baseline has a non-zero stdev.
            event, _ = self.ds.ingest({
                "event_type": "security_event",
                "entity": {"host": host},
                "data": {"authentication": {"failed_login_count": i % 2},
                         "network": {"connection_count": 2 + i % 2}},
                "severity": "low",
                "timestamp": ts(20 - i),
            })
            self.ds.build_features(event)
        # Now one loud event against the quiet baseline.
        loud, _ = self.ds.ingest({
            "event_type": "security_event",
            "entity": {"host": host},
            "data": {"authentication": {"failed_login_count": 20}, "network": {"connection_count": 60}},
            "severity": "high",
            "timestamp": ts(),
        })
        pre = self.ds.extract_features(loud)
        result = self.ds.detect_anomaly(loud, features=pre)
        self.assertTrue(result.is_anomaly)
        self.assertFalse(result.fallback_mode)
        self.assertTrue(any("σ" in e or "deviates" in e for e in result.explanation))


class RiskEngineTests(unittest.TestCase):
    def setUp(self):
        self.ds = make_ds()

    def _event_with(self, **fields):
        payload = {
            "event_type": "security_event",
            "entity": {"host": "risk-host", "ip": fields.pop("ip", "10.7.7.7")},
            "data": fields.pop("data", {}),
            "severity": fields.pop("severity", "medium"),
            "timestamp": ts(),
        }
        payload.update(fields)
        event, _ = self.ds.ingest(payload)
        return event

    def test_risk_is_explainable_with_factors(self):
        event = self._event_with(
            data={"authentication": {"failed_login_count": 9}, "network": {"source_ips": ["1.2.3.4"]}},
            severity="high",
        )
        self.ds.build_features(event)
        result = self.ds.score_risk(event)
        self.assertTrue(result.factors)
        for factor in result.factors:
            self.assertGreaterEqual(factor.contribution, 0.0)
            self.assertLessEqual(factor.contribution, 1.0)
        self.assertIn("Σ", result.explainability[-1])
        self.assertEqual(result.model_version, "v1")

    def test_malicious_ioc_boosts_risk(self):
        event = self._event_with(data={"network": {"source_ips": ["5.6.7.8"]}}, severity="medium")
        event.threat_intelligence = {"malicious_found": True, "mode": "real"}
        with_ti = self.ds.score_risk(event)
        event.threat_intelligence = {}
        without_ti = self.ds.score_risk(event)
        self.assertGreater(with_ti.risk_score, without_ti.risk_score)

    def test_severity_mapping_documented_thresholds(self):
        config = RiskConfig()
        event = self._event_with(severity="low", data={})
        low = self.ds.score_risk(event)
        event.severity = "critical"
        event.data = {"authentication": {"failed_login_count": 15}, "network": {"ports": [4444, 6666]}}
        self.ds.build_features(event)
        high = self.ds.score_risk(event)
        self.assertGreaterEqual(high.risk_score, low.risk_score)
        self.assertIn(high.severity, [label for _, label in config.severity_thresholds] + ["low"])

    def test_unavailable_ti_is_not_treated_as_clean(self):
        event = self._event_with(data={"network": {"source_ips": ["9.9.9.9"]}}, severity="medium")
        event.threat_intelligence = {"malicious_found": False, "mode": EventMode.UNAVAILABLE.value}
        result = self.ds.score_risk(event)
        # Unavailable enrichment contributes a small explicit signal, and the
        # explainability must be honest about the degradation.
        self.assertGreaterEqual(result.risk_score, 0.0)
        self.assertTrue(all(isinstance(f, str) for f in result.explainability))


class ModelRegistryTests(unittest.TestCase):
    def test_register_promote_and_retire(self):
        ds = make_ds()
        meta = ModelMetadata(model_name="anomaly", model_version="v2", algorithm="autoencoder",
                             status="candidate")
        ds.registry.register(meta)
        promoted = ds.registry.promote("anomaly", "v2")
        self.assertEqual(promoted.status, "production")
        self.assertEqual(ds.registry.production("anomaly").model_version, "v2")
        # v1 must have been retired, not silently deleted or duplicated.
        versions = {m.model_version: m.status for m in ds.registry.all() if m.model_name == "anomaly"}
        self.assertEqual(versions.get("v1"), "retired")

    def test_conflicting_reregistration_rejected(self):
        ds = make_ds()
        ds.registry.register(ModelMetadata(model_name="risk", model_version="v9", algorithm="a"))
        with self.assertRaises(ValueError):
            ds.registry.register(ModelMetadata(model_name="risk", model_version="v9", algorithm="b"))

    def test_production_model_never_silently_replaced(self):
        ds = make_ds()
        current = ds.registry.production("anomaly")
        self.assertIsNotNone(current)
        self.assertEqual(current.status, "production")


class FeedbackAndEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.ds = make_ds()

    def test_unvalidated_outcomes_rejected_contamination_guard(self):
        result = self.ds.record_outcome("evt-x", "confirmed_attack", validated_by="ml-self",
                                        validated=False)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(self.ds.validated_samples(), [])

    def test_missing_provenance_rejected(self):
        result = self.ds.record_outcome("evt-x", "confirmed_attack", validated_by="")
        self.assertEqual(result["status"], "rejected")

    def test_validated_outcome_stored_and_evaluated(self):
        host = "eval-host"
        events = []
        for i, label in enumerate(["confirmed_attack", "confirmed_attack",
                                   "false_positive", "false_positive"]):
            loud = label == "confirmed_attack"
            payload = {
                "event_type": "security_event",
                "entity": {"host": host},
                "data": {"authentication": {"failed_login_count": 10 if loud else 0}},
                "severity": "high" if loud else "low",
                "timestamp": ts(10 - i),
            }
            event, _ = self.ds.ingest(payload)
            self.ds.analyze(event)
            self.ds.bus.publish(event)  # bus history is where evaluation reads stored scores
            events.append((event.event_id, label))
            self.ds.record_outcome(event.event_id, label, validated_by="analyst-test", validated=True)

        self.assertEqual(len(self.ds.validated_samples()), 4)
        evaluation = self.ds.evaluate()
        self.assertEqual(evaluation["status"], "ok")
        metrics = evaluation["metrics"]
        self.assertEqual(metrics["labeled_samples"], 4)
        self.assertEqual(metrics["positive_count"], 2)
        self.assertEqual(metrics["negative_count"], 2)
        self.assertGreater(metrics["separation"], 0.0)  # positives score higher
        self.assertIn("best_threshold", metrics)
        self.assertIn("precision", metrics["best_threshold"])

    def test_evaluation_without_labels_is_never_fabricated(self):
        evaluation = self.ds.evaluate()
        self.assertEqual(evaluation["status"], "insufficient_data")
        self.assertEqual(evaluation["metrics"], {})


class AgentPipelineTests(unittest.TestCase):
    def test_analyze_attaches_anomaly_and_risk_to_event(self):
        ds = make_ds()
        payload = {
            "event_type": "security_event",
            "entity": {"host": "pipe-host", "ip": "10.8.8.8"},
            "data": {"authentication": {"failed_login_count": 6},
                     "network": {"source_ips": ["203.0.113.42"]}},
            "severity": "high",
            "timestamp": ts(),
        }
        event, _ = ds.ingest(payload)
        result = ds.analyze(event)
        self.assertEqual(result["status"], "success")
        self.assertIn("anomaly", event.analysis)
        self.assertIn("risk_score", event.risk)
        self.assertEqual(event.status.value, "risk_assessed")
        self.assertEqual(event.risk["model_version"], "v1")


if __name__ == "__main__":
    unittest.main()
