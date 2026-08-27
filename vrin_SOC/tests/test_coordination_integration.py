"""Integration tests for the coordination layer: agent-to-agent flows through
the event bus, graceful degradation, and the no-fabrication rule."""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from vrin_SOC.coordination.data_science_ai import DataScienceAI
from vrin_SOC.coordination.ethics_ai import ethics_ai
from vrin_SOC.coordination.event_bus import EventBus
from vrin_SOC.coordination.infrastructure_ai import InfrastructureAI
from vrin_SOC.coordination.knowledge_ai import KnowledgeAI
from vrin_SOC.coordination.schemas import EventMode, SecurityEvent
from vrin_SOC.coordination.soc_analyst_ai import SOCAnalystAI
from vrin_SOC.coordination.threat_intel_ai import ThreatIntelAI


def ts(offset_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=offset_minutes)).isoformat()


class FreshSystemTests(unittest.TestCase):
    """Each test gets its own bus + agents: deterministic, no shared state."""

    def setUp(self):
        self.bus = EventBus()
        self.infra = InfrastructureAI(bus=self.bus)
        self.ti = ThreatIntelAI(bus=self.bus)
        self.ds = DataScienceAI(bus=self.bus)
        self.soc = SOCAnalystAI(bus=self.bus)
        self.knowledge = KnowledgeAI(bus=self.bus)

    # ------------------------------------------------------------------
    # Infrastructure → bus → Data Science
    # ------------------------------------------------------------------
    def test_infrastructure_to_bus_to_data_science(self):
        event = self.infra.synthetic_event(
            "telemetry",
            {
                "cpu": {"cpu_usage_percent": 91.0},
                "memory": {"memory_usage_percent": 88.0},
                "authentication": {"failed_login_count": 0},
            },
            host="infra-host-1",
            timestamp=datetime.fromisoformat(ts()),
            severity="medium",
        )
        self.bus.publish(event)
        # Data Science subscribed to telemetry events on this bus.
        self.assertIn("anomaly", event.analysis)
        self.assertIn("risk_score", event.risk)
        self.assertEqual(event.provenance.mode, EventMode.SIMULATED)
        self.assertTrue(event.data.get("SIMULATION") is True)

    def test_real_telemetry_is_labeled_real_and_never_invented(self):
        event = self.infra.collect_telemetry(host="local-test-host")
        self.assertIn(event.provenance.mode, {EventMode.REAL, EventMode.FALLBACK})
        # Whatever the platform, unavailable sections are explicit.
        for section in ("cpu", "memory", "disk", "processes"):
            value = event.data.get(section)
            self.assertIsNotNone(value)
            if isinstance(value, dict) and value.get("status") == "unavailable":
                self.assertEqual(event.provenance.mode, EventMode.FALLBACK)

    # ------------------------------------------------------------------
    # Threat Intelligence: degrade, never fabricate
    # ------------------------------------------------------------------
    def test_ti_extracts_indicators(self):
        event = SecurityEvent(
            event_type="security_event",
            entity={"ip": "10.0.0.5", "domain": "evil-domain.example"},
            data={"note": "saw 203.0.113.10 and hash d41d8cd98f00b204e9800998ecf8427e"},
        )
        extracted = self.ti.extract_indicators(event)
        values = {i["type"]: [v["value"] for v in extracted if v["type"] == i["type"]] for i in extracted}
        self.assertIn("10.0.0.5", values["ipv4"])
        self.assertIn("203.0.113.10", values["ipv4"])
        self.assertIn("evil-domain.example", values["domain"])
        self.assertIn("d41d8cd98f00b204e9800998ecf8427e", values["md5"])

    def test_ti_degrades_to_unavailable_without_fabricating(self):
        event = SecurityEvent(
            event_type="security_event",
            entity={"ip": "10.0.0.6"},
            data={"note": "traffic from 198.51.100.77"},
        )
        result = self.ti.lookup("198.51.100.77", "ipv4")
        # Whatever the environment provides, 'malicious' must be an actual
        # determination or an explicit None — never an invented reputation.
        if result.get("status") == "unavailable" or result.get("degraded"):
            self.assertIn(result.get("malicious"), (None, False))
        self.assertIn(result["status"], {"ok", "unavailable", "degraded"})

    def test_enrichment_attaches_to_event(self):
        event = SecurityEvent(
            event_type="security_event",
            entity={"ip": "10.0.0.7"},
            data={"note": "packet to 203.0.113.99"},
        )
        result = self.ti.enrich(event)
        self.assertEqual(result["status"], "success")
        self.assertIn("indicators", event.threat_intelligence)
        self.assertGreaterEqual(result["indicators_checked"], 1)

    # ------------------------------------------------------------------
    # Data Science → SOC Analyst (correlated investigation)
    # ------------------------------------------------------------------
    def test_data_science_to_soc_investigation(self):
        cid = "corr-it-test-1"
        payload = {
            "event_type": "security_event",
            "correlation_id": cid,
            "entity": {"host": "soc-host", "ip": "10.1.1.1"},
            "data": {"authentication": {"failed_login_count": 8},
                     "network": {"source_ips": ["203.0.113.15"]}},
            "severity": "high",
            "timestamp": ts(),
        }
        event, quality = self.ds.ingest(payload)
        self.assertTrue(quality.accepted)
        self.ds.analyze(event)
        self.bus.publish(event)
        investigation = self.soc.investigate(event)
        self.assertEqual(investigation["status"], "success")
        self.assertIn("summary", investigation)
        self.assertTrue(investigation["recommendations"])
        self.assertIn("aggregate_risk", investigation["correlation"])
        # Evidence bundle contains all specialist inputs.
        evidence = investigation["evidence"]
        self.assertIn("threat_intelligence", evidence)
        self.assertIn("data_science", evidence)
        self.assertIn("risk", evidence)

    def test_correlation_window_binds_events(self):
        cid = "corr-window-test"
        e1 = self.bus.emit(event_type="security_event", correlation_id=cid,
                           entity={"ip": "10.2.2.2"}, timestamp=ts(10))
        e2 = self.bus.emit(event_type="security_event", correlation_id=cid,
                           entity={"ip": "10.2.2.2"}, timestamp=ts(5))
        self.bus.emit(event_type="security_event", correlation_id=cid,
                      entity={"ip": "10.2.2.2"}, timestamp=ts(120))  # 2h apart: outside window
        correlation = self.soc.correlate(e2)
        self.assertLessEqual(correlation["related_count"], 2)
        self.assertEqual(correlation["window_minutes"], 15)

    # ------------------------------------------------------------------
    # Knowledge → Data Science feedback
    # ------------------------------------------------------------------
    def test_knowledge_stores_validated_lesson_only(self):
        rejected = self.knowledge.record_outcome(
            "inc-x", "confirmed_attack", "summary", event_ids=["evt-1"],
            validated_by="ml-self-prediction", validated=False,
        )
        self.assertEqual(rejected["status"], "rejected")
        stored = self.knowledge.record_outcome(
            "inc-y", "confirmed_attack", "Brute force then C2 beacon pattern",
            event_ids=["evt-2"], pattern="brute_force_c2",
            validated_by="analyst-a", validated=True,
        )
        self.assertEqual(stored["status"], "success")
        self.assertIsNotNone(stored["lesson_id"])
        search = self.knowledge.search("brute force")
        self.assertGreaterEqual(search["count"], 1)
        self.assertEqual(search["lessons"][0]["conclusion"], "confirmed_attack")
        samples = self.knowledge.validated_samples()
        ids = [s["event_id"] for s in samples]
        self.assertIn("evt-2", ids)          # validated outcome enters the learning store
        self.assertNotIn("evt-1", ids)       # unvalidated prediction never does

    # ------------------------------------------------------------------
    # Graceful degradation: one broken agent never breaks the SOC
    # ------------------------------------------------------------------
    def test_broken_subscriber_does_not_break_pipeline(self):
        def explode(event):
            raise RuntimeError("agent exploded")

        self.bus.subscribe("security_event", explode, subscriber="broken-agent")
        payload = {
            "event_type": "security_event",
            "entity": {"host": "degrade-host"},
            "data": {"authentication": {"failed_login_count": 2}},
            "severity": "medium",
            "timestamp": ts(),
        }
        event, quality = self.ds.ingest(payload)
        self.assertTrue(quality.accepted)
        self.bus.publish(event)  # DS auto-handler analyzes; broken agent dies
        self.assertIn("anomaly", event.analysis)  # pipeline continued despite the crash
        dead = self.bus.dead_letter()
        self.assertTrue(any(d["subscriber"] == "broken-agent" for d in dead))

    def test_agent_run_guarded_returns_degraded_not_crash(self):
        def boom():
            raise ValueError("nope")

        outcome = self.ds.run_guarded(boom)
        self.assertEqual(outcome["status"], "error")
        self.assertTrue(outcome["degraded"])

    # ------------------------------------------------------------------
    # Ethics in the loop
    # ------------------------------------------------------------------
    def test_ethics_blocks_unauthorized_high_impact(self):
        assessment = ethics_ai.evaluate("isolate host prod-db-01 and delete its logs",
                                        context={}, authorization_status="missing")
        self.assertIn(assessment.decision.value, {"deny", "require_authorization", "escalate_to_human"})
        self.assertTrue(assessment.human_approval_required or assessment.decision.value == "deny")


if __name__ == "__main__":
    unittest.main()
