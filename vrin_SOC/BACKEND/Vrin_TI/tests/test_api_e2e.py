import tempfile
import unittest

from fastapi.testclient import TestClient

from Vrin_TI.api import create_app
from Vrin_TI.engine import ThreatIntelligenceEngine
from Vrin_TI.models import AssetReference, IndicatorReference, IntelligenceEvent, ThreatIndicator
from Vrin_TI.tests.helpers import make_test_config


class TIAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = make_test_config(self.tmp.name)
        self.engine = ThreatIntelligenceEngine(self.config)
        self.client_context = TestClient(create_app(self.engine))
        self.client = self.client_context.__enter__()
        self.headers = {"X-Vrindha-Service-Token": self.config.service_token}

    def tearDown(self):
        self.client_context.__exit__(None, None, None)
        self.tmp.cleanup()

    def test_auth_validation_ingestion_lookup_and_replay(self):
        self.assertEqual(self.client.get("/threat-intel/health").status_code, 401)
        self.assertEqual(self.client.get("/threat-intel/health", headers={"X-Vrindha-Service-Token": "wrong"}).status_code, 401)
        created = self.client.post("/threat-intel/indicators", headers=self.headers, json={
            "indicator_type": "domain", "indicator_value": "Example.COM.", "source": "test", "confidence": .8})
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["normalized_value"], "example.com")
        lookup = self.client.post("/threat-intel/lookup", headers=self.headers, json={"indicator": "example.com"})
        self.assertTrue(lookup.json()["found"])
        event = IntelligenceEvent(event_type="ioc_observation", source="soc",
            indicator=IndicatorReference(type="domain", value="example.com")).model_dump(mode="json")
        first = self.client.post("/intelligence/events", headers=self.headers, json=event)
        second = self.client.post("/intelligence/events", headers=self.headers, json=event)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 409)

    def test_body_limit_and_stix_validation(self):
        response = self.client.post("/threat-intel/stix/import", headers={**self.headers, "content-length": "2000000"}, json={"type": "bundle", "objects": []})
        self.assertEqual(response.status_code, 413)
        bad = self.client.post("/threat-intel/stix/import", headers=self.headers,
            json={"type": "indicator", "spec_version": "2.0", "id": "indicator--x"})
        self.assertEqual(bad.status_code, 422)

    def test_websocket_event_and_heartbeat_contract(self):
        with self.client.websocket_connect("/ws/threat-intelligence", headers=self.headers) as websocket:
            response = self.client.post("/threat-intel/indicators", headers=self.headers, json={
                "indicator_type": "sha256", "indicator_value": "a" * 64, "source": "test", "source_reliability": .99,
                "confidence": .99, "threat_score": 95, "malware_family": ["ExampleMalware"]})
            self.assertEqual(response.status_code, 201)
            message = websocket.receive_json()
            self.assertEqual(message["type"], "event")
            self.assertEqual(message["event"]["event_type"], "ioc_update")
            self.assertIn("event_id", message["event"])


class EndToEndCorrelationTests(unittest.IsolatedAsyncioTestCase):
    async def test_soc_gateway_to_ti_to_enriched_alert_without_action(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = ThreatIntelligenceEngine(make_test_config(directory))
            seeded = await engine.ingest_indicator(ThreatIndicator(indicator_type="ipv4", indicator_value="8.8.8.8",
                source="trusted-feed", source_reliability=.98, confidence=.95, threat_score=92,
                malware_family=["ExampleMalware"], threat_actor=["ExampleActor"], campaign=["ExampleCampaign"],
                mitre_attack_ids=["T1071.001"], tags=["c2"]))
            event = IntelligenceEvent(event_type="ioc_observation", source="soc",
                indicator=IndicatorReference(type="ipv4", value="8.8.8.8"),
                asset=AssetReference(id="host-001", ip="10.0.0.25", criticality=.95, exposed=False),
                context={"sensor": "suricata", "kind": "internal connection flow"}, severity="high", confidence=.93)
            result = await engine.process_soc_event(event)
            self.assertTrue(result["intelligence"]["malware_family"])
            self.assertIn("T1071.001", result["intelligence"]["mitre_attack_ids"])
            self.assertEqual(result["intelligence"]["sources"][0]["name"], "trusted-feed")
            self.assertIsNotNone(result["sighting"])
            self.assertGreater(result["correlation"]["risk_delta"], 0)
            self.assertGreaterEqual(result["soc_alert"]["risk_score"], seeded["threat_score"])
            self.assertTrue(result["soc_alert"]["requires_human_approval"])
            self.assertFalse(result["soc_alert"]["defensive_action_executed"])
            self.assertNotIn("command", result["soc_alert"])
            self.assertGreaterEqual(len(engine.database.correlations()), 1)
            report = engine.make_report(seeded["indicator_id"])
            self.assertTrue(report["evidence"])
            self.assertTrue(report["threat_summary"]["sources"])

    async def test_unknown_observation_is_not_declared_malicious(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = ThreatIntelligenceEngine(make_test_config(directory))
            event = IntelligenceEvent(event_type="ioc_observation", source="soc",
                indicator=IndicatorReference(type="domain", value="unknown.example"), confidence=.4)
            result = await engine.process_soc_event(event)
            self.assertLess(result["intelligence"]["threat_score"], 40)
            self.assertIsNone(result["correlation"])
            self.assertFalse(result["soc_alert"]["defensive_action_executed"])


if __name__ == "__main__":
    unittest.main()
