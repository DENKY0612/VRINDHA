import tempfile
import unittest
from datetime import timedelta

from Vrin_TI.database import ThreatDatabase
from Vrin_TI.models import utcnow
from Vrin_TI.scoring.threat_score import calculate_confidence, calculate_threat_score, severity_for
from Vrin_TI.stix import STIXAdapter, STIXValidationError, internal_to_stix, parse_bundle, pattern_to_indicator


class ScoringTests(unittest.TestCase):
    def test_threat_and_confidence_are_separate(self):
        confidence = calculate_confidence([0.9, 0.8], 0.8, 2)
        result = calculate_threat_score(source_reliabilities=[0.9, 0.8], reported_confidence=0.8,
            independent_sources=2, sightings=8, malware_association=True, attack_relevance=0.8)
        self.assertGreater(confidence, 0.7)
        self.assertGreater(result.score, 60)
        self.assertNotEqual(result.score, result.confidence)
        self.assertEqual(result.severity, severity_for(result.score))

    def test_kev_asset_context_beats_cvss_alone(self):
        base = calculate_threat_score(source_reliabilities=[0.9], reported_confidence=0.9, cvss=9.8)
        contextual = calculate_threat_score(source_reliabilities=[0.9], reported_confidence=0.9, cvss=9.8,
            kev=True, asset_exposure=1, asset_criticality=1, observed_exploitation=True)
        self.assertGreater(contextual.score, base.score)

    def test_age_and_false_positive_reduce_score(self):
        current = calculate_threat_score(source_reliabilities=[0.8], reported_confidence=0.8)
        stale = calculate_threat_score(source_reliabilities=[0.8], reported_confidence=0.8,
            last_seen=utcnow() - timedelta(days=365), false_positive_probability=0.8)
        self.assertLess(stale.score, current.score)

    def test_classification_boundaries(self):
        self.assertEqual([severity_for(x) for x in (0, 20, 40, 60, 80)],
                         ["informational", "low", "medium", "high", "critical"])


class STIXTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = ThreatDatabase(f"{self.tmp.name}/ti.db")
        self.adapter = STIXAdapter(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def test_stix_indicator_ingest_and_round_trip(self):
        payload = {"type": "bundle", "id": "bundle--11111111-1111-4111-8111-111111111111", "objects": [{
            "type": "indicator", "spec_version": "2.1", "id": "indicator--11111111-1111-4111-8111-111111111111",
            "created": "2026-08-14T00:00:00Z", "modified": "2026-08-14T00:00:00Z",
            "valid_from": "2026-08-14T00:00:00Z", "pattern_type": "stix",
            "pattern": "[domain-name:value = 'Example.COM']", "confidence": 85, "labels": ["phishing"]}]}
        stats = self.adapter.ingest(payload, "taxii", 0.9)
        self.assertEqual(stats["indicators"], 1)
        indicator = self.db.get_indicator("domain", "example.com")
        exported = internal_to_stix(indicator)
        self.assertEqual(exported["spec_version"], "2.1")
        self.assertEqual(pattern_to_indicator(exported["pattern"]), ("domain", "example.com"))

    def test_entities_relationships_and_vulnerability(self):
        objects = [
            {"type": "threat-actor", "spec_version": "2.1", "id": "threat-actor--11111111-1111-4111-8111-111111111111", "name": "Actor A"},
            {"type": "vulnerability", "spec_version": "2.1", "id": "vulnerability--11111111-1111-4111-8111-111111111111", "name": "CVE-2026-1234"},
            {"type": "relationship", "spec_version": "2.1", "id": "relationship--11111111-1111-4111-8111-111111111111",
             "relationship_type": "targets", "source_ref": "threat-actor--11111111-1111-4111-8111-111111111111",
             "target_ref": "vulnerability--11111111-1111-4111-8111-111111111111"},
        ]
        stats = self.adapter.ingest({"type": "bundle", "id": "bundle--x", "objects": objects}, "mitre", 0.98)
        self.assertEqual(stats["relationships"], 1)
        self.assertEqual(self.db.vulnerabilities()[0]["cve_id"], "CVE-2026-1234")

    def test_mitre_custom_tactic_object_is_retained(self):
        tactic = {"type": "x-mitre-tactic", "spec_version": "2.1",
            "id": "x-mitre-tactic--11111111-1111-4111-8111-111111111111", "name": "Execution"}
        stats = self.adapter.ingest(tactic, "mitre", .98)
        self.assertEqual(stats["entities"], 1)
        self.assertEqual(self.db.list_entities("x-mitre-tactic")[0]["name"], "Execution")

    def test_rejects_wrong_version_oversize_and_non_equality_patterns(self):
        bad = {"type": "indicator", "spec_version": "2.0", "id": "indicator--x", "pattern": "[domain-name:value='x.com']"}
        with self.assertRaises(STIXValidationError):
            parse_bundle(bad)
        self.assertIsNone(pattern_to_indicator("[domain-name:value MATCHES '.*']"))
        with self.assertRaises(STIXValidationError):
            parse_bundle("x" * 100, max_bytes=10)


if __name__ == "__main__":
    unittest.main()
