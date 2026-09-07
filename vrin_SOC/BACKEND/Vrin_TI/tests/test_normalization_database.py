import tempfile
import unittest
from datetime import timedelta

from Vrin_TI.config import PACKAGE_ROOT, config
from Vrin_TI.database import ThreatDatabase
from Vrin_TI.models import ThreatIndicator, utcnow
from Vrin_TI.normalization import InvalidIndicator, deterministic_indicator_id, detect_type, normalize_indicator


class NormalizationTests(unittest.TestCase):
    def test_default_runtime_paths_are_owned_by_ti(self):
        self.assertIn(PACKAGE_ROOT, config.database_path.parents)
        self.assertIn(PACKAGE_ROOT, config.log_dir.parents)

    def test_ip_domain_url_hash_cve_and_email(self):
        self.assertEqual(normalize_indicator("ipv6", "2001:0db8::1"), "2001:db8::1")
        self.assertEqual(normalize_indicator("domain", "Exämple.COM."), "xn--exmple-cua.com")
        self.assertEqual(normalize_indicator("url", "HTTPS://Example.COM:443/a%20b#fragment"), "https://example.com/a%20b")
        self.assertEqual(normalize_indicator("sha256", "A" * 64), "a" * 64)
        self.assertEqual(normalize_indicator("cve", "cve_2024_12345"), "CVE-2024-12345")
        self.assertEqual(normalize_indicator("email", "Analyst@Example.COM"), "Analyst@example.com")
        self.assertEqual(detect_type("8.8.8.8").value, "ipv4")
        self.assertEqual(detect_type("T1059.001").value, "mitre-technique")

    def test_rejects_malformed_and_dangerous_values(self):
        for kind, value in (("ipv4", "999.1.1.1"), ("url", "file:///etc/passwd"),
                            ("url", "http://user:pass@example.com"), ("domain", "bad..example.com"),
                            ("sha256", "z" * 64), ("cve", "CVE-24-1")):
            with self.assertRaises(InvalidIndicator, msg=(kind, value)):
                normalize_indicator(kind, value)
        with self.assertRaises(InvalidIndicator):
            detect_type("'; DROP TABLE threat_indicators; --")

    def test_deterministic_id(self):
        first = deterministic_indicator_id("domain", "EXAMPLE.com")
        self.assertEqual(first, deterministic_indicator_id("domain", "example.com."))
        from uuid import UUID
        UUID(first.split("--", 1)[1])


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = ThreatDatabase(f"{self.tmp.name}/ti.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_deduplicates_and_retains_provenance_history(self):
        first = self.db.upsert_indicator(ThreatIndicator(indicator_type="domain", indicator_value="Example.COM",
            source="feed-a", source_reliability=0.9, confidence=0.8, tags=["phishing"]))
        second = self.db.upsert_indicator(ThreatIndicator(indicator_type="domain", indicator_value="example.com.",
            source="feed-b", source_reliability=0.7, confidence=0.7, tags=["c2"]))
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(first["indicator_id"], second["indicator_id"])
        self.assertEqual({item["name"] for item in second["sources"]}, {"feed-a", "feed-b"})
        self.assertEqual(second["tags"], ["c2", "phishing"])
        self.assertGreaterEqual(len(second["confidence_history"]), 2)

    def test_expiration_and_false_positive_are_retained(self):
        item = ThreatIndicator(indicator_type="ipv4", indicator_value="203.0.113.4", source="test",
            expires_at=utcnow() - timedelta(seconds=1), verification_status="active")
        stored = self.db.upsert_indicator(item)
        self.assertEqual(self.db.expire_due(), 1)
        expired = self.db.get_indicator_by_id(stored["indicator_id"])
        self.assertFalse(expired["active"])
        self.assertEqual(expired["verification_status"], "expired")
        self.assertTrue(self.db.mark_false_positive(stored["indicator_id"], 0.95))
        self.assertEqual(self.db.get_indicator_by_id(stored["indicator_id"])["verification_status"], "false_positive")

    def test_source_reliability_learns_from_auditable_feedback(self):
        item = self.db.upsert_indicator(ThreatIndicator(indicator_type="domain", indicator_value="feedback.example",
            source="learning-feed", source_reliability=.9))
        before = item["sources"][0]["reliability"]
        self.assertEqual(self.db.record_source_outcome("learning-feed", False), 1)
        after = self.db.get_indicator("domain", "feedback.example")["sources"][0]["reliability"]
        self.assertLess(after, before)

    def test_parameterized_queries_survive_injection_text(self):
        item = self.db.upsert_indicator(ThreatIndicator(indicator_type="mutex", indicator_value="x'); DROP TABLE threat_indicators;--", source="test"))
        self.assertIsNotNone(self.db.get_indicator_by_id(item["indicator_id"]))
        self.assertEqual(len(self.db.list_indicators()), 1)


if __name__ == "__main__":
    unittest.main()
