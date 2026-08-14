import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from Vrin_TI.collectors.cisa_kev import CISAKEVCollector
from Vrin_TI.collectors.suricata import SuricataCollector
from Vrin_TI.collectors.zeek import ZeekCollector
from Vrin_TI.integrations.sigma import SigmaRuleLoader, SigmaRuleError
from Vrin_TI.integrations.yara import YARAIntegration


class CISACollectorTests(unittest.IsolatedAsyncioTestCase):
    @patch("Vrin_TI.collectors.cisa_kev.fetch_json", new_callable=AsyncMock)
    async def test_cisa_schema_maps_kev(self, fetch):
        fetch.return_value = {"catalogVersion": "1", "vulnerabilities": [{"cveID": "CVE-2026-1234",
            "vendorProject": "Vendor", "product": "Product", "vulnerabilityName": "RCE",
            "shortDescription": "Known exploited", "requiredAction": "Patch", "dueDate": "2026-09-01",
            "knownRansomwareCampaignUse": "Known", "notes": "https://example.com/advisory"}]}
        batch = await CISAKEVCollector(timeout=1, reliability=.98).collect()
        self.assertEqual(batch.items[0].payload["cve_id"], "CVE-2026-1234")
        self.assertTrue(batch.items[0].payload["kev"])
        self.assertTrue(batch.items[0].payload["ransomware_use"])


class LocalCollectorTests(unittest.IsolatedAsyncioTestCase):
    async def test_suricata_filtered_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "eve.json"
            path.write_text("\n".join([json.dumps({"event_type": "dns", "timestamp": "2026-08-14T00:00:00Z", "dns": {"rrname": "Bad.EXAMPLE"}}),
                json.dumps({"event_type": "stats", "stats": {"x": 1}})]) + "\n")
            batch = await SuricataCollector(str(path)).collect()
            self.assertEqual(len(batch.items), 1)
            self.assertEqual(batch.items[0].payload["indicator_type"], "domain")

    async def test_zeek_json(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "dns.log").write_text(json.dumps({"ts": 1780000000.0, "uid": "x", "query": "bad.example"}) + "\n")
            batch = await ZeekCollector(directory).collect()
            self.assertEqual(len(batch.items), 1)
            self.assertEqual(batch.items[0].payload["source"], "zeek")

    async def test_missing_optional_collectors_degrade_without_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(Exception):
                await SuricataCollector(str(Path(directory) / "missing")).collect()
            with self.assertRaises(Exception):
                await ZeekCollector(str(Path(directory) / "missing")).collect()


class RuleIntegrationTests(unittest.TestCase):
    def test_sigma_official_metadata_and_attack_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            loader = SigmaRuleLoader(directory)
            rule = loader.parse("""title: Suspicious Process
id: 11111111-1111-4111-8111-111111111111
logsource: {category: process_creation, product: linux}
detection:
  selection: {Image|endswith: /sh}
  condition: selection
falsepositives: [Administrative activity]
level: high
tags: [attack.t1059, attack.execution]
""")
            self.assertEqual(rule["mitre_attack_ids"], ["T1059"])
            self.assertEqual(rule["detection"]["condition"], "selection")

    def test_sigma_unsafe_python_tag_is_not_constructed(self):
        loader = SigmaRuleLoader(".")
        with self.assertRaises(SigmaRuleError):
            loader.parse("title: x\nlogsource: {}\ndetection: !!python/object:os.system ['id']")

    def test_yara_missing_or_disabled_never_breaks(self):
        status = YARAIntegration("", []).status()
        self.assertIn(status["status"], {"missing", "disabled"})


if __name__ == "__main__":
    unittest.main()
