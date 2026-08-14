import tempfile
import unittest
from unittest.mock import AsyncMock, Mock

from Vrin_TI.collectors.base import CollectedItem, CollectionBatch, FeedCollector
from Vrin_TI.collectors.feed_manager import FeedManager
from Vrin_TI.database import ThreatDatabase
from Vrin_TI.engine import ThreatIntelligenceEngine
from Vrin_TI.models import IntelligenceEvent, IndicatorReference
from Vrin_TI.tests.helpers import test_config
from vrin_SOC.core.intelligence_bus import IntelligenceGateway


class FlakyCollector(FeedCollector):
    name = "flaky"
    def __init__(self):
        super().__init__(timeout=1, reliability=.7)
        self.fail = True
    async def collect(self, cursor=None):
        if self.fail:
            raise RuntimeError("provider outage")
        return CollectionBatch([CollectedItem("indicator", {"indicator_type": "domain", "indicator_value": "recovered.example"})])


class FakeEngine:
    def __init__(self): self.items = []
    async def ingest_collected(self, item, source, reliability):
        self.items.append(item); return 1
    async def emit_feed_health(self, name, status, detail): pass


class FailureRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_feed_failure_then_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            db = ThreatDatabase(f"{directory}/ti.db")
            fake = FakeEngine()
            manager = FeedManager(test_config(directory), db, fake)
            collector = FlakyCollector()
            manager.register(collector, {"enabled": True, "interval": 60, "timeout": 1, "retry_count": 1, "reliability": .7})
            failed = await manager.sync("flaky")
            self.assertEqual(failed["status"], "error")
            collector.fail = False
            recovered = await manager.sync("flaky")
            self.assertEqual(recovered["status"], "healthy")
            self.assertEqual(recovered["items_ingested"], 1)

    async def test_soc_outage_queues_and_db_outage_does_not_raise(self):
        with tempfile.TemporaryDirectory() as directory:
            db = ThreatDatabase(f"{directory}/ti.db")
            gateway = IntelligenceGateway(db, "http://127.0.0.1:8010", "test-token")
            gateway._request = AsyncMock(side_effect=RuntimeError("SOC/TI unavailable"))
            event = IntelligenceEvent(event_type="ioc_observation", source="soc",
                indicator=IndicatorReference(type="domain", value="example.com"))
            queued = await gateway.send_observation(event)
            self.assertEqual(queued["status"], "queued")
            self.assertEqual(db.queue_depth(), 1)
            db.queue_event = Mock(side_effect=OSError("database unavailable"))
            other = IntelligenceEvent(event_type="ioc_observation", source="soc",
                indicator=IndicatorReference(type="domain", value="other.example"))
            degraded = await gateway.send_observation(other)
            self.assertEqual(degraded["status"], "error")
            self.assertIn("SOC continues", degraded["reason"])

    async def test_db_health_failure_is_reported_not_raised(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = ThreatIntelligenceEngine(test_config(directory))
            engine.database.queue_depth = Mock(side_effect=OSError("db down"))
            engine.bus.health = AsyncMock(side_effect=OSError("bus down"))
            result = await engine.health()
            self.assertEqual(result["status"], "degraded")
            self.assertIn("error", result["database"])

    async def test_external_connectors_and_reputation_outages_are_optional(self):
        with tempfile.TemporaryDirectory() as directory:
            engine = ThreatIntelligenceEngine(test_config(directory, external_enrichment=True, external_submission=True))
            engine.enrichment._virus_total = AsyncMock(side_effect=RuntimeError("VirusTotal down"))
            # No API key means policy/provider status is disabled; either way the
            # outage is represented in data rather than escaping the engine.
            result = await engine.enrichment.enrich("domain", "example.com", allow_external=True)
            statuses = {item["provider"]: item["status"] for item in result["external"]}
            self.assertIn(statuses["virustotal"], {"error", "disabled"})
            self.assertIn(statuses["abuseipdb"], {"disabled", "unsupported", "error"})
            self.assertEqual((await engine.monitor.misp.health())["status"], "disabled")
            self.assertEqual((await engine.monitor.opencti.health())["status"], "disabled")


if __name__ == "__main__":
    unittest.main()
