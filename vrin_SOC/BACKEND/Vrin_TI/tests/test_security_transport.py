import socket
import tempfile
import unittest
from datetime import timedelta
from unittest.mock import patch

from Vrin_TI.core.intelligence_bus import IntelligenceTransport, TransportManager
from Vrin_TI.database import ThreatDatabase
from Vrin_TI.models import IntelligenceEvent, IndicatorReference, utcnow
from Vrin_TI.privacy import PrivacyGate
from Vrin_TI.security import ReplayGuard, SecurityError, validate_external_url
from Vrin_TI.tests.helpers import make_test_config


class FailingTransport(IntelligenceTransport):
    name = "redis"
    async def connect(self): pass
    async def close(self): pass
    async def publish(self, event): raise RuntimeError("redis unavailable")
    async def health(self): return {"status": "error"}


class SecurityTests(unittest.TestCase):
    def test_ssrf_blocks_local_private_userinfo_and_non_https(self):
        for url in ("http://127.0.0.1/x", "https://10.0.0.1/x", "file:///etc/passwd", "https://u:p@example.com/x"):
            with self.assertRaises(SecurityError, msg=url):
                validate_external_url(url)

    @patch("Vrin_TI.security.socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))])
    def test_ssrf_blocks_dns_to_metadata(self, _resolve):
        with self.assertRaises(SecurityError):
            validate_external_url("https://evil.example/resource")

    @patch("Vrin_TI.security.socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])
    def test_ssrf_accepts_allowlisted_public_https(self, _resolve):
        url, addresses = validate_external_url("https://example.com/feed#x", allowed_hosts=["example.com"])
        self.assertEqual(url, "https://example.com/feed")
        self.assertEqual(addresses, ("93.184.216.34",))

    def test_privacy_requires_double_opt_in_and_public_data(self):
        gate = PrivacyGate(True, True)
        self.assertTrue(gate.allow("domain", "example.com", "provider", True).allowed)
        self.assertFalse(gate.allow("ipv4", "10.0.0.1", "provider", True).allowed)
        self.assertFalse(gate.allow("domain", "example.com", "provider", False).allowed)

    def test_replay_guard_timestamp_and_duplicate(self):
        event = IntelligenceEvent(event_type="ioc_observation", source="soc", indicator=IndicatorReference(type="ipv4", value="8.8.8.8"))
        ReplayGuard(300).validate(event, lambda _: False)
        with self.assertRaises(SecurityError):
            ReplayGuard(300).validate(event, lambda _: True)
        event.timestamp = utcnow() - timedelta(hours=1)
        with self.assertRaises(SecurityError):
            ReplayGuard(300).validate(event, lambda _: False)


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = ThreatDatabase(f"{self.tmp.name}/ti.db")
        self.manager = TransportManager(make_test_config(self.tmp.name), self.db)
        await self.manager.fallback.connect()

    async def asyncTearDown(self):
        await self.manager.fallback.close()
        self.tmp.cleanup()

    async def test_failed_redis_publish_falls_back_to_durable_sqlite(self):
        self.manager.active = FailingTransport()
        event = IntelligenceEvent(event_type="feed_health", source="ti", context={"feed": "x"})
        transport = await self.manager.publish(event)
        self.assertEqual(transport, "local_queue")
        self.assertEqual(self.db.queue_depth(), 1)
        self.assertEqual(self.manager.state, "degraded")

    async def test_local_queue_deduplicates_event(self):
        event = IntelligenceEvent(event_type="feed_health", source="ti", context={"feed": "x"})
        await self.manager.fallback.publish(event)
        await self.manager.fallback.publish(event)
        self.assertEqual(self.db.queue_depth(), 1)


if __name__ == "__main__":
    unittest.main()
