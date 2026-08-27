"""Unit tests for the coordination event bus (pub/sub, correlation, dead-letter)."""
from __future__ import annotations

import unittest

from vrin_SOC.coordination.event_bus import EventBus, InMemoryTransport
from vrin_SOC.coordination.schemas import SecurityEvent


class EventBusTests(unittest.TestCase):
    def setUp(self):
        self.bus = EventBus()

    def test_publish_delivers_to_specific_subscriber(self):
        received = []
        self.bus.subscribe("telemetry", lambda e: received.append(e.event_id), subscriber="t")
        self.bus.emit(event_type="telemetry")
        self.bus.emit(event_type="security_event")  # not subscribed → not delivered
        self.assertEqual(len(received), 1)

    def test_wildcard_subscriber_receives_all_types(self):
        received = []
        self.bus.subscribe("*", lambda e: received.append(e.event_type), subscriber="w")
        self.bus.emit(event_type="telemetry")
        self.bus.emit(event_type="security_event")
        self.assertEqual(sorted(received), ["security_event", "telemetry"])

    def test_subscriber_annotations_merge_back_into_event(self):
        self.bus.subscribe("security_event", lambda e: {"analysis": {"ml": 0.5}}, subscriber="ds")
        event = SecurityEvent(event_type="security_event")
        self.bus.publish(event)
        self.assertEqual(event.analysis.get("ml"), 0.5)

    def test_failing_subscriber_goes_to_dead_letter_not_crash(self):
        def bad_handler(event):
            raise RuntimeError("boom")

        self.bus.subscribe("telemetry", bad_handler, subscriber="bad")
        self.bus.subscribe("telemetry", lambda e: "ok", subscriber="good")
        event = SecurityEvent(event_type="telemetry")
        report = self.bus.publish(event)
        self.assertIn("bad", [x.split(":")[0] for x in report["errors"]])
        self.assertEqual(self.bus.stats()["failed"], 1)
        dead = self.bus.dead_letter()
        self.assertEqual(len(dead), 1)
        self.assertEqual(dead[0]["subscriber"], "bad")

    def test_correlate_groups_by_correlation_id(self):
        cid = "corr-test-123"
        e1 = self.bus.emit(event_type="security_event", correlation_id=cid)
        e2 = self.bus.emit(event_type="security_event", correlation_id=cid)
        self.bus.emit(event_type="security_event", correlation_id="other")
        related = self.bus.correlate(cid)
        self.assertEqual({e.event_id for e in related}, {e1.event_id, e2.event_id})

    def test_acknowledge_and_update(self):
        event = self.bus.emit(event_type="security_event")
        self.assertTrue(self.bus.acknowledge(event.event_id, "correlated", actor="soc"))
        self.assertTrue(self.bus.update(event.event_id, correlation={"x": 1}))
        found = self.bus.find(event.event_id)
        self.assertEqual(found.status.value, "correlated")
        self.assertEqual(found.correlation["x"], 1)

    def test_unsubscribe(self):
        received = []
        sub_id = self.bus.subscribe("telemetry", lambda e: received.append(1), subscriber="t")
        self.bus.publish(SecurityEvent(event_type="telemetry"))
        self.bus.unsubscribe(sub_id)
        self.bus.publish(SecurityEvent(event_type="telemetry"))
        self.assertEqual(received, [1])

    def test_stats_accounting(self):
        self.bus.subscribe("telemetry", lambda e: None, subscriber="t")
        self.bus.publish(SecurityEvent(event_type="telemetry"))
        stats = self.bus.stats()
        self.assertEqual(stats["published"], 1)
        self.assertEqual(stats["delivered"], 1)
        self.assertEqual(stats["failed"], 0)

    def test_transport_is_pluggable(self):
        class CountingTransport(InMemoryTransport):
            def __init__(self):
                super().__init__()
                self.stored = 0

            def store(self, event):
                self.stored += 1
                super().store(event)

        transport = CountingTransport()
        bus = EventBus(transport=transport)
        bus.publish(SecurityEvent(event_type="telemetry"))
        self.assertEqual(transport.stored, 1)
        self.assertEqual(len(transport.peek(10)), 1)


if __name__ == "__main__":
    unittest.main()
