"""Unit tests for the shared coordination event schema (Pydantic validation)."""
from __future__ import annotations

import unittest

from pydantic import ValidationError

from vrin_SOC.coordination.schemas import (
    EntityRef,
    EthicsAssessment,
    EthicsClassification,
    EthicsDecision,
    Incident,
    IncidentStatus,
    ModelMetadata,
    Provenance,
    SecurityEvent,
)


class SchemaValidationTests(unittest.TestCase):
    def test_minimal_event_is_valid(self):
        event = SecurityEvent(event_type="security_event", entity={"ip": "10.0.0.1"})
        self.assertTrue(event.event_id.startswith("evt-"))
        self.assertEqual(event.provenance.mode.value, "real")
        self.assertEqual(event.status.value, "new")

    def test_malformed_ip_rejected(self):
        with self.assertRaises(ValidationError):
            SecurityEvent(event_type="security_event", entity={"ip": "999.999.999.999"})

    def test_invalid_timestamp_rejected(self):
        with self.assertRaises(ValidationError):
            SecurityEvent(event_type="security_event", timestamp="not-a-timestamp")

    def test_empty_event_type_rejected(self):
        with self.assertRaises(ValidationError):
            SecurityEvent(event_type="   ")

    def test_mode_enum_values(self):
        provenance = Provenance(mode="simulated")
        self.assertEqual(provenance.mode.value, "simulated")
        with self.assertRaises(ValidationError):
            Provenance(mode="probably-real")

    def test_event_record_merges_sections(self):
        event = SecurityEvent(event_type="security_event")
        event.record(threat_intelligence={"a": 1}, analysis={"b": 2}, risk={"score": 0.5})
        self.assertEqual(event.threat_intelligence["a"], 1)
        self.assertEqual(event.analysis["b"], 2)
        self.assertEqual(event.risk["score"], 0.5)

    def test_ethics_assessment_judges_action_not_user(self):
        assessment = EthicsAssessment(
            requested_action="test action",
            classification=EthicsClassification.ETHICAL_CONCERN,
            decision=EthicsDecision.REQUIRE_AUTHORIZATION,
            authorization_status="missing",
            harm_risk=0.1,
            deception_risk=0.0,
            privacy_risk=0.1,
            reason="needs authorization",
        )
        dumped = assessment.model_dump()
        self.assertNotIn("user_score", dumped)  # no permanent moral scoring
        self.assertEqual(dumped["decision"], "require_authorization")

    def test_model_metadata_roundtrip(self):
        meta = ModelMetadata(model_name="anomaly", model_version="v1", algorithm="zscore")
        self.assertEqual(ModelMetadata.model_validate(meta.model_dump()).model_name, "anomaly")

    def test_incident_trace_appends(self):
        incident = Incident(title="test incident")
        incident.add_trace("stage1", {"x": 1})
        incident.add_trace("stage2", {"y": 2})
        self.assertEqual(len(incident.trace), 2)
        self.assertEqual(incident.status, IncidentStatus.OPEN)
        self.assertTrue(incident.incident_id.startswith("inc-"))


if __name__ == "__main__":
    unittest.main()
