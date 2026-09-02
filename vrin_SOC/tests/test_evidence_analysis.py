"""Tests for the Vrindha AI anti-hallucination & evidence-grounded analysis.

Covers the 13 rules of the operating contract (``VRINDHA_AI_PROMPT``):
no fabrication, FACT/INFERENCE/UNKNOWN separation, TI verification
(CONFIRMED / NOT CONFIRMED / UNKNOWN), multi-source correlation,
explainable risk+confidence, uncertainty handling, structured output,
high-impact action protection, human-in-the-loop, feedback loop, and
auditability.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from vrin_SOC._imports import install

install()

from vrin_SOC.coordination.evidence_analysis import (  # noqa: E402
    ATTRIBUTION_UNVERIFIED_PHRASE,
    BRUTE_FORCE_UNCONFIRMED_SENTENCE,
    CONFLICT_PHRASE,
    HUMAN_VERIFICATION_PHRASE,
    INSUFFICIENT_EVIDENCE_PHRASE,
    SUSPICIOUS_NOT_CONCLUSIVE_PHRASE,
    VrindhaAI,
    enforce_claim_guard,
    render_report,
    vrindha_ai,
)
from vrin_SOC.coordination.schemas import (  # noqa: E402
    SecurityAnalysis,
    SecurityEvent,
    ThreatIntelStatus,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _past(hours: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


class PromptContractTests(unittest.TestCase):
    def test_prompt_contains_core_anti_hallucination_rules(self):
        from vrin_SOC.coordination.evidence_analysis import VRINDHA_AI_PROMPT

        for fragment in (
            "Never invent, assume, or fabricate cybersecurity evidence",
            "FACT — Directly confirmed",
            "INFERENCE — A reasonable conclusion",
            "UNKNOWN — Information that cannot currently be verified",
            "Insufficient evidence — further investigation required.",
            "Threat Intelligence Status: NOT CONFIRMED",
            "Do not create a malicious reputation",
            "Never present an inference as a confirmed fact",
            "Risk Score: 0–100",
            "Confidence: 0–100",
            "Severity: LOW / MEDIUM / HIGH / CRITICAL",
            "Evidence is conflicting.",
            "This behavior is suspicious but not conclusively malicious.",
            "[SECURITY ANALYSIS]",
            "HUMAN APPROVAL:",
            "The AI must NOT independently perform high-impact actions",
            "Human verification required.",
            "Do not silently change historical evidence or audit records",
            "Evidence before inference. Inference before action. Verification before high-impact action.",
            "Trust me, this is malicious.",
        ):
            self.assertIn(fragment, VRINDHA_AI_PROMPT)

    def test_prompt_served_by_agent(self):
        result = vrindha_ai.prompt()
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["agent"], "VrindhaAI")
        self.assertEqual(result["rules"], 13)
        self.assertIn("Never invent, assume, or fabricate", result["prompt"])


class CanonicalExampleTests(unittest.TestCase):
    """Rule 3: the contract's own worked example must produce the contract's
    exact recommended wording — never the forbidden campaign claim."""

    def test_brute_force_without_ti_never_claims_ransomware_campaign(self):
        event = SecurityEvent(
            event_type="auth_failure",
            entity={"ip": "192.168.1.50"},
            data={
                "command": "37 failed SSH login attempts from 192.168.1.50",
                "authentication": {"failed_login_count": 37, "service": "ssh"},
            },
            severity="high",
        )
        analysis = vrindha_ai.analyze(event)
        self.assertIsInstance(analysis, SecurityAnalysis)

        report = render_report(analysis)
        # The forbidden claim must never appear.
        self.assertNotIn("is part of a ransomware campaign", report)
        # The contract's recommended wording must.
        self.assertIn(
            "The IP generated suspicious SSH activity consistent with possible "
            "brute-force behavior.",
            analysis.assessment,
        )
        self.assertIn(BRUTE_FORCE_UNCONFIRMED_SENTENCE, analysis.assessment)
        # No supporting intelligence exists ⇒ NOT CONFIRMED (rule 4).
        self.assertEqual(analysis.threat_intelligence, ThreatIntelStatus.NOT_CONFIRMED)
        # Risk/confidence are bounded 0-100 integers (rule 7).
        self.assertIsInstance(analysis.risk_score, int)
        self.assertIsInstance(analysis.confidence, int)
        self.assertGreaterEqual(analysis.risk_score, 0)
        self.assertLessEqual(analysis.risk_score, 100)
        self.assertGreaterEqual(analysis.confidence, 0)
        self.assertLessEqual(analysis.confidence, 100)
        self.assertIn(analysis.severity, {"low", "medium", "high", "critical"})

    def test_brute_force_requires_human_approval_for_block(self):
        event = SecurityEvent(
            event_type="auth_failure",
            entity={"ip": "192.168.1.50"},
            data={"authentication": {"failed_login_count": 37}},
            severity="high",
        )
        analysis = vrindha_ai.analyze(event)
        self.assertIn("block_ip", analysis.recommended_action)
        self.assertTrue(analysis.human_approval_required)
        self.assertIn("REQUIRED", render_report(analysis))
        # The analyzer must not have executed anything — no blocked IP was added
        # by the analysis itself.
        from vrin_SOC.database.db import get_blocked_ips

        self.assertNotIn("192.168.1.50", [ip["ip"] for ip in get_blocked_ips()])


class StructuredOutputTests(unittest.TestCase):
    def test_report_follows_contract_format(self):
        event = SecurityEvent(
            event_type="network_event",
            entity={"ip": "203.0.113.9"},
            data={"network": {"outbound": {"ip": "203.0.113.9", "port": 4444}}},
            severity="medium",
        )
        analysis = vrindha_ai.analyze(event)
        report = render_report(analysis)

        sections = [
            "[SECURITY ANALYSIS]",
            "Event:",
            "FACTS:",
            "EVIDENCE:",
            "DETECTION:",
            "ASSESSMENT:",
            "RISK SCORE:",
            "CONFIDENCE:",
            "THREAT INTELLIGENCE:",
            "UNKNOWN INFORMATION:",
            "RECOMMENDED ACTION:",
            "HUMAN APPROVAL:",
            "REASON:",
        ]
        positions = []
        for section in sections:
            self.assertIn(section + "\n", report)
            positions.append(report.index(section + "\n"))
        # Sections appear in the contract's order.
        self.assertEqual(positions, sorted(positions))
        self.assertIn("NOT CONFIRMED", report)
        self.assertRegex(report, r"RISK SCORE:\n(100|[0-9]{1,2})\n")
        self.assertRegex(report, r"CONFIDENCE:\n(100|[0-9]{1,2})\n")

    def test_findings_separate_fact_from_inference(self):
        event = SecurityEvent(
            event_type="auth_failure",
            entity={"ip": "10.0.0.7"},
            data={"authentication": {"failed_login_count": 12}},
            severity="medium",
        )
        analysis = vrindha_ai.analyze(event)
        self.assertTrue(analysis.findings)
        for finding in analysis.findings:
            self.assertTrue(finding.fact)
            self.assertTrue(finding.evidence)
            self.assertTrue(finding.inference)
        auth = next(f for f in analysis.findings if "failed authentication attempt" in f.fact)
        # The inference is explicitly hedged, never a confirmed-fact claim.
        self.assertIn("possible brute-force", auth.inference.lower())
        # The unknowns are stated, not silently dropped.
        self.assertTrue(auth.unknown)


class ThreatIntelVerificationTests(unittest.TestCase):
    def test_confirmed_when_sourced_fresh_record_matches(self):
        event = SecurityEvent(
            event_type="network_event",
            entity={"ip": "203.0.113.9"},
            data={"network": {"source_ips": ["203.0.113.9"]}},
            threat_intelligence={
                "mode": "real",
                "checked_at": _now(),
                "malicious_found": True,
                "indicators": [{
                    "indicator": "203.0.113.9",
                    "type": "ipv4",
                    "found": True,
                    "malicious": True,
                    "sources": ["misp", "cisa-kev"],
                    "threat_score": 88,
                    "last_seen": _now(),
                }],
            },
            severity="high",
        )
        analysis = vrindha_ai.analyze(event)
        self.assertEqual(analysis.threat_intelligence, ThreatIntelStatus.CONFIRMED)
        self.assertEqual(analysis.ti_detail["verified_sources"], ["cisa-kev", "misp"])
        self.assertIn("verified malicious", analysis.assessment)
        # A confirmed TI record must push risk into the high range.
        self.assertGreaterEqual(analysis.risk_score, 85)

    def test_unsourced_record_never_creates_reputation(self):
        event = SecurityEvent(
            event_type="network_event",
            entity={"ip": "203.0.113.44"},
            data={"network": {"source_ips": ["203.0.113.44"]}},
            threat_intelligence={
                "mode": "real",
                "checked_at": _now(),
                "indicators": [{
                    "indicator": "203.0.113.44",
                    "found": True,
                    "malicious": True,
                    "sources": [],  # no verified source
                }],
            },
            severity="high",
        )
        analysis = vrindha_ai.analyze(event)
        self.assertEqual(analysis.threat_intelligence, ThreatIntelStatus.NOT_CONFIRMED)
        self.assertIn("no verified source", analysis.ti_detail["reason"].lower())

    def test_stale_record_is_not_confirmed(self):
        event = SecurityEvent(
            event_type="network_event",
            entity={"ip": "203.0.113.51"},
            data={"network": {"source_ips": ["203.0.113.51"]}},
            timestamp=_now(),
            threat_intelligence={
                "mode": "real",
                "checked_at": _now(),
                "indicators": [{
                    "indicator": "203.0.113.51",
                    "found": True,
                    "malicious": True,
                    "sources": ["misp"],
                    "last_seen": (datetime.now(timezone.utc) - timedelta(days=400)).isoformat(),
                }],
            },
            severity="high",
        )
        analysis = vrindha_ai.analyze(event)
        self.assertEqual(analysis.threat_intelligence, ThreatIntelStatus.NOT_CONFIRMED)
        self.assertTrue(analysis.ti_detail["stale"])
        self.assertIn("stale", analysis.ti_detail["reason"])

    def test_unavailable_service_is_unknown_not_clean(self):
        event = SecurityEvent(
            event_type="network_event",
            entity={"ip": "203.0.113.50"},
            data={"network": {"outbound": {"ip": "203.0.113.50", "port": 5555}}},
            threat_intelligence={
                "mode": "unavailable",
                "status": "unavailable",
                "degraded": True,
                "found": None,
            },
            severity="medium",
        )
        analysis = vrindha_ai.analyze(event)
        self.assertEqual(analysis.threat_intelligence, ThreatIntelStatus.UNKNOWN)
        self.assertIn("unavailable", analysis.ti_detail["reason"])
        self.assertIn(
            "absence of evidence is not treated as clean",
            analysis.assessment,
        )


class UncertaintyTests(unittest.TestCase):
    def test_insufficient_evidence_uses_exact_phrase(self):
        event = SecurityEvent(
            event_type="security_event",
            entity={"ip": "10.1.2.3"},
            data={},
            severity="low",
        )
        analysis = vrindha_ai.analyze(event)
        self.assertTrue(analysis.insufficient_evidence)
        self.assertIn(INSUFFICIENT_EVIDENCE_PHRASE, analysis.assessment)
        self.assertLessEqual(analysis.risk_score, 35)
        self.assertIn("collect_more_evidence", analysis.recommended_action)
        self.assertFalse(analysis.human_approval_required)

    def test_conflicting_evidence_lowers_confidence_and_caps_conclusion(self):
        base = {
            "event_type": "auth_failure",
            "entity": {"ip": "198.51.100.20"},
            "data": {"authentication": {"failed_login_count": 25}},
            "severity": "high",
        }
        clean = vrindha_ai.analyze(SecurityEvent(**base))

        conflicted = vrindha_ai.analyze(SecurityEvent(
            **base,
            threat_intelligence={
                "mode": "real",
                "checked_at": _now(),
                "indicators": [{
                    "indicator": "198.51.100.20",
                    "found": True,
                    "malicious": False,  # whitelisted
                    "sources": ["internal-whitelist"],
                }],
            },
        ))
        self.assertTrue(conflicted.evidence_conflicting)
        self.assertFalse(clean.evidence_conflicting)
        self.assertLess(conflicted.confidence, clean.confidence)
        self.assertIn(CONFLICT_PHRASE, conflicted.assessment)
        self.assertIn(SUSPICIOUS_NOT_CONCLUSIVE_PHRASE, conflicted.assessment)
        self.assertIn(ATTRIBUTION_UNVERIFIED_PHRASE, conflicted.assessment)
        self.assertLessEqual(conflicted.risk_score, 65)

    def test_conflict_flag_in_data_is_honored(self):
        event = SecurityEvent(
            event_type="security_event",
            entity={"ip": "10.9.8.7"},
            data={
                "authentication": {"failed_login_count": 20},
                "network": {"outbound": {"ip": "10.9.8.7", "port": 4444}},
                "conflicting_evidence": True,
            },
            severity="high",
        )
        analysis = vrindha_ai.analyze(event)
        self.assertTrue(analysis.evidence_conflicting)
        self.assertIn(CONFLICT_PHRASE, analysis.assessment)


class CorroborationTests(unittest.TestCase):
    def test_multi_source_evidence_raises_confidence_over_single_source(self):
        single = SecurityEvent(
            event_type="auth_failure",
            entity={"ip": "10.5.5.5", "host": "host-a"},
            data={"authentication": {"failed_login_count": 20}},
            severity="medium",
        )
        multi = SecurityEvent(
            event_type="auth_failure",
            entity={"ip": "10.5.5.5", "host": "host-a"},
            data={
                "authentication": {"failed_login_count": 20},
                "network": {"outbound": {"ip": "203.0.113.77", "port": 4444}},
                "historical_alerts": 3,
            },
            correlation={"related_count": 2, "related_events": ["evt-a", "evt-b"]},
            analysis={"anomaly": {"anomaly_score": 0.8, "is_anomaly": True,
                                  "model": "zscore", "model_version": "v1"}},
            severity="high",
        )
        a_single = vrindha_ai.analyze(single)
        a_multi = vrindha_ai.analyze(multi)
        self.assertGreater(a_multi.confidence, a_single.confidence)
        self.assertGreaterEqual(a_multi.risk_score, a_single.risk_score)
        # The independent layers are visible in the explainable signal list.
        layers = {s["layer"] for s in a_multi.signals}
        self.assertLessEqual(
            {"authentication_behavior", "network_behavior", "correlation",
             "anomaly_detection"},
            layers,
        )

    def test_missing_evidence_is_listed_in_unknown_information(self):
        event = SecurityEvent(
            event_type="security_event",
            entity={"ip": "10.2.2.2"},
            data={},
            severity="low",
        )
        analysis = vrindha_ai.analyze(event)
        joined = " ".join(analysis.unknown_information)
        self.assertIn("No verified threat-intelligence record", joined)
        self.assertIn("No anomaly", joined)
        self.assertIn("No correlated events", joined)


class HumanInTheLoopTests(unittest.TestCase):
    def test_high_risk_block_recommendation_requires_human_approval(self):
        event = SecurityEvent(
            event_type="auth_failure",
            entity={"ip": "203.0.113.88"},
            data={"authentication": {"failed_login_count": 30}},
            severity="high",
        )
        analysis = vrindha_ai.analyze(event)
        self.assertIn("block_ip", analysis.recommended_action)
        self.assertTrue(analysis.human_approval_required)
        self.assertIn("REQUIRED", render_report(analysis))
        self.assertIn("REASON", render_report(analysis))

    def test_low_risk_monitoring_does_not_require_approval(self):
        # Two independent, low-strength signals ⇒ not "insufficient" but risk
        # stays below the 40 threshold ⇒ monitoring only, no approval needed.
        event = SecurityEvent(
            event_type="security_event",
            entity={"ip": "10.3.3.3"},
            data={"authentication": {"failed_login_count": 2}, "historical_alerts": 1},
            severity="low",
        )
        analysis = vrindha_ai.analyze(event)
        self.assertIn("continue_monitoring", analysis.recommended_action)
        self.assertFalse(analysis.human_approval_required)
        self.assertIn("NOT REQUIRED", render_report(analysis))

    def test_low_confidence_with_medium_risk_requests_human_verification(self):
        # Conflicting evidence (whitelisted TI vs. strong local signal) drives
        # confidence below 50 while risk stays medium ⇒ rule 11 applies.
        event = SecurityEvent(
            event_type="auth_failure",
            entity={"ip": "203.0.113.66"},
            data={"authentication": {"failed_login_count": 15}},
            threat_intelligence={
                "mode": "real",
                "checked_at": _now(),
                "indicators": [{
                    "indicator": "203.0.113.66",
                    "found": True,
                    "malicious": False,  # whitelisted
                    "sources": ["internal-whitelist"],
                }],
            },
            severity="medium",
        )
        analysis = vrindha_ai.analyze(event)
        self.assertLess(analysis.confidence, 50)
        self.assertGreaterEqual(analysis.risk_score, 40)
        self.assertTrue(analysis.human_approval_required)
        self.assertIn(HUMAN_VERIFICATION_PHRASE.lower(), analysis.reason.lower())


class ClaimGuardTests(unittest.TestCase):
    def test_forbidden_claims_stripped_without_ti(self):
        text = ("The host is part of a ransomware campaign and will attack again. "
                "Risk is high and data was exfiltrated. Continue monitoring.")
        sanitized, triggered = enforce_claim_guard(text, ThreatIntelStatus.NOT_CONFIRMED)
        self.assertTrue(triggered)
        self.assertNotIn("ransomware campaign", sanitized)
        self.assertNotIn("exfiltrated", sanitized)
        self.assertIn("Continue monitoring.", sanitized)

    def test_claims_pass_when_ti_confirmed(self):
        text = "The host is part of a ransomware campaign."
        sanitized, triggered = enforce_claim_guard(text, ThreatIntelStatus.CONFIRMED)
        self.assertFalse(triggered)
        self.assertEqual(sanitized, text)

    def test_guard_accepts_string_status(self):
        sanitized, triggered = enforce_claim_guard("Definitely malicious.", "unknown")
        self.assertTrue(triggered)
        self.assertIn(ATTRIBUTION_UNVERIFIED_PHRASE, sanitized)


class AuditabilityTests(unittest.TestCase):
    def test_audit_record_preserves_all_contract_fields(self):
        event = SecurityEvent(
            event_type="auth_failure",
            entity={"ip": "192.168.77.7"},
            data={"authentication": {"failed_login_count": 15}},
            severity="medium",
        )
        analysis = vrindha_ai.analyze(event)
        record = vrindha_ai.get_audit(analysis.analysis_id)
        self.assertIsNotNone(record)
        for field in (
            "analysis_id", "timestamp", "raw_evidence", "tools_used", "ti_sources",
            "rules_triggered", "correlation_results", "ai_assessment", "risk_score",
            "confidence", "recommended_action", "human_decision", "final_action",
            "severity", "threat_intelligence", "report",
        ):
            self.assertIn(field, record)
        self.assertEqual(record["event_id"], event.event_id)
        self.assertEqual(record["risk_score"], analysis.risk_score)
        self.assertEqual(record["confidence"], analysis.confidence)
        self.assertEqual(record["ai_assessment"], analysis.assessment)
        self.assertIn("[SECURITY ANALYSIS]", record["report"])
        self.assertEqual(record["human_decision"], None)
        self.assertEqual(record["final_action"], None)
        # Raw evidence must let a reviewer reconstruct the input.
        self.assertEqual(record["raw_evidence"]["data"], event.data)

    def test_get_audit_returns_none_for_unknown_id(self):
        self.assertIsNone(vrindha_ai.get_audit("ana-nope000000"))

    def test_list_audit_returns_records(self):
        result = vrindha_ai.list_audit(limit=5)
        self.assertEqual(result["status"], "success")
        self.assertGreaterEqual(result["count"], 1)


class FeedbackLoopTests(unittest.TestCase):
    def _fresh_analysis(self) -> str:
        event = SecurityEvent(
            event_type="auth_failure",
            entity={"ip": "10.40.40.40"},
            data={"authentication": {"failed_login_count": 8}},
            severity="medium",
        )
        return vrindha_ai.analyze(event).analysis_id

    def test_feedback_updates_human_decision_and_final_action(self):
        analysis_id = self._fresh_analysis()
        result = vrindha_ai.record_feedback(
            analysis_id, analyst="analyst-alpha",
            decision="true_positive", notes="confirmed in SIEM",
        )
        self.assertEqual(result["status"], "success")
        record = vrindha_ai.get_audit(analysis_id)
        self.assertEqual(record["human_decision"], "true_positive")
        self.assertTrue(record["final_action"])

    def test_feedback_is_append_only(self):
        analysis_id = self._fresh_analysis()
        vrindha_ai.record_feedback(analysis_id, "analyst-1", "unknown")
        vrindha_ai.record_feedback(analysis_id, "analyst-2", "false_positive")
        feedback = vrindha_ai.list_feedback(limit=200)
        rows = [f for f in feedback["feedback"] if f["analysis_id"] == analysis_id]
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["analyst"] for r in rows}, {"analyst-1", "analyst-2"})

    def test_feedback_rejects_invalid_decision_and_missing_analyst(self):
        analysis_id = self._fresh_analysis()
        bad = vrindha_ai.record_feedback(analysis_id, "analyst-1", "malicious")
        self.assertEqual(bad["status"], "error")
        no_analyst = vrindha_ai.record_feedback(analysis_id, "", "unknown")
        self.assertEqual(no_analyst["status"], "error")

    def test_feedback_rejects_unknown_analysis(self):
        result = vrindha_ai.record_feedback("ana-doesnotexist", "analyst-1", "unknown")
        self.assertEqual(result["status"], "error")


class DataModeHonestyTests(unittest.TestCase):
    def test_simulated_data_is_labeled_not_presented_as_real(self):
        event = SecurityEvent(
            event_type="security_event",
            entity={"ip": "10.70.70.70"},
            data={"authentication": {"failed_login_count": 12}, "SIMULATION": True},
            severity="high",
            provenance={"mode": "simulated", "source": "synthetic_generator"},
        )
        analysis = vrindha_ai.analyze(event)
        self.assertEqual(analysis.mode.value, "simulated")
        self.assertIn("SIMULATED", render_report(analysis))
        self.assertIn("not live telemetry", analysis.assessment)


class PipelineIntegrationTests(unittest.TestCase):
    """The analysis engine consumes events produced by the real pipeline
    (Data Science ingest → Threat Intel enrichment → DS analysis) and must
    stay honest about whatever TI state the enrichment resolved to."""

    def test_analyzes_pipeline_enriched_event(self):
        from vrin_SOC.coordination.data_science_ai import data_science_ai
        from vrin_SOC.coordination.threat_intel_ai import threat_intel_ai

        payload = {
            "event_type": "auth_failure",
            "correlation_id": f"corr-evidence-{datetime.now(timezone.utc).timestamp()}",
            "entity": {"ip": "203.0.113.99", "host": "pipe-host-1"},
            "data": {
                "authentication": {"failed_login_count": 9},
                "network": {"source_ips": ["203.0.113.99"]},
            },
            "severity": "high",
        }
        event, quality = data_science_ai.ingest(payload)
        self.assertIsNotNone(event, msg=str(quality.issues))

        threat_intel_ai.enrich(event)  # never fabricated; degrades to local DB
        data_science_ai.analyze(event)

        analysis = vrindha_ai.analyze(event)
        self.assertIsInstance(analysis, SecurityAnalysis)
        # TI was verified by the enrichment step — whatever honest state it
        # resolved to must be one of the three contract states.
        self.assertIn(analysis.threat_intelligence, set(ThreatIntelStatus))
        self.assertTrue(analysis.ti_detail.get("checked"),
                        "enrichment must have marked TI as checked")
        report = render_report(analysis)
        self.assertIn("[SECURITY ANALYSIS]", report)
        self.assertIn("THREAT INTELLIGENCE:\n", report)

        # Auditability: the persisted row ties the analysis to the event.
        record = vrindha_ai.get_audit(analysis.analysis_id)
        self.assertEqual(record["event_id"], event.event_id)
        self.assertIn("Threat Intelligence", " ".join(record["tools_used"]))


class EvidenceAnalysisAPITests(unittest.TestCase):
    """REST endpoints for the anti-hallucination analysis layer."""

    @classmethod
    def setUpClass(cls):
        from fastapi.testclient import TestClient
        from vrin_SOC.api import main as api_main

        cls.client = TestClient(api_main.app)

    def setUp(self):
        import tempfile
        from pathlib import Path

        from vrin_SOC.api import deps as api_deps
        from vrin_SOC.api import main as api_main
        from vrin_SOC.api.auth import AuthModule

        self._tmpdir = tempfile.TemporaryDirectory()
        self.auth = AuthModule(Path(self._tmpdir.name) / "users.json", "t" * 48)
        self._original_deps_auth = api_deps.auth_module
        self._original_main_auth = api_main.auth_module
        api_deps.auth_module = self.auth
        api_main.auth_module = self.auth
        self.token = None

    def tearDown(self):
        from vrin_SOC.api import deps as api_deps
        from vrin_SOC.api import main as api_main

        api_deps.auth_module = self._original_deps_auth
        api_main.auth_module = self._original_main_auth
        self._tmpdir.cleanup()

    def _bootstrap(self) -> str:
        response = self.client.post(
            "/register",
            json={"username": "admin", "password": "correct-horse-battery-staple-42"},
        )
        self.assertEqual(response.status_code, 201)
        return response.json()["access_token"]

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"}

    def test_endpoints_require_authentication(self):
        for endpoint in ("/analysis/prompt", "/analysis/audit", "/analysis/feedback"):
            response = self.client.get(endpoint)
            self.assertEqual(response.status_code, 401)

    def test_prompt_endpoint_serves_verbatim_contract(self):
        self.token = self._bootstrap()
        response = self.client.get("/analysis/prompt", headers=self._headers())
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["agent"], "VrindhaAI")
        self.assertIn("Never invent, assume, or fabricate", body["prompt"])

    def test_security_analysis_endpoint_roundtrip(self):
        self.token = self._bootstrap()
        payload = {
            "event_type": "auth_failure",
            "entity": {"ip": "192.168.1.50"},
            "data": {"authentication": {"failed_login_count": 37, "service": "ssh"}},
            "severity": "high",
        }
        response = self.client.post("/analysis/security", headers=self._headers(), json=payload)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "success")
        self.assertTrue(body["analysis_id"].startswith("ana-"))
        self.assertIn("[SECURITY ANALYSIS]", body["report"])
        self.assertEqual(body["analysis"]["threat_intelligence"], "not_confirmed")

        # Auditability: the exact record is retrievable.
        record = self.client.get(f"/analysis/{body['analysis_id']}", headers=self._headers())
        self.assertEqual(record.status_code, 200)
        self.assertEqual(record.json()["analysis_id"], body["analysis_id"])

        missing = self.client.get("/analysis/ana-doesnotexist", headers=self._headers())
        self.assertEqual(missing.status_code, 404)

    def test_feedback_endpoint_records_analyst_decision(self):
        self.token = self._bootstrap()
        created = self.client.post(
            "/analysis/security",
            headers=self._headers(),
            json={"event_type": "security_event", "entity": {"ip": "10.6.6.6"},
                  "data": {"authentication": {"failed_login_count": 4}}},
        )
        analysis_id = created.json()["analysis_id"]

        good = self.client.post(
            f"/analysis/{analysis_id}/feedback",
            headers=self._headers(),
            json={"analyst": "api-analyst", "decision": "false_positive",
                  "notes": "internal change window"},
        )
        self.assertEqual(good.status_code, 200)
        self.assertEqual(good.json()["decision"], "false_positive")

        bad = self.client.post(
            f"/analysis/{analysis_id}/feedback",
            headers=self._headers(),
            json={"analyst": "api-analyst", "decision": "malicious"},
        )
        self.assertEqual(bad.status_code, 422)

        feedback = self.client.get("/analysis/feedback", headers=self._headers())
        self.assertEqual(feedback.status_code, 200)
        self.assertTrue(
            any(f["analysis_id"] == analysis_id and f["decision"] == "false_positive"
                for f in feedback.json()["feedback"])
        )
        audit = self.client.get("/analysis/audit", headers=self._headers())
        self.assertEqual(audit.status_code, 200)
        self.assertTrue(
            any(r["analysis_id"] == analysis_id for r in audit.json()["records"])
        )


if __name__ == "__main__":
    unittest.main()
