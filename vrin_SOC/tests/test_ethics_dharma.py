"""Unit tests for the Ethics & Compliance AI (Dharma recognition, verified
Gita knowledge base, decision matrix, teach mode, audit log, no user scoring)."""
from __future__ import annotations

import unittest

from vrin_SOC.coordination.ethics_ai import (
    CONCEPT_VERSE_REFERENCES,
    DharmaRecognitionEngine,
    EthicsAI,
    gita_knowledge_base,
    ethics_ai,
)
from vrin_SOC.coordination.schemas import EthicsClassification, EthicsDecision


class GitaKnowledgeBaseTests(unittest.TestCase):
    def test_all_18_chapters_loaded_from_stored_dataset(self):
        self.assertEqual(len(gita_knowledge_base.chapters), 18)
        self.assertGreaterEqual(len(gita_knowledge_base.verses), 700)
        names = {c["chapter"]: c["name"] for c in gita_knowledge_base.chapter_index()}
        self.assertEqual(names[2], "Sankhya Yoga")
        self.assertEqual(names[18], "Moksha Sannyasa Yoga")

    def test_spec_cited_references_all_verified(self):
        """Every verse the plan cites must exist in the stored dataset."""
        for concept, (chapter, verse, _why) in CONCEPT_VERSE_REFERENCES.items():
            record = gita_knowledge_base.reference(chapter, verse)
            self.assertIsNotNone(
                record, f"concept {concept} references {chapter}.{verse} which is not in the stored dataset"
            )
            self.assertTrue(record["verified"])
            self.assertTrue(record["sanskrit"])
            # Stored dataset keeps the English text in translation and/or meaning.
            self.assertTrue(record["translation"] or record["meaning"])

    def test_fabricated_verse_never_served(self):
        self.assertIsNone(gita_knowledge_base.reference(18, 999))
        self.assertIsNone(gita_knowledge_base.reference(99, 1))

    def test_search_returns_only_stored_verses(self):
        results = gita_knowledge_base.search("duty action", limit=3)
        for record in results:
            self.assertIn((record["chapter"], record["verse"]), gita_knowledge_base.verses)


class DharmaRecognitionTests(unittest.TestCase):
    def setUp(self):
        self.engine = DharmaRecognitionEngine()

    def test_authorized_pentest_is_aligned(self):
        result = self.engine.classify("authorized penetration test of my lab system", "provided")
        self.assertEqual(result["classification"], EthicsClassification.DHARMA_ALIGNED)

    def test_credential_theft_is_high_risk_adharma(self):
        result = self.engine.classify("break into this account and steal the data", "missing")
        self.assertEqual(result["classification"], EthicsClassification.HIGH_RISK_ADHARMA)
        self.assertIn("ASTEYA", result["principles"])

    def test_unknown_target_scan_requires_authorization(self):
        result = self.engine.classify("scan this unknown public target for vulnerabilities", "missing")
        self.assertEqual(result["classification"], EthicsClassification.POTENTIAL_ADHARMA)

    def test_defensive_monitoring_is_aligned(self):
        result = self.engine.classify("monitor my server for intrusions", "missing")
        self.assertEqual(result["classification"], EthicsClassification.DHARMA_ALIGNED)

    def test_destruction_is_high_risk_regardless_of_auth(self):
        result = self.engine.classify("delete all customer backups", "provided")
        self.assertEqual(result["classification"], EthicsClassification.HIGH_RISK_ADHARMA)

    def test_substring_cannot_falsify(self):
        # "listen" must not trigger "steal"-family patterns; "crackdown" is not "crack".
        result = self.engine.classify("listen to system logs for anomalies", "missing")
        self.assertIn(result["classification"],
                      {EthicsClassification.ETHICALLY_NEUTRAL, EthicsClassification.DHARMA_ALIGNED})


class EthicsDecisionMatrixTests(unittest.TestCase):
    def test_deny_with_alternative_and_principles(self):
        assessment = ethics_ai.evaluate("steal the customer data and exfiltrate it",
                                        authorization_status="missing")
        self.assertEqual(assessment.decision, EthicsDecision.DENY)
        self.assertEqual(assessment.classification, EthicsClassification.HIGH_RISK_ADHARMA)
        self.assertTrue(assessment.principles)
        self.assertIsNotNone(assessment.alternative)
        joined = " ".join(assessment.legal_references)
        self.assertIn("Information Technology Act 2000", joined)
        # Legal references are labeled guidance, not advice.
        self.assertIn("not legal advice", assessment.legal_note.lower())

    def test_gita_reference_is_verified_when_present(self):
        assessment = ethics_ai.evaluate("steal the customer data and exfiltrate it",
                                        authorization_status="missing")
        if assessment.gita_reference:
            self.assertTrue(assessment.gita_reference["verified"])
            chapter = int(assessment.gita_reference["reference"].split()[2].split(".")[0])
            verse = int(assessment.gita_reference["reference"].split(".")[1])
            self.assertIsNotNone(gita_knowledge_base.reference(chapter, verse))

    def test_gita_guidance_is_optional_never_coercive(self):
        assessment = ethics_ai.evaluate("monitor my server for intrusions",
                                        authorization_status="provided",
                                        request_gita_guidance=False)
        self.assertIsNone(assessment.gita_reference)

    def test_no_user_moral_scoring_exists(self):
        assessment = ethics_ai.evaluate("scan this unknown public target for vulnerabilities",
                                        authorization_status="missing")
        dumped = assessment.model_dump()
        for forbidden in ("user_score", "user_dharma_score", "moral_ranking", "user_label"):
            self.assertNotIn(forbidden, dumped)
        # Judge the action: the wording never labels the user.
        self.assertNotIn("You are an Adharmi", assessment.reason)

    def test_high_impact_defense_requires_human_approval(self):
        assessment = ethics_ai.evaluate("block ip 45.33.32.156", context={"authorized": True},
                                        authorization_status="provided")
        self.assertTrue(assessment.human_approval_required)
        self.assertEqual(assessment.decision, EthicsDecision.ALLOW_WITH_WARNING)

    def test_ambiguous_context_asks_for_authorization_not_accusation(self):
        assessment = ethics_ai.evaluate("run a vulnerability scan on this target",
                                        target="10.0.0.9", authorization_status="missing")
        self.assertEqual(assessment.decision, EthicsDecision.REQUIRE_AUTHORIZATION)
        self.assertIn("confirm", (assessment.alternative or "").lower())
        self.assertNotIn("accusation", assessment.reason)

    def test_audit_log_records_every_decision(self):
        ethics_ai.evaluate("break into this account and steal the data", event_id="evt-audit-test",
                           authorization_status="missing")
        after = ethics_ai.audit_log(5)
        self.assertEqual(after["status"], "success")
        self.assertGreaterEqual(after["count"], 1)
        entry = after["entries"][0]  # most recent
        self.assertEqual(entry["event_id"], "evt-audit-test")
        self.assertEqual(entry["decision"], "deny")
        self.assertTrue(entry["requested_action"])


class TeachModeTests(unittest.TestCase):
    def test_teach_explains_instead_of_shaming(self):
        result = ethics_ai.teach("why is unauthorized access adharma")
        self.assertEqual(result["status"], "success")
        explanation = result["explanation"]
        for key in ("intent", "action", "harm", "responsibility", "authorization",
                    "ethical_principle", "legal_security_implication", "practical_alternative"):
            self.assertIn(key, explanation)
        # Educational, not judgmental.
        self.assertIn("not a judgment of any person", result["dharma_note"])
        if explanation["gita_teaching"]:
            self.assertTrue(explanation["gita_teaching"]["verified"])

    def test_teach_handles_arbitrary_topic(self):
        result = ethics_ai.teach("general question about responsible use")
        self.assertEqual(result["status"], "success")


class EthicsAIHealthTests(unittest.TestCase):
    def test_health_reports_gita_knowledge_base(self):
        health = ethics_ai.health()
        self.assertIn("gita_knowledge_base", health)
        self.assertEqual(health["gita_knowledge_base"]["chapters"], 18)
        self.assertEqual(health["status"], "healthy")


if __name__ == "__main__":
    unittest.main()
