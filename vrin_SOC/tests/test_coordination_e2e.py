"""End-to-end test of the safe demonstration scenario (spec §39):

suspicious event → Infrastructure AI → Commander → Threat Intelligence →
Data Science → SOC Analyst → Risk → Ethics → Human approval → defensive
response → Knowledge → Data Science feedback.

Every payload is synthetic and labeled SIMULATION.
"""
from __future__ import annotations

import unittest

from vrin_SOC.coordination.commander import commander_ai
from vrin_SOC.coordination.demo import run_demonstration
from vrin_SOC.coordination.data_science_ai import data_science_ai
from vrin_SOC.coordination.knowledge_ai import knowledge_ai


class EndToEndDemoTests(unittest.TestCase):
    def test_full_scenario_reaches_human_approval_and_response(self):
        result = run_demonstration(approver="e2e-test-human")
        self.assertEqual(result["status"], "success")
        self.assertTrue(result["SIMULATION"])
        self.assertTrue(result["simulation_note"])

        # Stage ordering: two pipeline runs (two correlated events), then the
        # human approval, then model evaluation after feedback.
        stages = [s["stage"] for s in result["stages"]]
        self.assertIn("pipeline", stages)
        self.assertIn("human_approval", stages)
        self.assertIn("model_evaluation_after_feedback", stages)

        # One shared incident across both correlated events.
        incident_ids = {s["result"]["incident_id"] for s in result["stages"]
                        if s["stage"] == "pipeline"}
        self.assertEqual(len(incident_ids), 1)
        incident_id = incident_ids.pop()
        self.assertEqual(result["incident_id"], incident_id)

        # The approval gate existed (high-impact action proposed + ethics passed).
        pipeline_results = [s["result"] for s in result["stages"] if s["stage"] == "pipeline"]
        self.assertTrue(any(r.get("status") == "awaiting_approval" for r in pipeline_results))
        awaiting = next(r for r in pipeline_results if r.get("status") == "awaiting_approval")
        # Controlled autonomy: the SOC recommended block_ip, the response
        # engine proposes the reversible, time-limited alternative and keeps
        # the original recommendation visible (reversibility first).
        proposed = awaiting["proposed_action"]
        self.assertEqual(proposed["original_action"], "block_ip")
        self.assertEqual(proposed["action"], "temporary_ip_restriction")
        self.assertIn(proposed["autonomy_level"], {"LEVEL 2", "LEVEL 3"})
        self.assertEqual(proposed["execution"], "HUMAN APPROVAL")
        self.assertTrue(proposed["rollback_available"])
        self.assertIn("[VRINDHA RESPONSE]", awaiting["vrindha_response"])
        self.assertIn("ACTION PREVIEW", awaiting["action_preview"])
        self.assertIsNotNone(awaiting.get("ethics"))

        # Human approval recorded with an approver identity (accountability).
        approval = next(s["result"] for s in result["stages"] if s["stage"] == "human_approval")
        self.assertEqual(approval["status"], "success")
        self.assertEqual(approval["approved_by"], "e2e-test-human")

        # Authorized defensive response executed (sandbox: simulated firewall)
        # through the controlled-response engine, with a rollback record and
        # an expiry (time-limited temporary action).
        response = approval["response_result"]
        self.assertEqual(response["action"], "temporary_ip_restriction")
        self.assertEqual(response["original_action"], "block_ip")
        self.assertIn(response["status"], {"success", "simulated"})
        self.assertIsNotNone(response["rollback_id"])
        self.assertIsNotNone(response["expires_at"])
        self.assertEqual(approval["rollback_ids"], [response["rollback_id"]])

        # Final incident closed with the knowledge link.
        final = result["final_incident"]
        self.assertEqual(final["status"], "closed")
        self.assertEqual(final["approved_by"], "e2e-test-human")
        self.assertIsNotNone(final.get("knowledge_id"))

        # Incident trace is fully reconstructable (auditability, spec §23).
        stage_names = [t["stage"] for t in final["trace"]]
        for expected in ("ingest", "threat_intelligence", "data_science",
                         "soc_investigation", "ethics", "controlled_response",
                         "human_approval", "authorized_response"):
            self.assertIn(expected, stage_names)

    def test_feedback_loop_reaches_data_science_evaluation(self):
        result = run_demonstration(approver="e2e-feedback-human")
        evaluation = next(s["result"] for s in result["stages"]
                          if s["stage"] == "model_evaluation_after_feedback")
        # After validated outcomes exist, evaluation must produce real metrics
        # (or explicitly say why it cannot) — never invented numbers.
        self.assertIn(evaluation["status"], {"ok", "insufficient_data"})
        if evaluation["status"] == "ok":
            self.assertGreaterEqual(evaluation["metrics"]["labeled_samples"], 2)

    def test_knowledge_lesson_stored_and_searchable(self):
        result = run_demonstration(approver="e2e-knowledge-human")
        lesson_id = result["final_incident"]["knowledge_id"]
        self.assertTrue(lesson_id.startswith("lesson-"))
        lessons = knowledge_ai.lessons(limit=10)
        self.assertTrue(any(l["lesson_id"] == lesson_id for l in lessons["lessons"]))

    def test_reject_path_closes_without_response(self):
        # Drive the pipeline to awaiting_approval, then reject instead of approve.
        from vrin_SOC.coordination.demo import build_demo_payloads

        payloads = build_demo_payloads()
        incident_id = None
        for payload in payloads:
            out = commander_ai.handle_event(payload)
            if out.get("incident_id"):
                incident_id = out["incident_id"]
        rejection = commander_ai.reject(incident_id, approver="e2e-rejector",
                                        reason="confirmed internal lab activity")
        self.assertEqual(rejection["status"], "success")
        final = commander_ai.incident(incident_id)
        self.assertEqual(final.status.value, "rejected")
        self.assertIsNone(final.response_result)

    def test_simulation_label_present_on_demo_events(self):
        from vrin_SOC.coordination.demo import build_demo_payloads

        for payload in build_demo_payloads():
            self.assertTrue(payload["data"]["SIMULATION"])
            self.assertEqual(payload["provenance"]["mode"], "simulated")

    def test_duplicate_rejection_recorded_not_silent(self):
        from vrin_SOC.coordination.demo import build_demo_payloads

        payload = build_demo_payloads()[0]
        first = commander_ai.handle_event(dict(payload))
        self.assertIn(first["status"], {"awaiting_approval", "open_monitoring", "closed_monitoring"})
        second = commander_ai.handle_event(dict(payload))  # identical content → duplicate
        self.assertEqual(second["status"], "rejected")
        self.assertIn("duplicate", second["reason"])


if __name__ == "__main__":
    unittest.main()
