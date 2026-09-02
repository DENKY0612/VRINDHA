"""Tests for the Controlled Autonomous Response & Safety engine.

Each test maps to a section of the safety contract (``VRINDHA_RESPONSE_PROMPT``):
three-level autonomy, critical-asset protection, allowlist, reversibility
first, confidence+risk, emergency policy, action preview, rollback, time
limits, anti-chaining, safe mode, audit immutability, review loop and the
``[VRINDHA RESPONSE]`` format.
"""
from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from vrin_SOC.coordination.controlled_response import (
    ACTION_CATALOG,
    VRINDHA_RESPONSE_PROMPT,
    AutonomyPolicy,
    ControlledResponseEngine,
    EmergencyPolicy,
    render_action_preview,
    render_response,
)
from vrin_SOC.coordination.event_bus import EventBus, InMemoryTransport
from vrin_SOC.coordination.schemas import (
    AssetCriticality,
    AutonomyLevel,
    ExecutionMode,
    SecurityEvent,
    ThreatIntelStatus,
)


def _event(ip="203.0.113.77", host="lab-host-01", risk=0.8, confidence=0.8, ti_malicious=False,
           ti_unavailable=False, failed=12, outbound=True, anomaly=True, correlated=2, **data):
    payload = {
        "authentication": {"failed_login_count": failed},
        "network": {"source_ips": [ip], "connection_count": 30},
        **data,
    }
    if outbound:
        payload["network"]["outbound"] = {"ip": ip, "port": 4444}
    event = SecurityEvent(
        event_type="security_event",
        entity={"host": host, "ip": "10.0.0.50"},
        severity="high",
        data=payload,
        risk={"risk_score": risk, "confidence": confidence, "severity": "high"},
        analysis={"anomaly": {"is_anomaly": anomaly, "anomaly_score": 0.9}},
        correlation={"investigation": {"correlated": correlated}},
    )
    if ti_unavailable:
        event.threat_intelligence = {"mode": "unavailable", "status": "unavailable"}
    else:
        event.threat_intelligence = {"malicious_found": ti_malicious, "mode": "real", "status": "success",
                                     "indicators": [{"value": ip, "malicious": ti_malicious}]}
    return event


def _engine(**policy_overrides) -> ControlledResponseEngine:
    raw = {"allowlist": {"trusted_ips": ["127.0.0.1", "198.51.100.9"], "critical_servers": ["dc01"],
                         "internal_networks": ["10.10.0.0/16"]}, **policy_overrides}
    return ControlledResponseEngine(bus=EventBus(InMemoryTransport()), policy=AutonomyPolicy(raw))


class ContractTests(unittest.TestCase):
    def test_prompt_is_served_verbatim_and_complete(self):
        engine = _engine()
        prompt = engine.prompt()
        self.assertEqual(prompt["sections"], 15)
        for phrase in ("Detect → Verify → Assess Risk → Check Policy → Act → Monitor → Roll Back if Necessary",
                       "LEVEL 1 — LOW RISK", "LEVEL 2 — MEDIUM RISK", "LEVEL 3 — HIGH RISK",
                       "Never create your own emergency policy dynamically.", "ACTION PREVIEW", "SAFE MODE",
                       "[VRINDHA RESPONSE]", "Autonomous where safe.", "Human-controlled where dangerous."):
            self.assertIn(phrase, VRINDHA_RESPONSE_PROMPT)
            self.assertIn(phrase, prompt["prompt"])

    def test_catalog_levels_match_contract_examples(self):
        for action in ("collect_logs", "increase_monitoring", "capture_network_metadata", "create_alert",
                       "record_ioc", "read_only_check", "correlated_review"):
            self.assertEqual(ACTION_CATALOG[action]["level"], 1, action)
            self.assertFalse(ACTION_CATALOG[action]["state_change"], action)
        for action in ("rate_limit", "temporary_ip_restriction", "quarantine_file", "restrict_session", "temporary_rule"):
            self.assertEqual(ACTION_CATALOG[action]["level"], 2, action)
            self.assertTrue(ACTION_CATALOG[action]["reversible"], action)
        for action in ("block_ip", "disable_account", "kill_process", "isolate_host",
                       "firewall_policy_change", "delete_file", "shutdown_service"):
            self.assertEqual(ACTION_CATALOG[action]["level"], 3, action)
        self.assertFalse(ACTION_CATALOG["kill_process"]["reversible"])
        self.assertFalse(ACTION_CATALOG["delete_file"]["reversible"])


class AutonomyLevelTests(unittest.TestCase):
    """§2 — LOW → auto-monitor, MEDIUM → recommend→approve, HIGH/CRITICAL → verify → policy → approve."""

    def test_level1_read_only_action_is_automatic(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.3, confidence=0.6), {"action": "investigate_host", "target": "lab-host-01"})
        self.assertEqual(decision.autonomy_level, AutonomyLevel.LEVEL_1)
        self.assertEqual(decision.execution, ExecutionMode.AUTOMATIC)
        self.assertFalse(decision.human_approval_required)
        self.assertFalse(decision.state_change)
        result = engine.execute(decision)
        self.assertEqual(result["status"], "success")
        self.assertFalse(result["state_change"])
        self.assertIsNone(result["rollback_id"])

    def test_low_risk_state_change_is_downgraded_to_monitoring(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.2, confidence=0.9, failed=0, outbound=False, anomaly=False, correlated=0),
                                 {"action": "block_ip", "target": "203.0.113.77"})
        self.assertEqual(decision.recommended_action, "increase_monitoring")
        self.assertEqual(decision.downgraded_from, "block_ip")
        self.assertEqual(decision.autonomy_level, AutonomyLevel.LEVEL_1)
        self.assertIn("auto-monitor", decision.reason)

    def test_medium_risk_recommends_reversible_action_with_human_approval(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.55, confidence=0.8), {"action": "block_ip", "target": "203.0.113.77"})
        self.assertEqual(decision.risk_tier.value, "medium")
        self.assertEqual(decision.recommended_action, "temporary_ip_restriction")
        self.assertEqual(decision.autonomy_level, AutonomyLevel.LEVEL_2)
        self.assertEqual(decision.execution, ExecutionMode.HUMAN_APPROVAL)
        self.assertTrue(decision.human_approval_required)
        self.assertTrue(decision.rollback_available)
        self.assertEqual(decision.duration_minutes, 15)

    def test_level2_never_executes_without_approval(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.55, confidence=0.8), {"action": "block_ip", "target": "203.0.113.77"})
        result = engine.execute(decision)  # no approver
        self.assertEqual(result["status"], "not_executed")
        self.assertIn("human approval required", result["reason"].lower())

    def test_critical_multi_source_keeps_block_at_level3_human_approval(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.92, confidence=0.95, ti_malicious=True),
                                 {"action": "block_ip", "target": "203.0.113.77"})
        self.assertEqual(decision.risk_tier.value, "critical")
        self.assertGreaterEqual(decision.independent_sources, 2)
        self.assertEqual(decision.recommended_action, "block_ip")
        self.assertEqual(decision.autonomy_level, AutonomyLevel.LEVEL_3)
        self.assertEqual(decision.execution, ExecutionMode.HUMAN_APPROVAL)
        self.assertIn("Human approval required before blocking.", decision.reason)

    def test_critical_but_single_source_requires_multi_source_verification(self):
        engine = _engine()
        event = _event(risk=0.9, confidence=0.9, failed=0, outbound=False, anomaly=False, correlated=0,
                       ti_malicious=False)
        event.data["network"] = {}
        decision = engine.decide(event, {"action": "block_ip", "target": "203.0.113.77"})
        self.assertLess(decision.independent_sources, 2)
        self.assertEqual(decision.recommended_action, "temporary_ip_restriction")
        self.assertIn("multi-source verification", decision.reason)

    def test_engine_never_lowers_a_catalog_level(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.95, confidence=0.97, ti_malicious=True),
                                 {"action": "kill_process", "target": "pid:4242"})
        # Irreversible LEVEL 3 with enough sources stays LEVEL 3; never AUTOMATIC.
        self.assertEqual(decision.autonomy_level, AutonomyLevel.LEVEL_3)
        self.assertNotEqual(decision.execution, ExecutionMode.AUTOMATIC)


class CriticalAssetTests(unittest.TestCase):
    """§3 — critical target ⇒ stronger verification, higher confidence, reversible, human approval."""

    def test_private_address_is_high_criticality_and_level3(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.9, confidence=0.95, ti_malicious=True),
                                 {"action": "temporary_ip_restriction", "target": "192.168.1.20"})
        self.assertIn(decision.asset_criticality, {AssetCriticality.HIGH, AssetCriticality.CRITICAL})
        self.assertEqual(decision.autonomy_level, AutonomyLevel.LEVEL_3)
        self.assertTrue(decision.human_approval_required)
        self.assertIn("never blindly block", decision.reason.lower())

    def test_explicit_asset_role_forces_critical(self):
        engine = _engine()
        event = _event(risk=0.9, confidence=0.95, ti_malicious=True, asset_role="domain-controller")
        decision = engine.decide(event, {"action": "isolate_host", "target": "lab-host-01"})
        self.assertEqual(decision.asset_criticality, AssetCriticality.CRITICAL)
        self.assertEqual(decision.autonomy_level, AutonomyLevel.LEVEL_3)
        self.assertEqual(decision.execution, ExecutionMode.HUMAN_APPROVAL)

    def test_hostname_heuristic_is_labeled_as_heuristic(self):
        engine = _engine()
        event = _event(risk=0.9, confidence=0.95, ti_malicious=True, host="prod-db-02")
        decision = engine.decide(event, {"action": "isolate_host", "target": "prod-db-02"})
        self.assertEqual(decision.asset_criticality, AssetCriticality.HIGH)
        self.assertTrue(any("heuristic" in r for r in decision.asset_reasons))

    def test_administrative_account_is_critical(self):
        engine = _engine()
        event = _event(risk=0.9, confidence=0.95, ti_malicious=True)
        event.entity.user = "root"
        decision = engine.decide(event, {"action": "disable_account", "target": "root"})
        self.assertEqual(decision.target_kind, "user")
        self.assertEqual(decision.asset_criticality, AssetCriticality.CRITICAL)
        self.assertEqual(decision.execution, ExecutionMode.BLOCKED)  # also allowlisted


class AllowlistTests(unittest.TestCase):
    """§4 — allowlist conflict ⇒ STOP, HIGH-PRIORITY ALERT, human verification."""

    def test_trusted_ip_is_blocked_with_alert(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.95, confidence=0.97, ti_malicious=True),
                                 {"action": "block_ip", "target": "198.51.100.9"})
        self.assertTrue(decision.allowlist_conflict)
        self.assertEqual(decision.execution, ExecutionMode.BLOCKED)
        self.assertTrue(decision.high_priority_alert)
        self.assertTrue(decision.human_approval_required)
        self.assertIn("Allowlist conflict", decision.reason)
        refused = engine.execute(decision)
        self.assertEqual(refused["status"], "not_executed")

    def test_internal_network_is_allowlisted(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.95, confidence=0.97, ti_malicious=True),
                                 {"action": "temporary_ip_restriction", "target": "10.10.4.4"})
        self.assertTrue(decision.allowlist_conflict)
        self.assertEqual(decision.execution, ExecutionMode.BLOCKED)

    def test_essential_process_is_allowlisted(self):
        engine = _engine()
        event = _event(risk=0.95, confidence=0.97, ti_malicious=True)
        event.entity.process = "sshd"
        decision = engine.decide(event, {"action": "kill_process", "target": "sshd"})
        self.assertEqual(decision.execution, ExecutionMode.BLOCKED)
        self.assertTrue(any("essential" in r for r in decision.asset_reasons))

    def test_human_can_override_allowlist_only_with_justification(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.95, confidence=0.97, ti_malicious=True),
                                 {"action": "block_ip", "target": "198.51.100.9"})
        self.assertEqual(engine.execute(decision, approver="analyst")["status"], "not_executed")
        done = engine.execute(decision, approver="analyst", justification="verified compromised jump host")
        self.assertIn(done["status"], {"success", "simulated"})
        self.assertEqual(done["executed_by"], "analyst")

    def test_read_only_action_on_allowlisted_target_is_not_blocked(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.5, confidence=0.7), {"action": "investigate_host", "target": "dc01"})
        self.assertFalse(decision.allowlist_conflict)
        self.assertEqual(decision.execution, ExecutionMode.AUTOMATIC)

    def test_allowlist_is_only_edited_by_a_human(self):
        engine = _engine()
        self.assertEqual(engine.update_allowlist({"trusted_ips": ["203.0.113.1"]}, by="")["status"], "error")
        result = engine.update_allowlist({"trusted_ips": ["203.0.113.1", "not-an-ip"]}, by="admin")
        self.assertEqual(result["changed"]["trusted_ips"], ["203.0.113.1"])
        decision = engine.decide(_event(risk=0.95, confidence=0.97, ti_malicious=True),
                                 {"action": "block_ip", "target": "203.0.113.1"})
        self.assertEqual(decision.execution, ExecutionMode.BLOCKED)


class ReversibilityTests(unittest.TestCase):
    """§5 — least destructive response first."""

    def test_high_tier_downgrades_block_to_temporary_restriction(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.75, confidence=0.85), {"action": "block_ip", "target": "203.0.113.77"})
        self.assertEqual(decision.risk_tier.value, "high")
        self.assertEqual(decision.original_action, "block_ip")
        self.assertEqual(decision.recommended_action, "temporary_ip_restriction")
        self.assertTrue(decision.reversible)
        self.assertIn("reversibility first", decision.reason)

    def test_irreversible_action_on_critical_asset_is_replaced(self):
        engine = _engine()
        event = _event(risk=0.95, confidence=0.97, ti_malicious=True, asset_criticality="critical")
        decision = engine.decide(event, {"action": "delete_file", "target": "lab-host-01"})
        self.assertEqual(decision.recommended_action, "quarantine_file")
        self.assertEqual(decision.downgraded_from, "delete_file")

    def test_unknown_action_is_never_executed(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.95, confidence=0.97, ti_malicious=True),
                                 {"action": "format_disk", "target": "lab-host-01"})
        self.assertEqual(decision.recommended_action, "increase_monitoring")
        self.assertIn("not in the action catalog", decision.reason)


class EmergencyPolicyTests(unittest.TestCase):
    """§7 — explicit, validated, reversible, time-limited, never dynamic."""

    def _policy(self, **overrides):
        raw = {"name": "c2-temp-restriction", "enabled": True,
               "triggers": {"min_risk": 90, "min_confidence": 90, "min_independent_sources": 3,
                            "require_ti_confirmed": True},
               "allowed_actions": ["temporary_ip_restriction"], "scope": {"target_kinds": ["ip"], "exclude_critical": True},
               "max_duration_minutes": 15}
        raw.update(overrides)
        return raw

    def test_policy_allowing_level3_or_irreversible_is_rejected(self):
        engine = _engine()
        rejected = engine.add_emergency_policy(self._policy(allowed_actions=["block_ip"]), by="admin")
        self.assertEqual(rejected["status"], "rejected")
        self.assertTrue(any("LEVEL 3" in p for p in rejected["problems"]))
        rejected = engine.add_emergency_policy(self._policy(allowed_actions=["kill_process"]), by="admin")
        self.assertEqual(rejected["status"], "rejected")
        rejected = engine.add_emergency_policy(self._policy(max_duration_minutes=0), by="admin")
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(engine.policy.emergency_policies, [])

    def test_matching_policy_allows_temporary_containment_with_rollback_and_expiry(self):
        engine = _engine()
        self.assertEqual(engine.add_emergency_policy(self._policy(), by="admin")["status"], "success")
        decision = engine.decide(_event(risk=0.93, confidence=0.95, ti_malicious=True),
                                 {"action": "temporary_ip_restriction", "target": "203.0.113.77"})
        self.assertEqual(decision.execution, ExecutionMode.AUTOMATIC)
        self.assertEqual(decision.emergency_policy, "c2-temp-restriction")
        self.assertFalse(decision.human_approval_required)
        self.assertLessEqual(decision.duration_minutes, 15)
        result = engine.execute(decision)
        self.assertIn(result["status"], {"success", "simulated"})
        self.assertIsNotNone(result["rollback_id"])
        self.assertIsNotNone(result["expires_at"])
        record = engine.get_rollback(result["rollback_id"])
        self.assertEqual(record.executed_by, "vrindha-automatic")
        self.assertTrue(record.rollback_available)

    def test_emergency_policy_never_automates_block_ip(self):
        engine = _engine()
        engine.add_emergency_policy(self._policy(), by="admin")
        decision = engine.decide(_event(risk=0.93, confidence=0.95, ti_malicious=True),
                                 {"action": "block_ip", "target": "203.0.113.77"})
        self.assertEqual(decision.recommended_action, "block_ip")  # critical + multi-source ⇒ stays
        self.assertEqual(decision.autonomy_level, AutonomyLevel.LEVEL_3)
        self.assertEqual(decision.execution, ExecutionMode.HUMAN_APPROVAL)

    def test_policy_does_not_match_without_confirmed_ti_or_enough_sources(self):
        engine = _engine()
        engine.add_emergency_policy(self._policy(), by="admin")
        decision = engine.decide(_event(risk=0.93, confidence=0.95, ti_malicious=False),
                                 {"action": "temporary_ip_restriction", "target": "203.0.113.77"})
        self.assertEqual(decision.execution, ExecutionMode.HUMAN_APPROVAL)
        self.assertIsNone(decision.emergency_policy)

    def test_disabled_policy_never_matches(self):
        engine = _engine()
        engine.add_emergency_policy(self._policy(enabled=False), by="admin")
        decision = engine.decide(_event(risk=0.93, confidence=0.95, ti_malicious=True),
                                 {"action": "temporary_ip_restriction", "target": "203.0.113.77"})
        self.assertEqual(decision.execution, ExecutionMode.HUMAN_APPROVAL)

    def test_emergency_scope_excludes_critical_assets(self):
        engine = _engine()
        engine.add_emergency_policy(self._policy(), by="admin")
        decision = engine.decide(_event(risk=0.93, confidence=0.95, ti_malicious=True),
                                 {"action": "temporary_ip_restriction", "target": "172.16.5.5"})
        self.assertNotEqual(decision.execution, ExecutionMode.AUTOMATIC)

    def test_validate_lists_every_problem(self):
        problems = EmergencyPolicy({"name": "", "allowed_actions": ["delete_file"], "max_duration_minutes": 999,
                                    "triggers": {"min_risk": 10, "min_confidence": 10, "min_independent_sources": 1}}).validate()
        self.assertGreaterEqual(len(problems), 5)


class ExecutionAndRollbackTests(unittest.TestCase):
    """§8–§11 — preview, rollback records, time limits, no chaining."""

    def test_action_preview_and_response_format(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.75, confidence=0.85), {"action": "block_ip", "target": "203.0.113.77"})
        preview = render_action_preview(decision)
        for field in ("ACTION PREVIEW", "Target:", "Threat:", "Evidence:", "Risk:", "Confidence:", "Asset Criticality:",
                      "Proposed Action:", "Expected Impact:", "Rollback Available:", "Human Approval:", "Reason:"):
            self.assertIn(field, preview)
        self.assertIn("Human Approval:\nREQUIRED", preview)
        self.assertIn("Rollback Available:\nYES", preview)
        response = render_response(decision)
        for field in ("[VRINDHA RESPONSE]", "Threat Intelligence:", "Autonomy Level:\nLEVEL 2",
                      "Execution:\nHUMAN APPROVAL", "Rollback:\nAVAILABLE"):
            self.assertIn(field, response)

    def test_approved_execution_creates_rollback_record_and_can_be_rolled_back(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.75, confidence=0.85), {"action": "block_ip", "target": "203.0.113.77"})
        result = engine.execute(decision, approver="analyst", justification="confirmed in packet capture")
        self.assertIn(result["status"], {"success", "simulated"})
        record = engine.get_rollback(result["rollback_id"])
        self.assertEqual(record.action, "temporary_ip_restriction")
        self.assertEqual(record.target, "203.0.113.77")
        self.assertIn("previous_state", record.model_dump())
        self.assertIn("203.0.113.77", record.rollback_procedure)
        self.assertEqual(record.policy_used, decision.policy)
        rolled = engine.rollback(record.action_id, by="analyst", reason="false positive")
        self.assertEqual(rolled["status"], "success")
        self.assertEqual(engine.get_rollback(record.action_id).status, "rolled_back")
        self.assertEqual(engine.rollback(record.action_id, by="analyst")["status"], "noop")

    def test_irreversible_action_has_no_rollback(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.95, confidence=0.97, ti_malicious=True),
                                 {"action": "kill_process", "target": "pid:4242"})
        self.assertEqual(decision.recommended_action, "kill_process")
        self.assertFalse(decision.rollback_available)
        result = engine.execute(decision, approver="analyst", justification="malware confirmed")
        self.assertEqual(result["status"], "simulated")
        self.assertFalse(result["rollback_available"])
        self.assertEqual(engine.rollback(result["rollback_id"], by="analyst")["status"], "not_available")

    def test_human_override_to_original_action_requires_justification(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.75, confidence=0.85), {"action": "block_ip", "target": "203.0.113.77"})
        refused = engine.execute(decision, approver="analyst", action_override="block_ip")
        self.assertEqual(refused["status"], "not_executed")
        done = engine.execute(decision, approver="analyst", justification="repeat offender, permanent block",
                              action_override="block_ip")
        self.assertEqual(done["action"], "block_ip")
        self.assertEqual(done["autonomy_level"], "LEVEL 3")
        self.assertIsNone(done["expires_at"])  # permanent — human decision, audited

    def test_temporary_actions_expire_and_can_be_extended_by_humans_only(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.75, confidence=0.85), {"action": "block_ip", "target": "203.0.113.77"})
        result = engine.execute(decision, approver="analyst", justification="ok")
        record = engine.get_rollback(result["rollback_id"])
        self.assertEqual(engine.extend(record.action_id, 30, by="vrindha-automatic")["status"], "error")
        extended = engine.extend(record.action_id, 30, by="analyst", justification="attack ongoing")
        self.assertEqual(extended["status"], "success")
        # Force expiry and run the scheduler.
        record = engine.get_rollback(record.action_id)
        record.expires_at = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        engine._persist_rollback(record)  # noqa: SLF001 — test fixture
        expired = engine.expire_due()
        self.assertGreaterEqual(expired["expired"], 1)
        self.assertEqual(engine.get_rollback(record.action_id).status, "expired")

    def test_no_chaining_of_automatic_state_changes(self):
        engine = _engine()
        engine.add_emergency_policy({"name": "p", "enabled": True,
                                     "triggers": {"min_risk": 90, "min_confidence": 90, "min_independent_sources": 3,
                                                  "require_ti_confirmed": True},
                                     "allowed_actions": ["temporary_ip_restriction", "rate_limit"],
                                     "scope": {"target_kinds": ["ip"]}, "max_duration_minutes": 15}, by="admin")
        event = _event(risk=0.93, confidence=0.95, ti_malicious=True)
        first = engine.decide(event, {"action": "temporary_ip_restriction", "target": "203.0.113.77"}, incident_id="inc-x")
        self.assertIn(engine.execute(first)["status"], {"success", "simulated"})
        second = engine.decide(event, {"action": "rate_limit", "target": "203.0.113.77"}, incident_id="inc-x")
        self.assertEqual(second.execution, ExecutionMode.AUTOMATIC)
        refused = engine.execute(second)
        self.assertEqual(refused["status"], "not_executed")
        self.assertIn("chained", refused["reason"])
        # A human can still act after re-evaluation.
        self.assertIn(engine.execute(second, approver="analyst", justification="re-evaluated")["status"],
                      {"success", "simulated"})


class SafeModeTests(unittest.TestCase):
    """§12 — degraded inputs ⇒ monitoring continues, high-impact autonomy stops."""

    def test_ti_failure_puts_decision_in_safe_mode(self):
        engine = _engine()
        engine.add_emergency_policy({"name": "p", "enabled": True,
                                     "triggers": {"min_risk": 80, "min_confidence": 80, "min_independent_sources": 2,
                                                  "require_ti_confirmed": False},
                                     "allowed_actions": ["temporary_ip_restriction"], "scope": {"target_kinds": ["ip"]},
                                     "max_duration_minutes": 15}, by="admin")
        decision = engine.decide(_event(risk=0.93, confidence=0.95, ti_unavailable=True),
                                 {"action": "temporary_ip_restriction", "target": "203.0.113.77"})
        self.assertTrue(decision.safe_mode)
        self.assertIn("threat intelligence unavailable", decision.degraded_inputs)
        self.assertEqual(decision.execution, ExecutionMode.HUMAN_APPROVAL)
        self.assertIn("SAFE MODE", decision.reason)

    def test_manual_safe_mode_stops_automation_but_not_level1(self):
        engine = _engine()
        engine.enter_safe_mode("database failure")
        level1 = engine.decide(_event(risk=0.3, confidence=0.6), {"action": "collect_logs", "target": "lab-host-01"})
        self.assertEqual(level1.execution, ExecutionMode.AUTOMATIC)
        self.assertTrue(level1.safe_mode)
        self.assertEqual(engine.exit_safe_mode(by="")["status"], "error")
        self.assertTrue(engine.safe_mode_state()["safe_mode"])
        self.assertEqual(engine.exit_safe_mode(by="admin")["safe_mode"], False)

    def test_engine_failure_fails_safe(self):
        engine = _engine()
        original = engine._decide  # noqa: SLF001

        def boom(*args, **kwargs):
            raise RuntimeError("model failure")

        engine._decide = boom  # noqa: SLF001
        try:
            decision = engine.decide(_event(), {"action": "block_ip", "target": "203.0.113.77"})
        finally:
            engine._decide = original  # noqa: SLF001
        self.assertTrue(decision.safe_mode)
        self.assertEqual(decision.recommended_action, "increase_monitoring")
        self.assertTrue(decision.human_approval_required)
        self.assertTrue(engine.safe_mode_state()["safe_mode"])


class AuditAndReviewTests(unittest.TestCase):
    """§13–§14 — immutable decision, appended reviews, validated learning only."""

    def test_audit_row_exists_and_decision_is_not_rewritten_by_execution(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.75, confidence=0.85), {"action": "block_ip", "target": "203.0.113.77"})
        before = engine.get_decision(decision.decision_id)
        self.assertEqual(before["decision"]["recommended_action"], "temporary_ip_restriction")
        engine.execute(decision, approver="analyst", justification="ok", action_override="block_ip")
        after = engine.get_decision(decision.decision_id)
        self.assertEqual(after["decision"], before["decision"])  # immutable
        self.assertEqual(after["execution_result"]["action"], "block_ip")
        self.assertIsNotNone(after["rollback_info"])
        self.assertEqual(after["human_review"][0]["approver"], "analyst")
        listing = engine.list_audit(limit=5)
        self.assertEqual(listing["records"][0]["decision_id"], decision.decision_id)

    def test_review_is_appended_and_unvalidated_reviews_do_not_learn(self):
        engine = _engine()
        decision = engine.decide(_event(risk=0.5, confidence=0.7), {"action": "investigate_host", "target": "lab-host-01"})
        self.assertEqual(engine.record_review("missing", "analyst", {})["status"], "error")
        validated = engine.record_review(decision.decision_id, "analyst",
                                         {"threat_real": "no", "action_appropriate": "yes"}, validated=True)
        self.assertIn("eligible", validated["learning"])
        unvalidated = engine.record_review(decision.decision_id, "analyst", {"threat_real": "yes"}, validated=False)
        self.assertIn("NOT used", unvalidated["learning"])
        reviews = engine.list_reviews(limit=5)["reviews"]
        self.assertEqual(reviews[0]["decision_id"], decision.decision_id)
        record = engine.get_decision(decision.decision_id)
        self.assertEqual(len(record["human_review"]), 2)


class CommanderIntegrationTests(unittest.TestCase):
    """The Commander pipeline routes every proposal through the engine."""

    def test_pipeline_parks_reversible_alternative_and_approval_executes_with_rollback(self):
        from vrin_SOC.coordination.commander import commander_ai

        payload = {
            "event_type": "security_event", "correlation_id": "corr-ctrl-test-1",
            "entity": {"host": "lab-host-02", "ip": "10.0.0.51"}, "severity": "high", "authorized": True,
            "data": {"SIMULATION": True, "authentication": {"failed_login_count": 15},
                     "network": {"source_ips": ["203.0.113.90"], "connection_count": 40,
                                 "outbound": {"ip": "203.0.113.90", "port": 4444}}},
            "provenance": {"source": "test", "collection_method": "simulation", "mode": "simulated"},
        }
        result = commander_ai.handle_event(payload)
        self.assertEqual(result["status"], "awaiting_approval")
        self.assertIn("ACTION PREVIEW", result["action_preview"])
        self.assertIn("[VRINDHA RESPONSE]", result["vrindha_response"])
        proposed = result["proposed_action"]
        self.assertEqual(proposed["original_action"], "block_ip")
        self.assertEqual(proposed["action"], "temporary_ip_restriction")
        approval = commander_ai.approve(result["incident_id"], approver="human", justification="ok")
        self.assertEqual(approval["status"], "success")
        self.assertEqual(approval["response_result"]["action"], "temporary_ip_restriction")
        self.assertTrue(approval["rollback_ids"])
        rolled = commander_ai.rollback_incident(result["incident_id"], by="human", reason="test")
        self.assertEqual(rolled["rollbacks"][0]["status"], "success")

    def test_false_positive_conclusion_executes_nothing(self):
        from vrin_SOC.coordination.commander import commander_ai

        payload = {
            "event_type": "security_event", "correlation_id": "corr-ctrl-test-2",
            "entity": {"host": "lab-host-03", "ip": "10.0.0.52"}, "severity": "high", "authorized": True,
            "data": {"SIMULATION": True, "authentication": {"failed_login_count": 15},
                     "network": {"source_ips": ["203.0.113.91"], "connection_count": 40}},
            "provenance": {"source": "test", "collection_method": "simulation", "mode": "simulated"},
        }
        result = commander_ai.handle_event(payload)
        self.assertEqual(result["status"], "awaiting_approval")
        approval = commander_ai.approve(result["incident_id"], approver="human", conclusion="false_positive")
        self.assertEqual(approval["response_result"]["action"], "none")
        self.assertEqual(approval["rollback_ids"], [])

    def test_allowlisted_target_is_blocked_in_pipeline(self):
        from vrin_SOC.coordination.commander import commander_ai

        commander_ai.response.update_allowlist({"trusted_ips": ["203.0.113.250"]}, by="test-admin")
        try:
            payload = {
                "event_type": "security_event", "correlation_id": "corr-ctrl-test-3",
                "entity": {"host": "lab-host-04", "ip": "10.0.0.53"}, "severity": "high", "authorized": True,
                "data": {"SIMULATION": True, "authentication": {"failed_login_count": 15},
                         "network": {"source_ips": ["203.0.113.250"], "connection_count": 40}},
                "provenance": {"source": "test", "collection_method": "simulation", "mode": "simulated"},
            }
            result = commander_ai.handle_event(payload)
            self.assertEqual(result["status"], "awaiting_approval")
            self.assertEqual(result["response_decision"]["execution"], "BLOCKED")
            self.assertIn("BLOCKED", result["approval"])
            approval = commander_ai.approve(result["incident_id"], approver="human")  # no justification
            self.assertEqual(approval["response_result"]["status"], "not_executed")
        finally:
            commander_ai.response.update_allowlist({"trusted_ips": ["127.0.0.1", "::1"]}, by="test-admin")


if __name__ == "__main__":
    unittest.main()
