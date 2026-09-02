"""Vrindha AI — Controlled Autonomous Response & Safety engine.

This module implements the *Controlled Autonomous Response & Safety* contract
(:data:`VRINDHA_RESPONSE_PROMPT`) as a deterministic, auditable policy engine
sitting between "the AI recommended an action" and "the action happened".

    Detect → Verify → Assess Risk → Check Policy → Act → Monitor → Roll Back

The level of automation is proportional to the **risk** and the
**reversibility** of the action — never to the confidence of a classifier
alone:

    LOW      → auto-monitor (LEVEL 1, read-only, automatic when policy allows)
    MEDIUM   → recommend → human approval (LEVEL 2, reversible, time-limited)
    HIGH     → verify → policy → controlled containment → audit → rollback
    CRITICAL → multi-source verification → human approval / explicitly
               configured emergency policy

Contract → implementation map (full table in ``docs/CONTROLLED_AUTONOMY.md``):

* §1  Core safety principle      — :meth:`ControlledResponseEngine.decide`
       never yields ``AUTOMATIC`` for a state-changing action on the basis of
       risk/confidence alone; policy + verification gates are always applied.
* §2  Three-level autonomy model — :data:`ACTION_CATALOG` assigns every known
       action a base level; the engine may only *raise* a level, never lower it.
* §3  Critical assets            — :meth:`AutonomyPolicy.asset_criticality`
       (explicit metadata first, documented heuristics second); critical
       targets force LEVEL 3 + human approval + reversible preference.
* §4  Trusted-asset allowlist    — :meth:`AutonomyPolicy.allowlist_conflict`;
       a conflict ⇒ ``BLOCKED`` + high-priority alert + human verification.
       The engine cannot override the allowlist on its own.
* §5  Reversibility first        — :data:`REVERSIBILITY_LADDER` and
       ``reversible_alternative`` in the catalog; irreversible/permanent
       actions are downgraded unless the situation is CRITICAL *and*
       independently corroborated.
* §6  Confidence + risk          — risk tier is computed from risk score, TI
       state, independent sources and asset criticality together.
* §7  Emergency response         — :class:`EmergencyPolicy` must be explicitly
       configured; only reversible, time-limited LEVEL ≤ 2 actions can ever be
       automated; the engine never creates a policy dynamically.
* §8  Action preview             — :func:`render_action_preview`.
* §9  Rollback system            — :class:`RollbackRecord` rows for every
       state change; :meth:`ControlledResponseEngine.rollback`.
* §10 Time limits                — ``expires_at`` on temporary actions and
       :meth:`ControlledResponseEngine.expire_due` (re-evaluate → extend /
       remove / escalate).
* §11 Never chain unsafe actions — one state-changing execution per call; a
       second automatic state change on the same incident inside the cooldown
       is refused (a human must re-evaluate).
* §12 Fail-safe / SAFE MODE      — degraded inputs or an explicit safe-mode
       switch stop high-impact autonomy while monitoring continues.
* §13 Audit everything           — ``response_audit`` table; decision columns
       are immutable, reviews are appended (never rewritten).
* §14 Learn from mistakes        — :meth:`ControlledResponseEngine.record_review`
       (validated outcomes only).
* §15 Required response format   — :func:`render_response`.

Everything that actually touches the system goes through the existing
``vrin_SOC.automation.actions`` module, which in this deployment runs as a
labeled **simulation**.
"""
from __future__ import annotations

import ipaddress
import json
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .event_bus import EventBus
from .observability import BaseAgent
from .schemas import (
    AssetCriticality,
    AutonomyLevel,
    ExecutionMode,
    ResponseDecision,
    RiskTier,
    RollbackRecord,
    SecurityEvent,
    ThreatIntelStatus,
    utc_now_iso,
)

# ---------------------------------------------------------------------------
# The operating contract, verbatim. Served by GET /response/prompt.
# ---------------------------------------------------------------------------
VRINDHA_RESPONSE_PROMPT = """\
Vrindha AI — Controlled Autonomous Response & Safety Prompt

You are Vrindha AI, an AI-powered cybersecurity SOC agent.

Your objective is to detect threats and respond quickly while preventing accidental disruption to legitimate users, systems, services, and infrastructure.

1. CORE SAFETY PRINCIPLE

Never perform an irreversible or high-impact defensive action solely because an AI model classified something as malicious.

Follow:

«Detect → Verify → Assess Risk → Check Policy → Act → Monitor → Roll Back if Necessary»

Speed is important, but safe and controlled response has priority over unrestricted autonomy.

---

2. THREE-LEVEL AUTONOMY MODEL

Classify every proposed response into one of three levels.

LEVEL 1 — LOW RISK

Examples:

- Collect additional logs
- Increase monitoring
- Capture network metadata
- Create an alert
- Record an IOC
- Run read-only security checks
- Increase logging temporarily
- Correlate additional events

Action:

Detection
↓
Verification
↓
Automatic Action
↓
Monitoring

These actions may be performed automatically when authorized by policy.

---

LEVEL 2 — MEDIUM RISK

Examples:

- Temporary rate limiting
- Temporary network restriction
- Quarantining a suspicious file
- Temporarily restricting a suspicious session
- Applying a reversible security rule

Action:

Detection
↓
Evidence Verification
↓
Risk Assessment
↓
AI Recommendation
↓
Human Approval
↓
Execute
↓
Monitor

Do not execute without the required approval.

---

LEVEL 3 — HIGH RISK

Examples:

- Blocking critical infrastructure
- Disabling an important user account
- Killing an unknown/critical process
- Isolating a production server
- Changing critical firewall policies
- Deleting system files
- Shutting down services
- Making irreversible changes

Action:

Detection
↓
Multi-Source Verification
↓
Risk Assessment
↓
Policy Validation
↓
Human Approval
↓
Controlled Execution
↓
Continuous Monitoring
↓
Rollback if Required

Human authorization is required unless an explicitly configured emergency policy permits automated containment.

---

3. PROTECT CRITICAL ASSETS

Before taking action, check whether the target is:

- Critical server
- Domain controller
- Database
- Authentication service
- Firewall
- DNS
- Production application
- Security monitoring infrastructure
- Backup system
- Known trusted IP
- Known administrative account
- Essential operating-system process

If the target is critical:

Increase verification requirements
+
Increase confidence threshold
+
Prefer reversible actions
+
Require human approval

Never blindly block or terminate a critical resource.

---

4. TRUSTED ASSET PROTECTION

Maintain a configurable allowlist containing:

- Trusted IPs
- Trusted domains
- Critical servers
- Security tools
- Administrative accounts
- Essential processes
- Internal infrastructure

If a proposed action conflicts with the allowlist:

STOP ACTION
↓
Generate HIGH-PRIORITY ALERT
↓
Request Human Verification

Do not automatically override the allowlist based only on an AI prediction.

---

5. REVERSIBILITY FIRST

Whenever possible, choose the least destructive response.

Prefer:

Monitor
    ↓
Rate Limit
    ↓
Temporary Restriction
    ↓
Temporary Isolation
    ↓
Blocking
    ↓
Termination
    ↓
Deletion

The agent should prefer a reversible action over an irreversible action when both can reasonably mitigate the threat.

---

6. CONFIDENCE + RISK

Do not use the AI classification alone.

Before responding, evaluate:

Threat Severity
+
AI Confidence
+
Threat Intelligence
+
Detection Rules
+
Behavioral Evidence
+
Asset Criticality
+
Historical Context
+
Action Impact
=
Response Decision

Example:

Risk Score: 92/100
Confidence: 95%
Asset Criticality: HIGH
Action Impact: HIGH

Result:

«Human approval required before blocking.»

---

7. EMERGENCY RESPONSE

For rapidly developing attacks, the system may use a predefined emergency containment policy.

Emergency automation must:

- Be explicitly configured
- Have clearly defined triggers
- Have a limited scope
- Use reversible actions where possible
- Have a time limit
- Generate an immediate alert
- Record the complete action
- Support rollback

Example:

Confirmed active attack
+
Multiple independent indicators
+
Very high confidence
+
Predefined emergency policy
        ↓
Temporary containment
        ↓
Immediate human notification
        ↓
Continuous monitoring
        ↓
Automatic expiration / rollback

Never create your own emergency policy dynamically.

---

8. ACTION PREVIEW

Before executing a significant action, generate:

ACTION PREVIEW

Target:
<IP / process / account / system>

Threat:
<detected threat>

Evidence:
<supporting evidence>

Risk:
<0–100>

Confidence:
<0–100>

Asset Criticality:
LOW / MEDIUM / HIGH / CRITICAL

Proposed Action:
<action>

Expected Impact:
<impact>

Rollback Available:
YES / NO

Human Approval:
REQUIRED / NOT REQUIRED

Reason:
<explanation>

This allows the SOC analyst to understand exactly what Vrindha intends to do.

---

9. ROLLBACK SYSTEM

Every automated action that changes system state should create a rollback record whenever technically possible.

Record:

Action ID
Target
Previous State
New State
Timestamp
Reason
Evidence
Policy Used
AI Recommendation
Execution Result
Rollback Procedure

If the action causes unexpected consequences:

Detect Failure
↓
Stop Further Actions
↓
Rollback Safe Changes
↓
Alert Human Analyst
↓
Record Incident

---

10. ACTION TIME LIMITS

Temporary actions should have expiration times.

Example:

Temporary IP restriction
Duration: 15 minutes
        ↓
Re-evaluate evidence
        ↓
Extend / Remove / Escalate

Do not create permanent blocks from uncertain AI findings without the required authorization.

---

11. NEVER CHAIN UNSAFE ACTIONS

Do not allow:

AI detects threat
↓
Automatically blocks IP
↓
AI interprets block failure as attack escalation
↓
Automatically kills process
↓
Automatically disables account
↓
Automatically shuts down server

Instead:

Action
↓
Observe Result
↓
Re-evaluate Evidence
↓
Recalculate Risk
↓
Policy Check
↓
Determine Next Action

Each significant action must be independently justified.

---

12. FAIL-SAFE BEHAVIOR

If the system experiences:

- Missing evidence
- Conflicting evidence
- Database failure
- Threat Intelligence failure
- Model failure
- Policy failure
- Communication failure
- Unexpected tool output

Do not compensate by guessing.

Use:

«SAFE MODE»

In safe mode:

Detection continues
↓
Monitoring continues
↓
Evidence collection continues
↓
High-impact autonomous actions STOP
↓
Human analyst notified

---

13. AUDIT EVERYTHING

Every autonomous action must be logged.

Record:

Alert ID
Evidence
Threat Intelligence
Risk Score
Confidence
Policy
Decision
Action
Timestamp
Target
Execution Result
Rollback Information
Human Review

The audit record must not be modified merely to hide an incorrect decision.

---

14. LEARN FROM MISTAKES

After every response, evaluate:

Was the threat real?
Was the risk score appropriate?
Was the action appropriate?
Was the asset actually critical?
Was the response successful?
Was there collateral impact?
Was rollback required?

Use this feedback to improve detection rules, policies, and models.

Do not automatically learn from unverified outcomes.

---

15. REQUIRED RESPONSE FORMAT

For every detected threat, return:

[VRINDHA RESPONSE]

Threat:
<description>

Evidence:
<verified evidence>

Threat Intelligence:
<confirmed / not confirmed / unknown>

Risk:
<0–100>

Confidence:
<0–100>

Asset Criticality:
<low / medium / high / critical>

Recommended Action:
<action>

Autonomy Level:
LEVEL 1 / LEVEL 2 / LEVEL 3

Execution:
AUTOMATIC / HUMAN APPROVAL / BLOCKED

Rollback:
AVAILABLE / NOT AVAILABLE

Reason:
<short explanation>

---

FINAL OPERATING RULE

Always follow:

«"The higher the potential impact of an action, the stronger the verification required."»

Vrindha should be:

Autonomous where safe.

Assisted where uncertain.

Human-controlled where dangerous.

The objective is not to make Vrindha blindly autonomous.

The objective is to make Vrindha fast, intelligent, explainable, reversible, auditable, and safely autonomous.
"""

ENGINE_VERSION = "controlled-response-v1"
HUMAN_APPROVAL_PHRASE = "Human approval required before blocking."
SAFE_MODE_PHRASE = "SAFE MODE — high-impact autonomous actions stopped; human analyst notified."
ALLOWLIST_PHRASE = "Allowlist conflict — action stopped, high-priority alert raised, human verification requested."

# ---------------------------------------------------------------------------
# Action catalog (§2 / §5). ``level`` is the *minimum* autonomy level; the
# engine may raise it (critical asset, allowlist, low confidence) but never
# lower it. ``reversible_alternative`` is the next-less-destructive action.
# ---------------------------------------------------------------------------
ACTION_CATALOG: Dict[str, Dict[str, Any]] = {
    # LEVEL 1 — read-only / observational
    "continue_monitoring":      {"level": 1, "impact": "none", "reversible": True,  "state_change": False, "duration": None},
    "increase_monitoring":      {"level": 1, "impact": "none", "reversible": True,  "state_change": False, "duration": 60},
    "collect_logs":             {"level": 1, "impact": "none", "reversible": True,  "state_change": False, "duration": None},
    "collect_more_evidence":    {"level": 1, "impact": "none", "reversible": True,  "state_change": False, "duration": None},
    "capture_network_metadata": {"level": 1, "impact": "none", "reversible": True,  "state_change": False, "duration": 30},
    "create_alert":             {"level": 1, "impact": "none", "reversible": True,  "state_change": False, "duration": None},
    "record_ioc":               {"level": 1, "impact": "none", "reversible": True,  "state_change": False, "duration": None},
    "read_only_check":          {"level": 1, "impact": "none", "reversible": True,  "state_change": False, "duration": None},
    "investigate_host":         {"level": 1, "impact": "low",  "reversible": True,  "state_change": False, "duration": None},
    "investigate_source":       {"level": 1, "impact": "low",  "reversible": True,  "state_change": False, "duration": None},
    "correlated_review":        {"level": 1, "impact": "low",  "reversible": True,  "state_change": False, "duration": None},
    # LEVEL 2 — reversible, time-limited restrictions
    "rate_limit":               {"level": 2, "impact": "medium", "reversible": True, "state_change": True, "duration": 15,
                                 "reversible_alternative": "increase_monitoring",
                                 "rollback": "remove the temporary rate-limit rule for the target"},
    "temporary_ip_restriction": {"level": 2, "impact": "medium", "reversible": True, "state_change": True, "duration": 15,
                                 "reversible_alternative": "rate_limit",
                                 "rollback": "delete the temporary deny rule for the target (ufw delete deny from <ip>)"},
    "quarantine_file":          {"level": 2, "impact": "medium", "reversible": True, "state_change": True, "duration": None,
                                 "reversible_alternative": "record_ioc",
                                 "rollback": "restore the file from quarantine to its original path"},
    "restrict_session":         {"level": 2, "impact": "medium", "reversible": True, "state_change": True, "duration": 15,
                                 "reversible_alternative": "increase_monitoring",
                                 "rollback": "lift the session restriction"},
    "temporary_rule":           {"level": 2, "impact": "medium", "reversible": True, "state_change": True, "duration": 15,
                                 "reversible_alternative": "increase_monitoring",
                                 "rollback": "remove the temporary security rule"},
    "temporary_isolation":      {"level": 2, "impact": "medium", "reversible": True, "state_change": True, "duration": 15,
                                 "reversible_alternative": "temporary_ip_restriction",
                                 "rollback": "re-attach the host to its normal network segment"},
    # LEVEL 3 — high impact / critical / irreversible
    "block_ip":                 {"level": 3, "impact": "high", "reversible": True,  "state_change": True, "duration": None,
                                 "reversible_alternative": "temporary_ip_restriction",
                                 "rollback": "delete the firewall deny rule (ufw delete deny from <ip> / iptables -D INPUT -s <ip> -j DROP)"},
    "isolate_host":             {"level": 3, "impact": "high", "reversible": True,  "state_change": True, "duration": None,
                                 "reversible_alternative": "temporary_isolation",
                                 "rollback": "bring the network interface back up / re-attach the host"},
    "disable_account":          {"level": 3, "impact": "high", "reversible": True,  "state_change": True, "duration": None,
                                 "reversible_alternative": "restrict_session",
                                 "rollback": "re-enable the account"},
    "firewall_policy_change":   {"level": 3, "impact": "high", "reversible": True,  "state_change": True, "duration": None,
                                 "reversible_alternative": "temporary_rule",
                                 "rollback": "restore the previous firewall policy snapshot"},
    "shutdown_service":         {"level": 3, "impact": "high", "reversible": True,  "state_change": True, "duration": None,
                                 "reversible_alternative": "rate_limit",
                                 "rollback": "restart the service"},
    "kill_process":             {"level": 3, "impact": "high", "reversible": False, "state_change": True, "duration": None,
                                 "reversible_alternative": "temporary_isolation",
                                 "rollback": None},
    "delete_file":              {"level": 3, "impact": "high", "reversible": False, "state_change": True, "duration": None,
                                 "reversible_alternative": "quarantine_file",
                                 "rollback": None},
}

#: §5 — least destructive first.
REVERSIBILITY_LADDER: List[str] = [
    "monitor", "rate_limit", "temporary_restriction", "temporary_isolation",
    "blocking", "termination", "deletion",
]

LEVEL_BY_INT = {1: AutonomyLevel.LEVEL_1, 2: AutonomyLevel.LEVEL_2, 3: AutonomyLevel.LEVEL_3}

#: Hostname/role fragments that *suggest* a critical asset (heuristic; §3).
CRITICAL_ROLE_HINTS: Dict[str, str] = {
    "domain-controller": "domain controller", "dc0": "domain controller", "dc1": "domain controller",
    "ldap": "authentication service", "kerberos": "authentication service", "auth": "authentication service",
    "sso": "authentication service", "idp": "authentication service",
    "db": "database", "database": "database", "sql": "database", "postgres": "database", "mysql": "database",
    "mongo": "database", "oracle": "database",
    "firewall": "firewall", "fw0": "firewall", "fw1": "firewall", "pfsense": "firewall",
    "dns": "DNS", "resolver": "DNS",
    "prod": "production application", "production": "production application",
    "siem": "security monitoring infrastructure", "splunk": "security monitoring infrastructure",
    "elastic": "security monitoring infrastructure", "wazuh": "security monitoring infrastructure",
    "sensor": "security monitoring infrastructure",
    "backup": "backup system", "bkp": "backup system", "veeam": "backup system",
}

ESSENTIAL_PROCESSES = {
    "systemd", "init", "kernel", "kthreadd", "sshd", "cron", "crond", "dbus-daemon", "journald",
    "systemd-journald", "systemd-logind", "networkd", "systemd-networkd", "rsyslogd", "auditd",
    "lsass.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "smss.exe", "svchost.exe",
}
SECURITY_TOOLS = {"suricata", "zeek", "snort", "wazuh", "ossec", "falco", "osquery", "crowdstrike", "sentinelone",
                  "auditd", "filebeat", "winlogbeat", "fluentd", "vrindha"}
ADMIN_ACCOUNTS = {"root", "administrator", "admin", "domain admins", "enterprise admins", "sysadmin"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _pct(value: Any) -> int:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    if 0.0 <= number <= 1.0:
        number *= 100.0
    return int(round(max(0.0, min(100.0, number))))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


_INTERNAL_RANGES = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "fc00::/7", "::1/128", "fe80::/10",
)]


def _is_internal_address(value: str) -> bool:
    """RFC 1918 / loopback / link-local / ULA — *not* the broader ``is_private``
    (which also covers documentation ranges such as 203.0.113.0/24)."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_RANGES)


# ---------------------------------------------------------------------------
# Policy (§3, §4, §7) — configurable, explicit, never created on the fly.
# ---------------------------------------------------------------------------
DEFAULT_POLICY_PATH = Path(__file__).resolve().parents[1] / "config" / "autonomy_policy.json"


class EmergencyPolicy:
    """An explicitly configured emergency containment policy (§7).

    A policy is only *valid* when every allowed action is reversible,
    time-limited and LEVEL ≤ 2. Invalid policies are recorded and ignored —
    the engine will not "repair" or invent one.
    """

    def __init__(self, raw: Dict[str, Any]) -> None:
        self.name = str(raw.get("name", "")).strip()
        self.enabled = bool(raw.get("enabled", False))
        triggers = raw.get("triggers") or {}
        self.min_risk = int(triggers.get("min_risk", 90))
        self.min_confidence = int(triggers.get("min_confidence", 90))
        self.min_independent_sources = int(triggers.get("min_independent_sources", 3))
        self.require_ti_confirmed = bool(triggers.get("require_ti_confirmed", True))
        self.event_types = [str(x) for x in (triggers.get("event_types") or [])]
        self.allowed_actions = [str(x) for x in (raw.get("allowed_actions") or [])]
        scope = raw.get("scope") or {}
        self.target_kinds = [str(x) for x in (scope.get("target_kinds") or ["ip"])]
        self.exclude_critical = bool(scope.get("exclude_critical", True))
        self.max_duration_minutes = int(raw.get("max_duration_minutes", 15))
        self.raw = raw

    def validate(self) -> List[str]:
        problems: List[str] = []
        if not self.name:
            problems.append("policy has no name")
        if not self.allowed_actions:
            problems.append("policy allows no actions")
        for action in self.allowed_actions:
            spec = ACTION_CATALOG.get(action)
            if spec is None:
                problems.append(f"unknown action {action!r}")
                continue
            if spec["level"] > 2:
                problems.append(f"{action} is LEVEL 3 — emergency policies may only automate LEVEL ≤ 2")
            if not spec["reversible"]:
                problems.append(f"{action} is irreversible — emergency policies must be reversible")
        if not (1 <= self.max_duration_minutes <= 240):
            problems.append("max_duration_minutes must be 1..240 (time-limited)")
        if self.min_risk < 70 or self.min_confidence < 70:
            problems.append("triggers must require at least risk 70 and confidence 70")
        if self.min_independent_sources < 2:
            problems.append("triggers must require ≥ 2 independent indicators")
        return problems

    def matches(self, decision: "ResponseDecision", event_type: str) -> Tuple[bool, str]:
        if not self.enabled:
            return False, "policy disabled"
        if self.validate():
            return False, "policy invalid"
        if decision.risk < self.min_risk:
            return False, f"risk {decision.risk} < {self.min_risk}"
        if decision.confidence < self.min_confidence:
            return False, f"confidence {decision.confidence} < {self.min_confidence}"
        if decision.independent_sources < self.min_independent_sources:
            return False, f"independent sources {decision.independent_sources} < {self.min_independent_sources}"
        if self.require_ti_confirmed and decision.threat_intelligence != ThreatIntelStatus.CONFIRMED:
            return False, "threat intelligence not confirmed"
        if self.event_types and event_type not in self.event_types:
            return False, f"event type {event_type!r} out of scope"
        if decision.target_kind not in self.target_kinds:
            return False, f"target kind {decision.target_kind!r} out of scope"
        if self.exclude_critical and decision.asset_criticality in {AssetCriticality.HIGH, AssetCriticality.CRITICAL}:
            return False, "critical asset excluded from emergency scope"
        if decision.recommended_action not in self.allowed_actions:
            return False, f"{decision.recommended_action} not in allowed actions"
        return True, "all triggers satisfied"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "enabled": self.enabled,
            "triggers": {"min_risk": self.min_risk, "min_confidence": self.min_confidence,
                         "min_independent_sources": self.min_independent_sources,
                         "require_ti_confirmed": self.require_ti_confirmed, "event_types": self.event_types},
            "allowed_actions": self.allowed_actions,
            "scope": {"target_kinds": self.target_kinds, "exclude_critical": self.exclude_critical},
            "max_duration_minutes": self.max_duration_minutes,
            "problems": self.validate(),
        }


class AutonomyPolicy:
    """Configurable allowlist, critical-asset rules, thresholds, emergency policies."""

    def __init__(self, raw: Optional[Dict[str, Any]] = None) -> None:
        raw = raw or {}
        allow = raw.get("allowlist") or {}
        self.trusted_ips: List[str] = list(allow.get("trusted_ips", ["127.0.0.1", "::1"]))
        self.trusted_domains: List[str] = list(allow.get("trusted_domains", []))
        self.critical_servers: List[str] = list(allow.get("critical_servers", []))
        self.security_tools: List[str] = list(allow.get("security_tools", sorted(SECURITY_TOOLS)))
        self.administrative_accounts: List[str] = list(allow.get("administrative_accounts", sorted(ADMIN_ACCOUNTS)))
        self.essential_processes: List[str] = list(allow.get("essential_processes", sorted(ESSENTIAL_PROCESSES)))
        self.internal_networks: List[str] = list(allow.get("internal_networks", []))
        thresholds = raw.get("thresholds") or {}
        self.tier_medium = int(thresholds.get("medium", 40))
        self.tier_high = int(thresholds.get("high", 70))
        self.tier_critical = int(thresholds.get("critical", 85))
        self.min_confidence_automatic = int(thresholds.get("min_confidence_automatic", 70))
        self.critical_confidence_bonus = int(thresholds.get("critical_confidence_bonus", 15))
        self.min_independent_sources_irreversible = int(thresholds.get("min_independent_sources_irreversible", 2))
        self.auto_level1 = bool(raw.get("auto_level1", True))
        self.protect_private_ranges = bool(raw.get("protect_private_ranges", True))
        self.default_duration_minutes = int(raw.get("default_duration_minutes", 15))
        self.chain_cooldown_minutes = int(raw.get("chain_cooldown_minutes", 10))
        self.emergency_policies: List[EmergencyPolicy] = [
            EmergencyPolicy(p) for p in (raw.get("emergency_policies") or []) if isinstance(p, dict)
        ]
        self.source = raw.get("_source", "defaults")

    # -- loading ---------------------------------------------------------
    @classmethod
    def load(cls, path: Optional[Path] = None) -> "AutonomyPolicy":
        path = path or Path(os.environ.get("VRINDHA_AUTONOMY_POLICY", str(DEFAULT_POLICY_PATH)))
        try:
            if path.is_file():
                raw = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    raw["_source"] = str(path)
                    return cls(raw)
        except (OSError, ValueError):
            pass
        return cls()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "allowlist": {
                "trusted_ips": self.trusted_ips, "trusted_domains": self.trusted_domains,
                "critical_servers": self.critical_servers, "security_tools": self.security_tools,
                "administrative_accounts": self.administrative_accounts,
                "essential_processes": self.essential_processes, "internal_networks": self.internal_networks,
            },
            "thresholds": {
                "medium": self.tier_medium, "high": self.tier_high, "critical": self.tier_critical,
                "min_confidence_automatic": self.min_confidence_automatic,
                "critical_confidence_bonus": self.critical_confidence_bonus,
                "min_independent_sources_irreversible": self.min_independent_sources_irreversible,
            },
            "auto_level1": self.auto_level1,
            "protect_private_ranges": self.protect_private_ranges,
            "default_duration_minutes": self.default_duration_minutes,
            "chain_cooldown_minutes": self.chain_cooldown_minutes,
            "emergency_policies": [p.to_dict() for p in self.emergency_policies],
            "reversibility_ladder": REVERSIBILITY_LADDER,
        }

    # -- §4 allowlist ----------------------------------------------------
    def allowlist_conflict(self, target: str, target_kind: str) -> List[str]:
        """Reasons the target is on the trusted allowlist (empty = no conflict)."""
        target_l = (target or "").strip().lower()
        if not target_l:
            return []
        reasons: List[str] = []
        if _is_ip(target_l):
            addr = ipaddress.ip_address(target_l)
            if target_l in {t.lower() for t in self.trusted_ips}:
                reasons.append("trusted IP")
            for cidr in self.internal_networks:
                try:
                    if addr in ipaddress.ip_network(cidr, strict=False):
                        reasons.append(f"internal infrastructure ({cidr})")
                        break
                except ValueError:
                    continue
        if target_l in {d.lower() for d in self.trusted_domains} or any(
                target_l.endswith("." + d.lower()) for d in self.trusted_domains):
            reasons.append("trusted domain")
        if target_l in {s.lower() for s in self.critical_servers}:
            reasons.append("critical server (allowlisted)")
        if target_kind in {"process", "unknown", "system"} and target_l in {p.lower() for p in self.essential_processes}:
            reasons.append("essential operating-system process")
        if target_kind in {"process", "host", "unknown", "system"} and any(
                tool.lower() in target_l for tool in self.security_tools):
            reasons.append("security tool")
        if target_kind in {"user", "unknown"} and target_l in {a.lower() for a in self.administrative_accounts}:
            reasons.append("administrative account")
        return reasons

    # -- §3 critical assets ----------------------------------------------
    def asset_criticality(self, target: str, target_kind: str,
                          data: Dict[str, Any]) -> Tuple[AssetCriticality, List[str]]:
        """Explicit metadata first; documented heuristics second (labeled as such)."""
        reasons: List[str] = []
        level = AssetCriticality.LOW
        data = data if isinstance(data, dict) else {}

        explicit = str(data.get("asset_criticality") or data.get("criticality") or "").lower()
        if explicit in {"low", "medium", "high", "critical"}:
            level = AssetCriticality(explicit)
            reasons.append(f"explicit asset_criticality={explicit}")
        target_type = str(data.get("target_type") or "").lower()
        if target_type in {"production", "customer"}:
            level = max(level, AssetCriticality.HIGH, key=_crit_rank)
            reasons.append(f"explicit target_type={target_type}")
        role = str(data.get("asset_role") or "").lower()
        if role:
            for hint, label in CRITICAL_ROLE_HINTS.items():
                if hint in role:
                    level = max(level, AssetCriticality.CRITICAL, key=_crit_rank)
                    reasons.append(f"explicit asset_role indicates {label}")
                    break

        target_l = (target or "").lower()
        for reason in self.allowlist_conflict(target, target_kind):
            level = max(level, AssetCriticality.CRITICAL, key=_crit_rank)
            reasons.append(f"allowlisted: {reason}")
        if target_kind in {"host", "domain", "system"}:
            for hint, label in CRITICAL_ROLE_HINTS.items():
                if hint in target_l:
                    level = max(level, AssetCriticality.HIGH, key=_crit_rank)
                    reasons.append(f"heuristic: name contains '{hint}' → possible {label} (verify)")
                    break
        if target_kind == "ip" and self.protect_private_ranges and _is_internal_address(target_l):
            level = max(level, AssetCriticality.HIGH, key=_crit_rank)
            reasons.append("private/internal address range — blocking may disrupt internal infrastructure")
        if target_kind == "process" and target_l in {p.lower() for p in self.essential_processes}:
            level = AssetCriticality.CRITICAL
            reasons.append("essential operating-system process")
        if target_kind == "user" and target_l in {a.lower() for a in self.administrative_accounts}:
            level = AssetCriticality.CRITICAL
            reasons.append("known administrative account")
        return level, reasons


def _join(reasons: List[str]) -> str:
    return " ".join(r.strip().rstrip(".") + "." for r in reasons if r and r.strip())


def _crit_rank(level: AssetCriticality) -> int:
    return ["low", "medium", "high", "critical"].index(level.value)


# ---------------------------------------------------------------------------
# Rendering (§8, §15)
# ---------------------------------------------------------------------------
def render_action_preview(decision: ResponseDecision) -> str:
    evidence = "\n".join(f"- {e}" for e in decision.evidence) or "- (no verified evidence recorded)"
    return (
        "ACTION PREVIEW\n\n"
        f"Target:\n{decision.target or 'n/a'} ({decision.target_kind})\n\n"
        f"Threat:\n{decision.threat or 'n/a'}\n\n"
        f"Evidence:\n{evidence}\n\n"
        f"Risk:\n{decision.risk}\n\n"
        f"Confidence:\n{decision.confidence}\n\n"
        f"Asset Criticality:\n{decision.asset_criticality.value.upper()}\n\n"
        f"Proposed Action:\n{decision.recommended_action}"
        + (f" (downgraded from {decision.downgraded_from})" if decision.downgraded_from else "")
        + (f" — duration {decision.duration_minutes} min" if decision.duration_minutes else "")
        + "\n\n"
        f"Expected Impact:\n{decision.expected_impact.upper()}\n\n"
        f"Rollback Available:\n{'YES' if decision.rollback_available else 'NO'}\n\n"
        f"Human Approval:\n{'REQUIRED' if decision.human_approval_required else 'NOT REQUIRED'}\n\n"
        f"Reason:\n{decision.reason}"
    )


def render_response(decision: ResponseDecision) -> str:
    evidence = "\n".join(f"- {e}" for e in decision.evidence) or "- Insufficient evidence — further investigation required."
    ti = {"confirmed": "confirmed", "not_confirmed": "not confirmed", "unknown": "unknown"}[decision.threat_intelligence.value]
    return (
        "[VRINDHA RESPONSE]\n\n"
        f"Threat:\n{decision.threat or 'n/a'}\n\n"
        f"Evidence:\n{evidence}\n\n"
        f"Threat Intelligence:\n{ti}\n\n"
        f"Risk:\n{decision.risk}\n\n"
        f"Confidence:\n{decision.confidence}\n\n"
        f"Asset Criticality:\n{decision.asset_criticality.value}\n\n"
        f"Recommended Action:\n{decision.recommended_action} (target: {decision.target or 'n/a'})\n\n"
        f"Autonomy Level:\n{decision.autonomy_level.value}\n\n"
        f"Execution:\n{decision.execution.value}\n\n"
        f"Rollback:\n{'AVAILABLE' if decision.rollback_available else 'NOT AVAILABLE'}\n\n"
        f"Reason:\n{decision.reason}"
    )


# ---------------------------------------------------------------------------
# Persistence (§9, §13, §14)
# ---------------------------------------------------------------------------
def _db():
    from vrin_SOC.database import db

    return db


def _ensure_tables(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS response_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            decision_id TEXT UNIQUE,
            incident_id TEXT,
            event_id TEXT,
            alert_id TEXT,
            timestamp TEXT,
            target TEXT,
            threat TEXT,
            evidence TEXT,
            threat_intelligence TEXT,
            risk INTEGER,
            confidence INTEGER,
            asset_criticality TEXT,
            autonomy_level TEXT,
            execution TEXT,
            policy TEXT,
            decision TEXT,
            action TEXT,
            execution_result TEXT,
            rollback_info TEXT,
            human_review TEXT,
            preview TEXT,
            response_block TEXT,
            created_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS rollback_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_id TEXT UNIQUE,
            decision_id TEXT,
            incident_id TEXT,
            status TEXT,
            expires_at TEXT,
            payload TEXT,
            created_at TEXT,
            updated_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS response_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            decision_id TEXT,
            reviewer TEXT,
            threat_real TEXT,
            risk_appropriate TEXT,
            action_appropriate TEXT,
            asset_critical TEXT,
            response_successful TEXT,
            collateral_impact TEXT,
            rollback_required TEXT,
            notes TEXT,
            validated INTEGER,
            recorded_at TEXT
        )
        """
    )


# ---------------------------------------------------------------------------
# The engine
# ---------------------------------------------------------------------------
class ControlledResponseEngine(BaseAgent):
    """Detect → Verify → Assess Risk → Check Policy → Act → Monitor → Roll Back."""

    name = "ControlledResponseEngine"
    kind = "governor"
    capabilities = [
        "autonomy_classification", "critical_asset_protection", "allowlist_protection",
        "reversibility_first", "emergency_policy", "action_preview", "controlled_execution",
        "rollback", "time_limits", "anti_chaining", "safe_mode", "audit", "review",
    ]
    agent_version = "1.0"

    def __init__(self, bus: Optional[EventBus] = None, policy: Optional[AutonomyPolicy] = None) -> None:
        super().__init__(bus)
        self.policy = policy or AutonomyPolicy.load()
        self._lock = threading.Lock()
        self._safe_mode = False
        self._safe_mode_reason = ""
        self._last_state_change: Dict[str, datetime] = {}
        self._db_ok = True
        try:
            _db()._run_db(_ensure_tables)  # noqa: SLF001 — idempotent schema bootstrap
        except Exception as exc:  # noqa: BLE001
            self._db_ok = False
            self.enter_safe_mode(f"database failure during bootstrap: {exc}"[:200])

    # ------------------------------------------------------------------
    # Public: contract, policy, safe mode
    # ------------------------------------------------------------------
    def prompt(self) -> Dict[str, Any]:
        return {"status": "success", "agent": self.name, "engine": ENGINE_VERSION,
                "deterministic": True, "sections": 15, "prompt": VRINDHA_RESPONSE_PROMPT}

    def policy_view(self) -> Dict[str, Any]:
        return {"status": "success", "safe_mode": self.safe_mode_state(), "policy": self.policy.to_dict(),
                "action_catalog": {k: {**v, "autonomy_level": LEVEL_BY_INT[v["level"]].value}
                                   for k, v in ACTION_CATALOG.items()}}

    def update_allowlist(self, updates: Dict[str, List[str]], by: str) -> Dict[str, Any]:
        """Human-configured allowlist changes (admin). The engine never edits it itself."""
        if not by:
            return {"status": "error", "reason": "operator identity required"}
        allowed = {"trusted_ips", "trusted_domains", "critical_servers", "security_tools",
                   "administrative_accounts", "essential_processes", "internal_networks"}
        changed: Dict[str, List[str]] = {}
        for key, values in (updates or {}).items():
            if key not in allowed or not isinstance(values, list):
                continue
            cleaned = [str(v).strip() for v in values if str(v).strip()]
            if key == "trusted_ips":
                cleaned = [v for v in cleaned if _is_ip(v)]
            if key == "internal_networks":
                kept = []
                for v in cleaned:
                    try:
                        ipaddress.ip_network(v, strict=False)
                        kept.append(v)
                    except ValueError:
                        continue
                cleaned = kept
            setattr(self.policy, key, cleaned)
            changed[key] = cleaned
        self.policy.source = f"runtime update by {by} at {utc_now_iso()}"
        return {"status": "success", "updated_by": by, "changed": changed, "policy": self.policy.to_dict()}

    def add_emergency_policy(self, raw: Dict[str, Any], by: str) -> Dict[str, Any]:
        """Register an *explicitly configured* emergency policy (admin only).

        The engine validates but never authors policies; an invalid policy is
        rejected with the reasons instead of being silently "fixed".
        """
        if not by:
            return {"status": "error", "reason": "operator identity required"}
        policy = EmergencyPolicy(raw or {})
        problems = policy.validate()
        if problems:
            return {"status": "rejected", "reason": "emergency policy failed validation", "problems": problems}
        self.policy.emergency_policies = [p for p in self.policy.emergency_policies if p.name != policy.name]
        self.policy.emergency_policies.append(policy)
        return {"status": "success", "configured_by": by, "policy": policy.to_dict()}

    def enter_safe_mode(self, reason: str) -> Dict[str, Any]:
        with self._lock:
            self._safe_mode = True
            self._safe_mode_reason = reason[:300]
        self._alert(f"SAFE MODE entered: {reason}", priority="high")
        return self.safe_mode_state()

    def exit_safe_mode(self, by: str) -> Dict[str, Any]:
        if not by:
            return {"status": "error", "reason": "a human operator must exit safe mode"}
        with self._lock:
            self._safe_mode = False
            self._safe_mode_reason = ""
        self._alert(f"SAFE MODE exited by {by}", priority="normal")
        return self.safe_mode_state()

    def safe_mode_state(self) -> Dict[str, Any]:
        with self._lock:
            return {"safe_mode": self._safe_mode, "reason": self._safe_mode_reason,
                    "note": SAFE_MODE_PHRASE if self._safe_mode else "normal operation",
                    "database": "ok" if self._db_ok else "unavailable"}

    # ------------------------------------------------------------------
    # Decide (§1–§8, §11, §12)
    # ------------------------------------------------------------------
    def decide(self, event: SecurityEvent, recommendation: Optional[Dict[str, Any]],
               incident_id: Optional[str] = None, analysis: Any = None,
               degraded_inputs: Optional[List[str]] = None) -> ResponseDecision:
        result = self.run_guarded(self._decide, event, recommendation, incident_id, analysis,
                                  list(degraded_inputs or []))
        if isinstance(result, ResponseDecision):
            return result
        # run_guarded returned a degraded dict → fail safe (§12): monitor only.
        self.enter_safe_mode(f"decision engine failure: {result.get('error', 'unknown')}")
        return self._fail_safe_decision(event, incident_id, str(result.get("error", "engine failure")))

    def _fail_safe_decision(self, event: SecurityEvent, incident_id: Optional[str], why: str) -> ResponseDecision:
        target = (event.entity and event.entity.primary()) or "system"
        decision = ResponseDecision(
            incident_id=incident_id, event_id=event.event_id, correlation_id=event.correlation_id,
            target=target, target_kind=self._target_kind(target, event),
            threat=f"{event.event_type} on {target}", evidence=[], risk=0, confidence=0,
            original_action="unknown", recommended_action="increase_monitoring", expected_impact="none",
            autonomy_level=AutonomyLevel.LEVEL_1, execution=ExecutionMode.HUMAN_APPROVAL,
            rollback_available=False, reversible=True, state_change=False,
            human_approval_required=True, safe_mode=True, degraded_inputs=[f"engine: {why}"],
            policy="fail-safe", verification=["decision engine failed — no guessing"],
            reason=f"{SAFE_MODE_PHRASE} Cause: {why}",
        )
        self._persist_decision(decision, event)
        return decision

    def _decide(self, event: SecurityEvent, recommendation: Optional[Dict[str, Any]],
                incident_id: Optional[str], analysis: Any, degraded_inputs: List[str]) -> ResponseDecision:
        recommendation = dict(recommendation or {})
        original_action = str(recommendation.get("action") or "continue_monitoring")
        target = str(recommendation.get("target") or (event.entity and event.entity.primary()) or "system")
        target_kind = self._target_kind(target, event)
        data = event.data if isinstance(event.data, dict) else {}
        verification: List[str] = []

        # -- Verify: gather independent evidence (§6) ------------------------
        risk, confidence, ti_status, sources, evidence = self._verify(event, analysis)
        verification.append(f"{len(sources)} independent evidence source(s): {', '.join(sources) or 'none'}")
        verification.append(f"threat intelligence: {ti_status.value}")
        if analysis is not None and getattr(analysis, "evidence_conflicting", False):
            degraded_inputs.append("conflicting evidence")
        if analysis is not None and getattr(analysis, "insufficient_evidence", False):
            verification.append("evidence analysis reports insufficient evidence")
        if ti_status == ThreatIntelStatus.UNKNOWN:
            degraded_inputs.append("threat intelligence unavailable")

        # -- Assess risk tier + asset criticality (§3, §6) -------------------
        criticality, asset_reasons = self.policy.asset_criticality(target, target_kind, data)
        tier = self._risk_tier(risk, ti_status, len(sources))
        verification.append(f"risk tier {tier.value.upper()} (risk {risk}, confidence {confidence})")
        if asset_reasons:
            verification.append("asset criticality " + criticality.value.upper() + ": " + "; ".join(asset_reasons))

        # -- Check policy: action catalog + reversibility (§2, §5) ----------
        action, downgraded_from, downgrade_reason = self._select_action(
            original_action, tier, criticality, len(sources), ti_status, confidence)
        spec = ACTION_CATALOG.get(action) or ACTION_CATALOG["continue_monitoring"]
        level_int = int(spec["level"])
        reasons: List[str] = []
        if downgrade_reason:
            reasons.append(downgrade_reason)
        if spec["state_change"] and criticality in {AssetCriticality.HIGH, AssetCriticality.CRITICAL}:
            level_int = 3
            reasons.append("target is a critical/protected asset — verification and confidence requirements raised, "
                           "human approval required (never blindly block or terminate a critical resource)")
        allowlist = self.policy.allowlist_conflict(target, target_kind)
        allowlist_conflict = bool(allowlist) and bool(spec["state_change"])
        if allowlist_conflict:
            level_int = 3

        # -- Safe mode (§12) -------------------------------------------------
        engine_safe = self.safe_mode_state()["safe_mode"]
        safe_mode = engine_safe or bool(degraded_inputs)
        if engine_safe:
            degraded_inputs.append(f"engine safe mode: {self._safe_mode_reason}")

        duration = spec.get("duration") if spec["state_change"] or spec.get("duration") else None
        if spec["state_change"] and spec["reversible"] and duration is None and level_int < 3:
            duration = self.policy.default_duration_minutes

        decision = ResponseDecision(
            incident_id=incident_id, event_id=event.event_id, correlation_id=event.correlation_id,
            target=target, target_kind=target_kind,
            threat=self._threat_description(event, analysis),
            evidence=evidence, threat_intelligence=ti_status, risk=risk, confidence=confidence,
            risk_tier=tier, asset_criticality=criticality, asset_reasons=asset_reasons,
            independent_sources=len(sources), original_action=original_action,
            recommended_action=action, expected_impact=str(spec["impact"]),
            autonomy_level=LEVEL_BY_INT[level_int], rollback_available=bool(spec.get("rollback")) and bool(spec["reversible"]),
            reversible=bool(spec["reversible"]), state_change=bool(spec["state_change"]),
            duration_minutes=duration, allowlist_conflict=allowlist_conflict,
            safe_mode=safe_mode, degraded_inputs=degraded_inputs, verification=verification,
            downgraded_from=downgraded_from,
        )

        # -- Execution mode (§1, §2, §4, §7, §12) ----------------------------
        self._assign_execution(decision, event, allowlist, reasons)
        self._persist_decision(decision, event)
        if decision.high_priority_alert:
            self._alert(f"HIGH PRIORITY: {ALLOWLIST_PHRASE} target={target} action={original_action} "
                        f"incident={incident_id}", priority="high")
        if decision.safe_mode and decision.state_change:
            self._alert(f"{SAFE_MODE_PHRASE} incident={incident_id} degraded={decision.degraded_inputs}",
                        priority="high")
        return decision

    # -- verification -----------------------------------------------------
    def _verify(self, event: SecurityEvent, analysis: Any) -> Tuple[int, int, ThreatIntelStatus, List[str], List[str]]:
        data = event.data if isinstance(event.data, dict) else {}
        risk_block = event.risk or {}
        evidence: List[str] = []
        sources: List[str] = []

        if analysis is not None and hasattr(analysis, "risk_score"):
            risk = int(analysis.risk_score)
            confidence = int(analysis.confidence)
            ti_status = ThreatIntelStatus(getattr(analysis, "threat_intelligence", ThreatIntelStatus.UNKNOWN))
            evidence.extend(str(e) for e in list(getattr(analysis, "evidence", []))[:6])
            for signal in getattr(analysis, "signals", []) or []:
                layer = str(signal.get("layer", ""))
                if layer and layer != "declared_severity" and float(signal.get("score", 0)) > 0:
                    sources.append(layer)
        else:
            risk = _pct(risk_block.get("risk_score", 0))
            confidence = _pct(risk_block.get("confidence", 0))
            ti_status = self._ti_status(event)

        ti = event.threat_intelligence or {}
        if ti_status == ThreatIntelStatus.CONFIRMED and "threat_intelligence" not in sources:
            sources.append("threat_intelligence")
            evidence.append("verified threat-intelligence match on the observed indicator")
        auth = data.get("authentication") if isinstance(data.get("authentication"), dict) else {}
        failed = int(auth.get("failed_login_count", 0) or 0)
        if failed >= 5 and "authentication_behavior" not in sources:
            sources.append("authentication_behavior")
            evidence.append(f"{failed} failed authentication attempts recorded")
        network = data.get("network") if isinstance(data.get("network"), dict) else {}
        if network and "network_behavior" not in sources and (
                network.get("outbound") or network.get("unusual_port_count") or
                int(network.get("connection_count", 0) or 0) >= 20 or network.get("source_ips")):
            sources.append("network_behavior")
            outbound = network.get("outbound") if isinstance(network.get("outbound"), dict) else {}
            if outbound.get("ip"):
                evidence.append(f"outbound connection to {outbound.get('ip')}:{outbound.get('port', '?')}")
            if network.get("source_ips"):
                evidence.append(f"activity from source IP(s) {', '.join(map(str, network['source_ips'][:3]))}")
        anomaly = (event.analysis or {}).get("anomaly") or {}
        if anomaly.get("is_anomaly") and "anomaly_detection" not in sources:
            sources.append("anomaly_detection")
            evidence.append(f"anomaly detector flagged the event (score {float(anomaly.get('anomaly_score', 0)):.2f})")
        investigation = (event.correlation or {}).get("investigation") or {}
        if int(investigation.get("correlated", 0) or 0) >= 1 and "correlation" not in sources:
            sources.append("correlation")
            evidence.append(f"{investigation.get('correlated')} correlated event(s) in the investigation window")
        if ti_status == ThreatIntelStatus.NOT_CONFIRMED and ti:
            evidence.append("threat intelligence checked: no supporting record (absence is not 'clean')")
        return risk, confidence, ti_status, sources, evidence[:8]

    @staticmethod
    def _ti_status(event: SecurityEvent) -> ThreatIntelStatus:
        ti = event.threat_intelligence or {}
        if not ti or ti.get("mode") == "unavailable" or ti.get("status") == "unavailable":
            return ThreatIntelStatus.UNKNOWN
        if ti.get("malicious_found"):
            return ThreatIntelStatus.CONFIRMED
        return ThreatIntelStatus.NOT_CONFIRMED

    def _risk_tier(self, risk: int, ti_status: ThreatIntelStatus, sources: int) -> RiskTier:
        if risk >= self.policy.tier_critical or (ti_status == ThreatIntelStatus.CONFIRMED and risk >= self.policy.tier_high):
            return RiskTier.CRITICAL
        if risk >= self.policy.tier_high:
            return RiskTier.HIGH
        if risk >= self.policy.tier_medium:
            return RiskTier.MEDIUM
        return RiskTier.LOW

    # -- reversibility-first action selection (§5) ---------------------------
    def _select_action(self, action: str, tier: RiskTier, criticality: AssetCriticality,
                       sources: int, ti_status: ThreatIntelStatus, confidence: int
                       ) -> Tuple[str, Optional[str], str]:
        spec = ACTION_CATALOG.get(action)
        if spec is None:
            return "increase_monitoring", action, (
                f"'{action}' is not in the action catalog — unknown actions are never executed; "
                "monitoring increased instead")
        if not spec["state_change"]:
            return action, None, ""
        if tier == RiskTier.LOW:
            return "increase_monitoring", action, (
                "risk tier LOW → auto-monitor only; a state-changing action is not justified by the evidence")
        alternative = spec.get("reversible_alternative")
        if spec["level"] == 3 and alternative:
            if tier in {RiskTier.MEDIUM, RiskTier.HIGH}:
                return alternative, action, (
                    f"reversibility first: risk tier {tier.value.upper()} does not justify the irreversible/permanent "
                    f"'{action}'; the reversible, time-limited '{alternative}' mitigates the threat")
            if sources < self.policy.min_independent_sources_irreversible:
                return alternative, action, (
                    f"CRITICAL tier but only {sources} independent source(s) — multi-source verification "
                    f"(≥ {self.policy.min_independent_sources_irreversible}) is required before '{action}'; "
                    f"reversible '{alternative}' proposed instead")
            if not spec["reversible"] and criticality in {AssetCriticality.HIGH, AssetCriticality.CRITICAL}:
                return alternative, action, (
                    f"'{action}' is irreversible and the target is a critical asset — reversible '{alternative}' preferred")
        return action, None, ""

    # -- execution mode ---------------------------------------------------------
    def _assign_execution(self, decision: ResponseDecision, event: SecurityEvent,
                          allowlist: List[str], reasons: List[str]) -> None:
        level = decision.autonomy_level
        min_conf = self.policy.min_confidence_automatic
        if decision.asset_criticality in {AssetCriticality.HIGH, AssetCriticality.CRITICAL}:
            min_conf += self.policy.critical_confidence_bonus

        if decision.allowlist_conflict:
            decision.execution = ExecutionMode.BLOCKED
            decision.human_approval_required = True
            decision.high_priority_alert = True
            decision.policy = "trusted-asset-allowlist"
            reasons.insert(0, f"{ALLOWLIST_PHRASE} Matched: {', '.join(allowlist)}. "
                              "The allowlist is not overridden on an AI prediction alone.")
            decision.reason = _join(reasons)
            return

        if not decision.state_change:
            automatic = self.policy.auto_level1
            decision.execution = ExecutionMode.AUTOMATIC if automatic else ExecutionMode.HUMAN_APPROVAL
            decision.human_approval_required = not automatic
            decision.policy = "level1-auto-monitor" if automatic else "level1-manual"
            reasons.append("LEVEL 1 read-only action — no system state changes; "
                           + ("performed automatically under policy, monitoring continues"
                              if automatic else "automatic LEVEL 1 actions are disabled by policy"))
            if decision.safe_mode:
                reasons.append("safe mode active: detection, monitoring and evidence collection continue")
            decision.reason = _join(reasons)
            return

        # State-changing action (LEVEL 2 / LEVEL 3)
        if decision.safe_mode:
            decision.execution = ExecutionMode.HUMAN_APPROVAL
            decision.human_approval_required = True
            decision.policy = "safe-mode"
            reasons.insert(0, f"{SAFE_MODE_PHRASE} Degraded inputs: {', '.join(decision.degraded_inputs) or 'n/a'}.")
            decision.reason = _join(reasons)
            return

        if level == AutonomyLevel.LEVEL_3:
            decision.execution = ExecutionMode.HUMAN_APPROVAL
            decision.human_approval_required = True
            decision.policy = "level3-human-authorization"
            reasons.append(f"{HUMAN_APPROVAL_PHRASE} LEVEL 3: multi-source verification → risk assessment → "
                           "policy validation → human approval → controlled execution → monitoring → rollback. "
                           "Emergency policies may never automate LEVEL 3.")
            decision.reason = _join(reasons)
            return

        # LEVEL 2 — human approval unless an explicitly configured emergency policy applies.
        for policy in self.policy.emergency_policies:
            ok, why = policy.matches(decision, event.event_type)
            if ok and decision.confidence >= min_conf:
                decision.execution = ExecutionMode.AUTOMATIC
                decision.human_approval_required = False
                decision.emergency_policy = policy.name
                decision.policy = f"emergency:{policy.name}"
                decision.duration_minutes = min(decision.duration_minutes or policy.max_duration_minutes,
                                                policy.max_duration_minutes)
                reasons.append(
                    f"explicitly configured emergency policy '{policy.name}' matched ({why}): temporary, "
                    f"reversible containment for {decision.duration_minutes} min with immediate human "
                    "notification, continuous monitoring and automatic expiration/rollback")
                decision.reason = _join(reasons)
                return
        decision.execution = ExecutionMode.HUMAN_APPROVAL
        decision.human_approval_required = True
        decision.policy = "level2-recommend-then-approve"
        if decision.confidence < min_conf:
            reasons.append(f"confidence {decision.confidence} < {min_conf} required for any automatic containment")
        reasons.append("LEVEL 2 reversible, time-limited action — AI recommends, a human approves, then it executes "
                       f"for {decision.duration_minutes or self.policy.default_duration_minutes} min and is re-evaluated")
        decision.reason = _join(reasons)

    # ------------------------------------------------------------------
    # Execute (§9, §10, §11) — one action, observed, recorded, reversible
    # ------------------------------------------------------------------
    def execute(self, decision: ResponseDecision, approver: str = "", justification: str = "",
                action_override: Optional[str] = None) -> Dict[str, Any]:
        result = self.run_guarded(self._execute, decision, approver, justification, action_override)
        if result.get("status") == "error" and result.get("degraded"):
            self.enter_safe_mode(f"execution failure: {result.get('error', 'unknown')}")
        return result

    def _execute(self, decision: ResponseDecision, approver: str, justification: str,
                 action_override: Optional[str]) -> Dict[str, Any]:
        human = bool(approver) and approver != "vrindha-automatic"
        action = decision.recommended_action

        # Human may escalate to the SOC-recommended original action (e.g. block_ip)
        # with an explicit justification — their decision, audited as LEVEL 3.
        if action_override and action_override != action:
            if not human:
                return self._refuse(decision, "action override requires a human approver")
            if action_override not in ACTION_CATALOG:
                return self._refuse(decision, f"unknown action '{action_override}' is never executed")
            if not justification.strip():
                return self._refuse(decision, "a justification is required to override the recommended action")
            if self.policy.allowlist_conflict(decision.target, decision.target_kind) and not justification.strip():
                return self._refuse(decision, "allowlisted target — override requires justification")
            action = action_override
        spec = ACTION_CATALOG.get(action) or ACTION_CATALOG["continue_monitoring"]

        # Gates
        if decision.execution == ExecutionMode.BLOCKED and not human:
            return self._refuse(decision, ALLOWLIST_PHRASE)
        if decision.execution == ExecutionMode.BLOCKED and human and not justification.strip():
            return self._refuse(decision, "allowlist conflict: a human may proceed only with a recorded justification")
        if decision.human_approval_required and not human:
            return self._refuse(decision, "human approval required — not executed")
        if decision.execution == ExecutionMode.AUTOMATIC and not human and spec["state_change"]:
            if self.safe_mode_state()["safe_mode"]:
                return self._refuse(decision, SAFE_MODE_PHRASE)
            if decision.emergency_policy is None:
                return self._refuse(decision, "automatic state change without an emergency policy is not permitted")
            # §11 — never chain: one automatic state change per incident per cooldown.
            key = decision.incident_id or decision.correlation_id or decision.target
            last = self._last_state_change.get(key)
            if last and _now() - last < timedelta(minutes=self.policy.chain_cooldown_minutes):
                return self._refuse(decision, "chained automatic action refused — observe result, re-evaluate evidence, "
                                              "recalculate risk and re-check policy first (human re-evaluation required)")

        previous_state = self._observe_state(action, decision.target)
        result = self._perform(action, decision, approver or "vrindha-automatic")
        ok = result.get("status") in {"success", "simulated"}
        record: Optional[RollbackRecord] = None
        if spec["state_change"] and ok:
            key = decision.incident_id or decision.correlation_id or decision.target
            self._last_state_change[key] = _now()
            duration = decision.duration_minutes if action == decision.recommended_action else spec.get("duration")
            expires = (_now() + timedelta(minutes=duration)).isoformat() if duration else None
            record = RollbackRecord(
                decision_id=decision.decision_id, incident_id=decision.incident_id, event_id=decision.event_id,
                action=action, target=decision.target, autonomy_level=LEVEL_BY_INT[spec["level"]],
                execution=decision.execution, previous_state=previous_state,
                new_state={"action": action, "status": result.get("status"), "expires_at": expires},
                expires_at=expires, reason=justification or decision.reason, evidence=decision.evidence,
                policy_used=decision.policy, ai_recommendation={"original": decision.original_action,
                                                                 "recommended": decision.recommended_action},
                execution_result=result, rollback_procedure=(spec.get("rollback") or "not available (irreversible)")
                .replace("<ip>", decision.target),
                rollback_available=bool(spec.get("rollback")) and bool(spec["reversible"]),
                executed_by=approver or "vrindha-automatic",
            )
            self._persist_rollback(record)
        elif spec["state_change"] and not ok:
            # §9 — detect failure → stop further actions → alert human.
            self._alert(f"execution FAILED for {action} on {decision.target}: {result.get('message', '')} — "
                        "further autonomous actions stopped for this incident", priority="high")
            self._last_state_change[decision.incident_id or decision.target] = _now()

        outcome = {
            "status": result.get("status", "error"),
            "action": action,
            "original_action": decision.original_action,
            "target": decision.target,
            "autonomy_level": LEVEL_BY_INT[spec["level"]].value,
            "execution": decision.execution.value if not human else "HUMAN APPROVAL",
            "executed_by": approver or "vrindha-automatic",
            "emergency_policy": decision.emergency_policy,
            "state_change": bool(spec["state_change"]),
            "rollback_id": record.action_id if record else None,
            "rollback_available": record.rollback_available if record else False,
            "expires_at": record.expires_at if record else None,
            "result": result,
            "next_step": "observe result → re-evaluate evidence → recalculate risk → policy check → "
                         "determine next action (no automatic chaining)",
        }
        self._update_audit(decision.decision_id, execution_result=outcome,
                           rollback_info=record.model_dump() if record else None,
                           human_review={"approver": approver, "justification": justification[:500]} if human else None)
        if decision.emergency_policy and not human:
            self._alert(f"EMERGENCY CONTAINMENT executed under policy '{decision.emergency_policy}': {action} on "
                        f"{decision.target} for {decision.duration_minutes} min (rollback {outcome['rollback_id']}). "
                        "Immediate human review requested.", priority="high")
        return outcome

    def _refuse(self, decision: ResponseDecision, why: str) -> Dict[str, Any]:
        outcome = {"status": "not_executed", "action": decision.recommended_action, "target": decision.target,
                   "autonomy_level": decision.autonomy_level.value, "execution": decision.execution.value,
                   "reason": why}
        self._update_audit(decision.decision_id, execution_result=outcome)
        return outcome

    def _observe_state(self, action: str, target: str) -> Dict[str, Any]:
        state: Dict[str, Any] = {"observed_at": utc_now_iso()}
        if action in {"block_ip", "temporary_ip_restriction", "rate_limit"}:
            try:
                from vrin_SOC.database.db import get_blocked_ips

                state["already_blocked"] = any(r.get("ip") == target for r in get_blocked_ips(200))
            except Exception:  # noqa: BLE001
                state["already_blocked"] = "unknown"
        return state

    def _perform(self, action: str, decision: ResponseDecision, by: str) -> Dict[str, Any]:
        from vrin_SOC.automation.actions import automation_actions

        target = decision.target
        spec = ACTION_CATALOG[action]
        if not spec["state_change"]:
            if action in {"create_alert", "increase_monitoring", "collect_logs", "collect_more_evidence",
                          "capture_network_metadata", "read_only_check"}:
                automation_actions.send_alert(f"[LEVEL 1] {action} for {target} (incident {decision.incident_id}) — "
                                              f"risk {decision.risk}, confidence {decision.confidence}")
            if action == "record_ioc" or decision.risk >= self.policy.tier_medium:
                try:
                    from vrin_SOC.database.db import add_threat

                    add_threat(threat_type=f"ioc:{decision.threat[:80]}", source_ip=target if decision.target_kind == "ip" else "",
                               risk_level=decision.risk_tier.value.capitalize(),
                               description=f"IOC recorded by controlled response ({action}); TI {decision.threat_intelligence.value}")
                except Exception:  # noqa: BLE001
                    pass
            return {"status": "success", "action": action, "target": target,
                    "message": "Observation-only action completed; no system change made.",
                    "timestamp": utc_now_iso()}

        if action in {"block_ip", "temporary_ip_restriction"}:
            result = automation_actions.block_ip(target)
            if action == "temporary_ip_restriction" and result.get("status") in {"success", "simulated"}:
                result["message"] = f"[TEMPORARY {decision.duration_minutes or self.policy.default_duration_minutes} min] " + str(result.get("message", ""))
                result["action"] = action
            return result
        if action == "kill_process":
            try:
                pid = int(str(target).split(":")[-1])
            except ValueError:
                return {"status": "error", "action": action, "message": "kill_process requires a numeric PID target"}
            return automation_actions.kill_process(pid)
        if action == "isolate_host":
            return {"status": "simulated", "action": action, "target": target,
                    "message": f"[SIMULATION] Controlled isolation of {target} (approved by {by}); rollback available."}
        # All other state changes are simulated in this deployment and labeled as such.
        return {"status": "simulated", "action": action, "target": target,
                "message": f"[SIMULATION] {action} on {target} (by {by}). No real system change occurred.",
                "timestamp": utc_now_iso()}

    # ------------------------------------------------------------------
    # Rollback / expiry / extension (§9, §10)
    # ------------------------------------------------------------------
    def rollback(self, action_id: str, by: str, reason: str = "") -> Dict[str, Any]:
        record = self.get_rollback(action_id)
        if record is None:
            return {"status": "error", "reason": f"rollback record {action_id} not found"}
        if record.status in {"rolled_back", "expired"}:
            return {"status": "noop", "action_id": action_id, "record_status": record.status}
        if not record.rollback_available:
            record.status = "failed"
            record.rollback_result = {"status": "not_available", "message": "irreversible action — no rollback procedure"}
            self._persist_rollback(record)
            return {"status": "not_available", "action_id": action_id, "message": record.rollback_result["message"]}
        result = {"status": "simulated", "action": f"rollback:{record.action}", "target": record.target,
                  "message": f"[SIMULATION] {record.rollback_procedure}", "timestamp": utc_now_iso()}
        record.status = "rolled_back" if by != "vrindha-expiry" else "expired"
        record.rolled_back_at = utc_now_iso()
        record.rolled_back_by = by or "unknown"
        record.rollback_result = {**result, "reason": reason}
        self._persist_rollback(record)
        self._update_audit(record.decision_id, rollback_info=record.model_dump())
        return {"status": "success", "action_id": action_id, "record_status": record.status, "result": result}

    def extend(self, action_id: str, minutes: int, by: str, justification: str = "") -> Dict[str, Any]:
        if not by or by == "vrindha-automatic":
            return {"status": "error", "reason": "extending a temporary action requires a human decision"}
        if not (1 <= int(minutes) <= 240):
            return {"status": "error", "reason": "minutes must be 1..240"}
        record = self.get_rollback(action_id)
        if record is None or record.status not in {"executed", "extended"}:
            return {"status": "error", "reason": "no active temporary action with that id"}
        base = _parse_ts(record.expires_at) or _now()
        record.expires_at = (max(base, _now()) + timedelta(minutes=int(minutes))).isoformat()
        record.status = "extended"
        record.new_state = {**record.new_state, "extended_by": by, "justification": justification[:300],
                            "expires_at": record.expires_at}
        self._persist_rollback(record)
        self._update_audit(record.decision_id, rollback_info=record.model_dump(),
                           human_review={"extended_by": by, "minutes": int(minutes), "justification": justification[:300]})
        return {"status": "success", "action_id": action_id, "expires_at": record.expires_at}

    def expire_due(self) -> Dict[str, Any]:
        """Time limits: expired temporary actions are rolled back and flagged for re-evaluation."""
        expired: List[Dict[str, Any]] = []
        for record in self.list_rollbacks(limit=500).get("records", []):
            if record.get("status") not in {"executed", "extended"} or not record.get("expires_at"):
                continue
            when = _parse_ts(record["expires_at"])
            if when and when <= _now():
                result = self.rollback(record["action_id"], by="vrindha-expiry",
                                       reason="time limit reached — re-evaluate evidence: extend / remove / escalate")
                expired.append({"action_id": record["action_id"], "action": record["action"],
                                "target": record["target"], "result": result})
                self._alert(f"Temporary action {record['action']} on {record['target']} expired and was rolled back; "
                            "re-evaluate evidence (extend / remove / escalate)", priority="normal")
        return {"status": "success", "expired": len(expired), "records": expired, "checked_at": utc_now_iso()}

    # ------------------------------------------------------------------
    # Learn from mistakes (§14) — validated review, append-only
    # ------------------------------------------------------------------
    def record_review(self, decision_id: str, reviewer: str, answers: Dict[str, Any],
                      notes: str = "", validated: bool = True) -> Dict[str, Any]:
        if not reviewer:
            return {"status": "error", "reason": "reviewer identity required"}
        if self.get_decision(decision_id) is None:
            return {"status": "error", "reason": f"decision {decision_id} not found"}
        keys = ("threat_real", "risk_appropriate", "action_appropriate", "asset_critical",
                "response_successful", "collateral_impact", "rollback_required")
        row = {k: str(answers.get(k, "unknown")).lower()[:32] for k in keys}

        def insert(conn):
            conn.execute(
                "INSERT INTO response_reviews (decision_id, reviewer, threat_real, risk_appropriate, action_appropriate, "
                "asset_critical, response_successful, collateral_impact, rollback_required, notes, validated, recorded_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (decision_id, reviewer, row["threat_real"], row["risk_appropriate"], row["action_appropriate"],
                 row["asset_critical"], row["response_successful"], row["collateral_impact"], row["rollback_required"],
                 notes[:2000], 1 if validated else 0, utc_now_iso()),
            )

        try:
            _db()._run_db(insert)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "reason": str(exc)[:200]}
        # The decision columns stay untouched; only the "Human Review" column is appended to.
        self._update_audit(decision_id, human_review={"reviewer": reviewer, **row, "validated": validated})
        return {"status": "success", "decision_id": decision_id, "review": row, "validated": validated,
                "learning": ("eligible for rule/policy/model improvement" if validated
                             else "NOT used for learning — outcome not validated")}

    def list_reviews(self, limit: int = 50) -> Dict[str, Any]:
        def query(conn):
            return conn.execute(
                "SELECT decision_id, reviewer, threat_real, risk_appropriate, action_appropriate, asset_critical, "
                "response_successful, collateral_impact, rollback_required, notes, validated, recorded_at "
                "FROM response_reviews ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

        try:
            rows = _db()._run_db(query)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "reason": str(exc)[:200]}
        cols = ("decision_id", "reviewer", "threat_real", "risk_appropriate", "action_appropriate", "asset_critical",
                "response_successful", "collateral_impact", "rollback_required", "notes", "validated", "recorded_at")
        return {"status": "success", "count": len(rows),
                "reviews": [dict(zip(cols, r)) for r in rows]}

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def get_decision(self, decision_id: str) -> Optional[Dict[str, Any]]:
        def query(conn):
            return conn.execute("SELECT decision, execution_result, rollback_info, human_review, preview, response_block "
                                "FROM response_audit WHERE decision_id = ?", (decision_id,)).fetchone()

        try:
            row = _db()._run_db(query)  # noqa: SLF001
        except Exception:  # noqa: BLE001
            return None
        if not row:
            return None
        return {"decision": json.loads(row[0]) if row[0] else None,
                "execution_result": json.loads(row[1]) if row[1] else None,
                "rollback_info": json.loads(row[2]) if row[2] else None,
                "human_review": json.loads(row[3]) if row[3] else None,
                "action_preview": row[4], "response": row[5]}

    def list_audit(self, limit: int = 50) -> Dict[str, Any]:
        def query(conn):
            return conn.execute(
                "SELECT decision_id, incident_id, event_id, timestamp, target, threat, threat_intelligence, risk, "
                "confidence, asset_criticality, autonomy_level, execution, policy, action, execution_result, "
                "rollback_info, human_review FROM response_audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

        try:
            rows = _db()._run_db(query)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "reason": str(exc)[:200]}
        records = []
        for r in rows:
            records.append({
                "decision_id": r[0], "incident_id": r[1], "event_id": r[2], "timestamp": r[3], "target": r[4],
                "threat": r[5], "threat_intelligence": r[6], "risk": r[7], "confidence": r[8],
                "asset_criticality": r[9], "autonomy_level": r[10], "execution": r[11], "policy": r[12],
                "action": r[13],
                "execution_result": json.loads(r[14]) if r[14] else None,
                "rollback_info": json.loads(r[15]) if r[15] else None,
                "human_review": json.loads(r[16]) if r[16] else None,
            })
        return {"status": "success", "count": len(records), "records": records}

    def get_rollback(self, action_id: str) -> Optional[RollbackRecord]:
        def query(conn):
            row = conn.execute("SELECT payload FROM rollback_records WHERE action_id = ?", (action_id,)).fetchone()
            return row[0] if row else None

        try:
            raw = _db()._run_db(query)  # noqa: SLF001
        except Exception:  # noqa: BLE001
            return None
        if not raw:
            return None
        try:
            return RollbackRecord.model_validate(json.loads(raw))
        except Exception:  # noqa: BLE001
            return None

    def list_rollbacks(self, limit: int = 50, active_only: bool = False) -> Dict[str, Any]:
        def query(conn):
            sql = "SELECT payload FROM rollback_records"
            if active_only:
                sql += " WHERE status IN ('executed', 'extended')"
            sql += " ORDER BY id DESC LIMIT ?"
            return conn.execute(sql, (limit,)).fetchall()

        try:
            rows = _db()._run_db(query)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "reason": str(exc)[:200], "records": []}
        records = []
        for (raw,) in rows:
            try:
                records.append(json.loads(raw))
            except ValueError:
                continue
        return {"status": "success", "count": len(records), "records": records}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _target_kind(target: str, event: SecurityEvent) -> str:
        target_l = (target or "").lower()
        if _is_ip(target_l):
            return "ip"
        entity = event.entity
        if entity:
            if entity.user and entity.user.lower() == target_l:
                return "user"
            if entity.process and entity.process.lower() == target_l:
                return "process"
            if entity.domain and entity.domain.lower() == target_l:
                return "domain"
            if entity.host and entity.host.lower() == target_l:
                return "host"
        if target_l.startswith("pid:") or target_l.endswith(".exe"):
            return "process"
        if target_l in {"system", ""}:
            return "system"
        if "." in target_l and " " not in target_l:
            return "domain"
        return "host"

    @staticmethod
    def _threat_description(event: SecurityEvent, analysis: Any) -> str:
        if analysis is not None and getattr(analysis, "detection", ""):
            return str(analysis.detection)[:300]
        entity = (event.entity and event.entity.primary()) or "system"
        return f"{event.event_type} on {entity} (severity {event.severity})"

    def _alert(self, message: str, priority: str = "normal") -> None:
        try:
            from vrin_SOC.automation.actions import automation_actions

            automation_actions.send_alert(f"[{priority.upper()}] {message}")
        except Exception:  # noqa: BLE001
            pass

    def _persist_decision(self, decision: ResponseDecision, event: SecurityEvent) -> None:
        preview = render_action_preview(decision)
        block = render_response(decision)

        def insert(conn):
            conn.execute(
                "INSERT OR IGNORE INTO response_audit (decision_id, incident_id, event_id, alert_id, timestamp, target, "
                "threat, evidence, threat_intelligence, risk, confidence, asset_criticality, autonomy_level, execution, "
                "policy, decision, action, execution_result, rollback_info, human_review, preview, response_block, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?, ?)",
                (decision.decision_id, decision.incident_id, decision.event_id, event.event_id, decision.created_at,
                 decision.target, decision.threat, json.dumps(decision.evidence), decision.threat_intelligence.value,
                 decision.risk, decision.confidence, decision.asset_criticality.value, decision.autonomy_level.value,
                 decision.execution.value, decision.policy, decision.model_dump_json(), decision.recommended_action,
                 preview, block, utc_now_iso()),
            )

        try:
            _db()._run_db(insert)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            self.metrics.record_error(f"audit persist failed: {exc}")
            self.enter_safe_mode("database failure while writing the response audit")

    def _update_audit(self, decision_id: str, execution_result: Any = None, rollback_info: Any = None,
                      human_review: Any = None) -> None:
        """Only the contract's Execution Result / Rollback Information / Human Review columns are
        ever updated — the decision itself is immutable (§13)."""
        def update(conn):
            if execution_result is not None:
                conn.execute("UPDATE response_audit SET execution_result = ? WHERE decision_id = ?",
                             (json.dumps(execution_result, default=str), decision_id))
            if rollback_info is not None:
                conn.execute("UPDATE response_audit SET rollback_info = ? WHERE decision_id = ?",
                             (json.dumps(rollback_info, default=str), decision_id))
            if human_review is not None:
                row = conn.execute("SELECT human_review FROM response_audit WHERE decision_id = ?",
                                   (decision_id,)).fetchone()
                existing: List[Any] = []
                if row and row[0]:
                    try:
                        loaded = json.loads(row[0])
                        existing = loaded if isinstance(loaded, list) else [loaded]
                    except ValueError:
                        existing = []
                existing.append({**human_review, "at": utc_now_iso()})
                conn.execute("UPDATE response_audit SET human_review = ? WHERE decision_id = ?",
                             (json.dumps(existing, default=str), decision_id))

        try:
            _db()._run_db(update)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            self.metrics.record_error(f"audit update failed: {exc}")

    def _persist_rollback(self, record: RollbackRecord) -> None:
        def upsert(conn):
            conn.execute(
                "INSERT INTO rollback_records (action_id, decision_id, incident_id, status, expires_at, payload, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(action_id) DO UPDATE SET status=excluded.status, "
                "expires_at=excluded.expires_at, payload=excluded.payload, updated_at=excluded.updated_at",
                (record.action_id, record.decision_id, record.incident_id, record.status, record.expires_at,
                 record.model_dump_json(), record.timestamp, utc_now_iso()),
            )

        try:
            _db()._run_db(upsert)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            self.metrics.record_error(f"rollback persist failed: {exc}")
            self.enter_safe_mode("database failure while writing a rollback record")

    def health(self) -> Dict[str, Any]:
        base = super().health()
        base["safe_mode"] = self.safe_mode_state()
        base["emergency_policies"] = [p.name for p in self.policy.emergency_policies if p.enabled and not p.validate()]
        base["active_temporary_actions"] = self.list_rollbacks(limit=200, active_only=True).get("count", 0)
        return base

    def _model_info(self) -> Optional[Dict[str, Any]]:
        return {"model": ENGINE_VERSION, "model_version": "1.0", "deterministic": True}


controlled_response_engine = ControlledResponseEngine()

__all__ = [
    "ACTION_CATALOG",
    "REVERSIBILITY_LADDER",
    "VRINDHA_RESPONSE_PROMPT",
    "AutonomyPolicy",
    "EmergencyPolicy",
    "ControlledResponseEngine",
    "controlled_response_engine",
    "render_action_preview",
    "render_response",
]
