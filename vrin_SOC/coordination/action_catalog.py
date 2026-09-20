"""
Action Catalog and Reversibility Ladder for Controlled Response engine.

Defines every known action's base autonomy level and reversibility characteristics.
Per §2: the engine may only *raise* a level, never lower it.
Per §5: irreversibility is a primary factor in level assignment.
"""
from __future__ import annotations

from typing import Any, Dict, Literal, Optional
from .schemas import AutonomyLevel, RiskTier, ExecutionMode


# ---------------------------------------------------------------------------
# Reversibility Ladder (§5)
# ---------------------------------------------------------------------------
REVERSIBILITY_LADDER: Dict[str, int] = {
    "monitor": 0,           # read-only, fully reversible
    "alert": 0,             # notification only
    "collect_logs": 0,      # read-only
    "increase_monitoring": 0,
    "rate_limit": 1,        # temporary, auto-expires
    "temporary_ip_restriction": 1,
    "temporary_network_restriction": 1,
    "quarantine_file": 2,   # reversible but needs action
    "restrict_session": 2,
    "disable_account": 3,   # semi-reversible (admin action to restore)
    "block_ip": 3,
    "kill_process": 3,
    "isolate_host": 3,
    "change_firewall_policy": 3,
    "delete_system_files": 5,  # irreversible
    "shutdown_service": 4,
    "permanent_block": 5,
}


# ---------------------------------------------------------------------------
# Action Catalog (§2)
# Maps action name -> base autonomy level + metadata
# ---------------------------------------------------------------------------
ACTION_CATALOG: Dict[str, Dict[str, Any]] = {
    # LEVEL 1 — Auto-monitor (read-only, automatic when policy allows)
    "monitor": {
        "base_level": AutonomyLevel.LEVEL_1,
        "reversible": True,
        "reversible_alternative": None,
        "description": "Increase monitoring / logging for target",
        "risk_tiers": [RiskTier.LOW, RiskTier.MEDIUM],
        "requires_human": False,
        "default_duration_minutes": 60,
    },
    "alert": {
        "base_level": AutonomyLevel.LEVEL_1,
        "reversible": True,
        "reversible_alternative": None,
        "description": "Create alert / notification",
        "risk_tiers": [RiskTier.LOW, RiskTier.MEDIUM, RiskTier.HIGH],
        "requires_human": False,
        "default_duration_minutes": 0,
    },
    "collect_logs": {
        "base_level": AutonomyLevel.LEVEL_1,
        "reversible": True,
        "reversible_alternative": None,
        "description": "Collect additional logs / SIEM correlation",
        "risk_tiers": [RiskTier.LOW, RiskTier.MEDIUM],
        "requires_human": False,
        "default_duration_minutes": 30,
    },
    "increase_monitoring": {
        "base_level": AutonomyLevel.LEVEL_1,
        "reversible": True,
        "reversible_alternative": None,
        "description": "Temporarily increase monitoring verbosity",
        "risk_tiers": [RiskTier.LOW, RiskTier.MEDIUM],
        "requires_human": False,
        "default_duration_minutes": 60,
    },
    "record_ioc": {
        "base_level": AutonomyLevel.LEVEL_1,
        "reversible": True,
        "reversible_alternative": None,
        "description": "Record indicator of compromise",
        "risk_tiers": [RiskTier.LOW, RiskTier.MEDIUM, RiskTier.HIGH],
        "requires_human": False,
        "default_duration_minutes": 0,
    },
    "run_readonly_check": {
        "base_level": AutonomyLevel.LEVEL_1,
        "reversible": True,
        "reversible_alternative": None,
        "description": "Run read-only security check (port scan, config audit)",
        "risk_tiers": [RiskTier.LOW, RiskTier.MEDIUM],
        "requires_human": False,
        "default_duration_minutes": 30,
    },

    # LEVEL 2 — Recommend → Human approval (reversible, time-limited)
    "rate_limit": {
        "base_level": AutonomyLevel.LEVEL_2,
        "reversible": True,
        "reversible_alternative": "monitor",
        "description": "Temporary rate limiting on IP/port",
        "risk_tiers": [RiskTier.MEDIUM, RiskTier.HIGH],
        "requires_human": True,
        "default_duration_minutes": 15,
    },
    "temporary_ip_restriction": {
        "base_level": AutonomyLevel.LEVEL_2,
        "reversible": True,
        "reversible_alternative": "rate_limit",
        "description": "Temporary network restriction for IP (auto-expires)",
        "risk_tiers": [RiskTier.MEDIUM, RiskTier.HIGH],
        "requires_human": True,
        "default_duration_minutes": 15,
    },
    "temporary_network_restriction": {
        "base_level": AutonomyLevel.LEVEL_2,
        "reversible": True,
        "reversible_alternative": "rate_limit",
        "description": "Temporary network segment restriction",
        "risk_tiers": [RiskTier.MEDIUM, RiskTier.HIGH],
        "requires_human": True,
        "default_duration_minutes": 15,
    },
    "quarantine_file": {
        "base_level": AutonomyLevel.LEVEL_2,
        "reversible": True,
        "reversible_alternative": "monitor",
        "description": "Quarantine suspicious file (restorable from quarantine)",
        "risk_tiers": [RiskTier.MEDIUM, RiskTier.HIGH],
        "requires_human": True,
        "default_duration_minutes": 60,
    },
    "restrict_session": {
        "base_level": AutonomyLevel.LEVEL_2,
        "reversible": True,
        "reversible_alternative": "monitor",
        "description": "Temporarily restrict suspicious session",
        "risk_tiers": [RiskTier.MEDIUM, RiskTier.HIGH],
        "requires_human": True,
        "default_duration_minutes": 30,
    },
    "apply_reversible_rule": {
        "base_level": AutonomyLevel.LEVEL_2,
        "reversible": True,
        "reversible_alternative": "rate_limit",
        "description": "Apply reversible security rule (firewall, WAF)",
        "risk_tiers": [RiskTier.MEDIUM, RiskTier.HIGH],
        "requires_human": True,
        "default_duration_minutes": 15,
    },

    # LEVEL 3 — Verify → Policy → Controlled containment → Audit → Rollback
    "block_ip": {
        "base_level": AutonomyLevel.LEVEL_3,
        "reversible": True,
        "reversible_alternative": "temporary_ip_restriction",
        "description": "Block IP at firewall (requires human approval)",
        "risk_tiers": [RiskTier.HIGH, RiskTier.CRITICAL],
        "requires_human": True,
        "default_duration_minutes": 60,
    },
    "disable_account": {
        "base_level": AutonomyLevel.LEVEL_3,
        "reversible": True,
        "reversible_alternative": "restrict_session",
        "description": "Disable user account (admin must re-enable)",
        "risk_tiers": [RiskTier.HIGH, RiskTier.CRITICAL],
        "requires_human": True,
        "default_duration_minutes": 60,
    },
    "kill_process": {
        "base_level": AutonomyLevel.LEVEL_3,
        "reversible": False,  # Process termination is not cleanly reversible
        "reversible_alternative": "restrict_session",
        "description": "Kill process on endpoint",
        "risk_tiers": [RiskTier.HIGH, RiskTier.CRITICAL],
        "requires_human": True,
        "default_duration_minutes": 0,
    },
    "isolate_host": {
        "base_level": AutonomyLevel.LEVEL_3,
        "reversible": True,
        "reversible_alternative": "temporary_network_restriction",
        "description": "Network isolate host (VLAN move / ACL)",
        "risk_tiers": [RiskTier.HIGH, RiskTier.CRITICAL],
        "requires_human": True,
        "default_duration_minutes": 60,
    },
    "change_firewall_policy": {
        "base_level": AutonomyLevel.LEVEL_3,
        "reversible": True,
        "reversible_alternative": "temporary_ip_restriction",
        "description": "Modify firewall rule/policy",
        "risk_tiers": [RiskTier.HIGH, RiskTier.CRITICAL],
        "requires_human": True,
        "default_duration_minutes": 30,
    },

    # LEVEL 4+ — Irreversible / critical (never automatic, emergency policy only)
    "delete_system_files": {
        "base_level": AutonomyLevel.LEVEL_3,
        "reversible": False,
        "reversible_alternative": None,
        "description": "Delete system files (IRREVERSIBLE — emergency only)",
        "risk_tiers": [RiskTier.CRITICAL],
        "requires_human": True,
        "default_duration_minutes": 0,
    },
    "shutdown_service": {
        "base_level": AutonomyLevel.LEVEL_3,
        "reversible": False,
        "reversible_alternative": "isolate_host",
        "description": "Shutdown critical service (high impact)",
        "risk_tiers": [RiskTier.CRITICAL],
        "requires_human": True,
        "default_duration_minutes": 0,
    },
    "permanent_block": {
        "base_level": AutonomyLevel.LEVEL_3,
        "reversible": False,
        "reversible_alternative": "block_ip",
        "description": "Permanent IP block (no auto-expiry)",
        "risk_tiers": [RiskTier.CRITICAL],
        "requires_human": True,
        "default_duration_minutes": 0,
    },
}


def get_action_catalog() -> Dict[str, Dict[str, Any]]:
    """Return the full action catalog."""
    return ACTION_CATALOG


def get_action_info(action: str) -> Optional[Dict[str, Any]]:
    """Get catalog entry for an action, or None if unknown."""
    return ACTION_CATALOG.get(action)


def get_reversibility(action: str) -> int:
    """Get reversibility score (0=fully reversible, 5=irreversible)."""
    return REVERSIBILITY_LADDER.get(action, 3)


def get_reversible_alternative(action: str) -> Optional[str]:
    """Get the reversible alternative for an action, if defined."""
    info = ACTION_CATALOG.get(action)
    if info:
        return info.get("reversible_alternative")
    return None


def is_reversible(action: str) -> bool:
    """Check if action is reversible."""
    info = ACTION_CATALOG.get(action)
    if info:
        return info.get("reversible", False)
    return REVERSIBILITY_LADDER.get(action, 3) <= 2