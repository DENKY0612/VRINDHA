"""
Policy definitions for Controlled Autonomous Response & Safety engine.

Contains: EmergencyPolicy, AutonomyPolicy, and related validation logic.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
# EmergencyPolicy — explicitly configured emergency response rules
# ---------------------------------------------------------------------------
class EmergencyPolicy:
    """Emergency policy as defined in §7 of the contract.

    Must be explicitly configured via autonomy_policy.json or API.
    Only reversible, time-limited LEVEL ≤ 2 actions can be automated.
    """

    def __init__(self, raw: Dict[str, Any]) -> None:
        self.name = raw.get("name", "")
        self.enabled = bool(raw.get("enabled", False))
        self.triggers = raw.get("triggers", {})
        self.allowed_actions = raw.get("allowed_actions", [])
        self.scope = raw.get("scope", {})
        self.max_duration_minutes = int(raw.get("max_duration_minutes", 15))

    def validate(self) -> List[str]:
        """Return list of validation errors (empty if valid)."""
        errors = []
        if not self.name:
            errors.append("EmergencyPolicy: name is required")
        if not self.enabled:
            errors.append(f"EmergencyPolicy '{self.name}': enabled must be true")
        if not self.allowed_actions:
            errors.append(f"EmergencyPolicy '{self.name}': allowed_actions cannot be empty")
        if self.max_duration_minutes > 60:
            errors.append(f"EmergencyPolicy '{self.name}': max_duration_minutes must be ≤ 60")
        return errors

    def matches(
        self, decision: "ResponseDecision", event_type: str
    ) -> Tuple[bool, str]:
        """Check if this emergency policy applies to the given decision/event."""
        if not self.enabled:
            return False, "policy disabled"
        if decision.action not in self.allowed_actions:
            return False, f"action '{decision.action}' not in allowed_actions"
        triggers = self.triggers
        if triggers.get("event_types") and event_type not in triggers["event_types"]:
            return False, f"event_type '{event_type}' not in triggers.event_types"
        if triggers.get("min_risk") and decision.risk_score < triggers["min_risk"]:
            return False, f"risk_score {decision.risk_score} < min_risk {triggers['min_risk']}"
        if triggers.get("min_confidence") and decision.confidence_score < triggers["min_confidence"]:
            return False, f"confidence {decision.confidence_score} < min_confidence {triggers['min_confidence']}"
        if triggers.get("min_independent_sources") and len(decision.independent_sources or []) < triggers["min_independent_sources"]:
            return False, "insufficient independent sources"
        if triggers.get("require_ti_confirmed") and decision.ti_status != ThreatIntelStatus.AVAILABLE:
            return False, "TI confirmation required but TI unavailable"
        return True, "matches"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "triggers": self.triggers,
            "allowed_actions": self.allowed_actions,
            "scope": self.scope,
            "max_duration_minutes": self.max_duration_minutes,
        }


# ---------------------------------------------------------------------------
# AutonomyPolicy — asset criticality, allowlist, thresholds
# ---------------------------------------------------------------------------
class AutonomyPolicy:
    """Policy loaded from autonomy_policy.json (or defaults).

    Governs: allowlists, asset criticality, risk thresholds, emergency policies.
    """

    def __init__(self, raw: Optional[Dict[str, Any]] = None) -> None:
        raw = raw or {}
        self.allowlist = raw.get("allowlist", {})
        self.thresholds = raw.get("thresholds", {})
        self.auto_level1 = bool(raw.get("auto_level1", True))
        self.protect_private_ranges = bool(raw.get("protect_private_ranges", True))
        self.default_duration_minutes = int(raw.get("default_duration_minutes", 15))
        self.chain_cooldown_minutes = int(raw.get("chain_cooldown_minutes", 10))
        self.emergency_policies = [
            EmergencyPolicy(p) for p in raw.get("emergency_policies", [])
        ]

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "AutonomyPolicy":
        if path is None:
            # Default location
            repo_root = Path(__file__).resolve().parents[2]
            path = repo_root / "vrin_SOC" / "config" / "autonomy_policy.json"
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        else:
            raw = {}
        return cls(raw)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowlist": self.allowlist,
            "thresholds": self.thresholds,
            "auto_level1": self.auto_level1,
            "protect_private_ranges": self.protect_private_ranges,
            "default_duration_minutes": self.default_duration_minutes,
            "chain_cooldown_minutes": self.chain_cooldown_minutes,
            "emergency_policies": [p.to_dict() for p in self.emergency_policies],
        }

    def allowlist_conflict(self, target: str, target_kind: str) -> List[str]:
        """Return list of allowlist conflicts for the target."""
        conflicts = []
        target_lower = target.lower()
        for category, items in self.allowlist.items():
            if not isinstance(items, list):
                continue
            for item in items:
                if target_lower == item.lower() or (target_kind == "ip" and self._ip_matches(target, item)):
                    conflicts.append(f"{category}:{item}")
        return conflicts

    def _ip_matches(self, target: str, pattern: str) -> bool:
        try:
            import ipaddress
            if "/" in pattern:
                return ipaddress.ip_address(target) in ipaddress.ip_network(pattern, strict=False)
            return target == pattern
        except Exception:
            return False

    def asset_criticality(
        self, target: str, target_kind: str
    ) -> AssetCriticality:
        """Determine asset criticality (§3): explicit metadata first, heuristics second."""
        # Critical servers from allowlist
        for server in self.allowlist.get("critical_servers", []):
            if target.lower() == server.lower():
                return AssetCriticality.CRITICAL
        # Private IP ranges
        if target_kind == "ip" and self.protect_private_ranges:
            if self._is_private_ip(target):
                return AssetCriticality.HIGH
        # Essential processes
        for proc in self.allowlist.get("essential_processes", []):
            if target.lower() == proc.lower():
                return AssetCriticality.HIGH
        return AssetCriticality.NORMAL

    def _is_private_ip(self, ip: str) -> bool:
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def _join(reasons: List[str]) -> str:
    return " + ".join(r for r in reasons if r)


def _crit_rank(level: AssetCriticality) -> int:
    return {
        AssetCriticality.CRITICAL: 3,
        AssetCriticality.HIGH: 2,
        AssetCriticality.NORMAL: 1,
        AssetCriticality.LOW: 0,
    }.get(level, 1)