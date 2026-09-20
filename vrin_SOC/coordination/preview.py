"""
Action Preview Rendering for Controlled Response engine.

Implements §8: render_action_preview — human-readable preview of what an action will do,
including risk, reversibility, duration, and rollback plan.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .schemas import (
    AssetCriticality,
    AutonomyLevel,
    ExecutionMode,
    ResponseDecision,
    RiskTier,
    utc_now_iso,
)
from .action_catalog import (
    ACTION_CATALOG,
    REVERSIBILITY_LADDER,
    get_action_info,
    get_reversible_alternative,
    is_reversible,
)


def render_action_preview(decision: ResponseDecision) -> str:
    """
    Render a human-readable preview of the proposed action (§8).

    Includes: action description, risk tier, autonomy level, reversibility,
    duration, rollback plan, and human approval requirement.
    """
    action_info = get_action_info(decision.action)
    catalog = action_info or {}

    lines = [
        "╔══════════════════════════════════════════════════════════════╗",
        f"║  ACTION PREVIEW: {decision.action:<42} ║",
        "╠══════════════════════════════════════════════════════════════╣",
    ]

    # Basic info
    lines.append(f"║  Target: {decision.target} ({decision.target_kind})")
    lines.append(f"║  Risk Score: {decision.risk_score}/100  │  Risk Tier: {decision.risk_tier.value}")
    lines.append(f"║  Confidence: {decision.confidence_score}/100  │  TI Status: {decision.ti_status.value}")
    lines.append("╠══════════════════════════════════════════════════════════════╣")

    # Action details
    desc = catalog.get("description", "No description available")
    lines.append(f"║  Action: {desc}")
    base_level = catalog.get("base_level", AutonomyLevel.MONITOR)
    lines.append(f"║  Base Autonomy Level: {base_level.value}")
    lines.append(f"║  Execution Mode: {decision.execution_mode.value}")

    # Reversibility
    reversible = catalog.get("reversible", is_reversible(decision.action))
    rev_score = REVERSIBILITY_LADDER.get(decision.action, 3)
    rev_status = "✅ Reversible" if reversible else "⚠️ IRREVERSIBLE"
    lines.append(f"║  Reversibility: {rev_status} (ladder score: {rev_score}/5)")

    if reversible:
        alt = get_reversible_alternative(decision.action)
        if alt:
            lines.append(f"║  Reversible Alternative: {alt}")

    # Duration
    expires_at = decision.expires_at
    if expires_at:
        lines.append(f"║  Expires: {expires_at}")
    default_dur = catalog.get("default_duration_minutes", 0)
    if default_dur > 0:
        lines.append(f"║  Default Duration: {default_dur} minutes")

    # Asset criticality
    lines.append(f"║  Asset Criticality: {decision.asset_criticality.value}")

    # Allowlist conflicts
    if decision.allowlist_conflicts:
        conflicts = ", ".join(decision.allowlist_conflicts)
        lines.append(f"║  ⚠️ ALLOWLIST CONFLICTS: {conflicts}")

    # Independent sources
    if decision.independent_sources:
        lines.append(f"║  Independent Sources: {len(decision.independent_sources)}")
        for src in decision.independent_sources[:3]:
            lines.append(f"║    - {src}")
        if len(decision.independent_sources) > 3:
            lines.append(f"║    ... and {len(decision.independent_sources) - 3} more")

    # Human approval
    if decision.requires_approval:
        lines.append("╠══════════════════════════════════════════════════════════════╣")
        lines.append("║  🔴 HUMAN APPROVAL REQUIRED")
        lines.append(f"║  Reason: {decision.approval_reason}")
        lines.append("║  Action cannot execute until explicit approval is given.")
    elif decision.execution_mode == ExecutionMode.AUTOMATIC:
        lines.append("╠══════════════════════════════════════════════════════════════╣")
        lines.append("║  🟢 AUTOMATIC EXECUTION (policy permits)")
    else:
        lines.append("╠══════════════════════════════════════════════════════════════╣")
        lines.append("║  🟡 MONITOR ONLY (no state change)")

    # Rollback plan
    lines.append("╠══════════════════════════════════════════════════════════════╣")
    lines.append("║  ROLLBACK PLAN:")
    if reversible:
        alt = get_reversible_alternative(decision.action)
        if alt:
            lines.append(f"║  1. Execute reversible alternative: {alt}")
        lines.append("║  2. Automatic expiry removes the action at expiration time")
        lines.append("║  3. Manual rollback available via: rollback(action_id)")
        lines.append("║  4. Rollback restores pre-action state (where possible)")
    else:
        lines.append("║  ⚠️  ACTION IS IRREVERSIBLE — no automatic rollback")
        lines.append("║  1. No automatic rollback available")
        lines.append("║  2. Manual remediation required if action is incorrect")
        lines.append("║  3. Forensic evidence preserved for investigation")

    # Audit trail
    lines.append("╠══════════════════════════════════════════════════════════════╣")
    lines.append("║  AUDIT TRAIL:")
    lines.append("║  - Decision recorded in response_audit table (immutable)")
    lines.append("║  - Rollback record created in rollback_records table")
    lines.append("║  - All reviews appended (never rewritten)")
    lines.append("║  - Correlation ID: " + (decision.correlation_id or "N/A"))

    lines.append("╚══════════════════════════════════════════════════════════════╝")

    return "\n".join(lines)


def render_response(decision: ResponseDecision) -> Dict[str, Any]:
    """
    Render the required response format (§15).

    Returns the structured dict that matches the contract output format.
    """
    action_info = get_action_info(decision.action) or {}

    return {
        "decision_id": decision.decision_id,
        "action": decision.action,
        "target": decision.target,
        "target_kind": decision.target_kind,
        "risk_score": decision.risk_score,
        "risk_tier": decision.risk_tier.value,
        "confidence_score": decision.confidence_score,
        "execution_mode": decision.execution_mode.value,
        "autonomy_level": decision.autonomy_level.value,
        "asset_criticality": decision.asset_criticality.value,
        "allowlist_conflicts": decision.allowlist_conflicts,
        "independent_sources": decision.independent_sources or [],
        "requires_approval": decision.requires_approval,
        "approval_reason": decision.approval_reason,
        "reversible": action_info.get("reversible", is_reversible(decision.action)),
        "reversible_alternative": get_reversible_alternative(decision.action),
        "expires_at": decision.expires_at,
        "reason": decision.reason,
        "evidence": decision.evidence,
        "correlation_id": decision.correlation_id,
        "timestamp": decision.timestamp or utc_now_iso(),
    }


def format_preview_plain(decision: ResponseDecision) -> str:
    """Plain-text version without box drawing for terminal compatibility."""
    action_info = get_action_info(decision.action) or {}
    desc = action_info.get("description", "No description")
    base_level = action_info.get("base_level", AutonomyLevel.MONITOR).value

    reversible = action_info.get("reversible", is_reversible(decision.action))
    alt = get_reversible_alternative(decision.action)

    parts = [
        f"ACTION PREVIEW: {decision.action}",
        f"Target: {decision.target} ({decision.target_kind})",
        f"Risk: {decision.risk_score}/100 ({decision.risk_tier.value})",
        f"Confidence: {decision.confidence_score}/100",
        f"TI Status: {decision.ti_status.value}",
        f"Description: {desc}",
        f"Base Level: {base_level}",
        f"Execution: {decision.execution_mode.value}",
        f"Reversible: {'Yes' if reversible else 'NO - IRREVERSIBLE'}",
    ]

    if alt:
        parts.append(f"Reversible Alternative: {alt}")
    if decision.expires_at:
        parts.append(f"Expires: {decision.expires_at}")
    parts.append(f"Asset Criticality: {decision.asset_criticality.value}")

    if decision.allowlist_conflicts:
        parts.append(f"⚠️ ALLOWLIST CONFLICTS: {', '.join(decision.allowlist_conflicts)}")

    if decision.requires_approval:
        parts.append(f"🔴 HUMAN APPROVAL REQUIRED: {decision.approval_reason}")
    elif decision.execution_mode == ExecutionMode.AUTOMATIC:
        parts.append("🟢 AUTOMATIC EXECUTION")
    else:
        parts.append("🟡 MONITOR ONLY")

    parts.append("ROLLBACK PLAN:")
    if reversible:
        parts.append("  - Reversible alternative available")
        parts.append("  - Auto-expires at expiration time")
        parts.append("  - Manual rollback via rollback(action_id)")
    else:
        parts.append("  - NO automatic rollback (irreversible)")

    parts.append("AUDIT: decision_id=" + decision.decision_id)

    return "\n".join(parts)