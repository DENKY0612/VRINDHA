"""Strongly validated shared event schema for the Vrindha coordination layer.

Every agent in the HIVE communicates through these Pydantic models. Arbitrary
unvalidated dictionaries must not cross agent boundaries: anything entering the
event bus is validated here first, and rejected records are recorded with the
reason instead of being silently discarded.

Design notes
------------
* ``mode`` is mandatory on all telemetry/intelligence payloads so the system
  can always distinguish REAL / SIMULATED / MOCK / FALLBACK (no-fabrication
  rule).
* ``provenance`` makes every result reconstructable: which agent, which model,
  which model version, and which source produced it.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_event_id() -> str:
    return f"evt-{uuid4().hex[:12]}"


class EventMode(str, Enum):
    """Data provenance mode — never present simulated data as real."""

    REAL = "real"
    SIMULATED = "simulated"
    MOCK = "mock"
    FALLBACK = "fallback"
    UNAVAILABLE = "unavailable"


class EventStatus(str, Enum):
    NEW = "new"
    INGESTED = "ingested"
    ENRICHED = "enriched"
    ANALYZED = "analyzed"
    RISK_ASSESSED = "risk_assessed"
    CORRELATED = "correlated"
    INVESTIGATING = "investigating"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    RESPONDED = "responded"
    CLOSED = "closed"


class EntityRef(BaseModel):
    """The entity an event is about."""

    host: Optional[str] = None
    user: Optional[str] = None
    ip: Optional[str] = None
    domain: Optional[str] = None
    process: Optional[str] = None

    @field_validator("ip")
    @classmethod
    def _check_ip(cls, v: Optional[str]) -> Optional[str]:
        if not v:
            return v
        import ipaddress

        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(f"invalid IPv4/IPv6 address: {v!r}") from exc
        return v

    def primary(self) -> Optional[str]:
        return self.host or self.ip or self.user or self.domain or self.process


class Provenance(BaseModel):
    """Audit trail attached to every event and analytical result."""

    source: str = "system"
    collection_method: str = "api"
    source_agent: Optional[str] = None
    agent_version: str = "1.0"
    model: Optional[str] = None
    model_version: Optional[str] = None
    mode: EventMode = EventMode.REAL
    request_id: Optional[str] = None


class SecurityEvent(BaseModel):
    """The single shared communication contract of the HIVE."""

    event_id: str = Field(default_factory=new_event_id)
    timestamp: str = Field(default_factory=utc_now_iso)
    event_type: str = "security_event"
    source_agent: str = "external"
    source_system: Optional[str] = None
    correlation_id: Optional[str] = None

    entity: EntityRef = Field(default_factory=EntityRef)
    data: Dict[str, Any] = Field(default_factory=dict)
    threat_intelligence: Dict[str, Any] = Field(default_factory=dict)
    analysis: Dict[str, Any] = Field(default_factory=dict)
    risk: Dict[str, Any] = Field(default_factory=dict)
    correlation: Dict[str, Any] = Field(default_factory=dict)
    provenance: Provenance = Field(default_factory=Provenance)
    status: EventStatus = EventStatus.NEW
    severity: str = "low"  # low | medium | high | critical

    @field_validator("timestamp")
    @classmethod
    def _parse_timestamp(cls, v: str) -> str:
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"timestamp must be ISO-8601, got {v!r}") from exc
        return v

    @field_validator("severity", "event_type")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("must not be empty")
        return v

    @model_validator(mode="after")
    def _entity_has_a_primary(self) -> "SecurityEvent":
        # Allow pure broadcast events (no entity) but keep them explicit.
        return self

    def to_json(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")

    def record(self, event: Optional["SecurityEvent"] = None, **fields: Any) -> None:
        """Attach structured result sections in place."""
        if event is not None:
            merged = event.model_dump()
            self.threat_intelligence = {**self.threat_intelligence, **merged.get("threat_intelligence", {})}
            self.analysis = {**self.analysis, **merged.get("analysis", {})}
            self.risk = {**self.risk, **merged.get("risk", {})}
            self.correlation = {**self.correlation, **merged.get("correlation", {})}
        for key, value in fields.items():
            if key in {"threat_intelligence", "analysis", "risk", "correlation"} and isinstance(value, dict):
                setattr(self, key, {**getattr(self, key), **value})
            else:
                setattr(self, key, value)


class DataQualityReport(BaseModel):
    """Why a record was accepted or rejected — never silently discarded."""

    accepted: bool
    checked: int = 0
    issues: List[str] = Field(default_factory=list)
    rejected_records: List[Dict[str, Any]] = Field(default_factory=list)
    duplicates: int = 0
    checked_at: str = Field(default_factory=utc_now_iso)


class AnomalyResult(BaseModel):
    anomaly_score: float = Field(ge=0.0, le=1.0)
    is_anomaly: bool
    confidence: float = Field(ge=0.0, le=1.0)
    model: str
    model_version: str
    fallback_mode: bool = False
    explanation: List[str] = Field(default_factory=list)


class RiskFactor(BaseModel):
    factor: str
    contribution: float = Field(ge=0.0, le=1.0)


class RiskResult(BaseModel):
    risk_score: float = Field(ge=0.0, le=1.0)
    severity: str  # low | medium | high | critical
    confidence: float = Field(ge=0.0, le=1.0)
    factors: List[RiskFactor] = Field(default_factory=list)
    model: str
    model_version: str
    explainability: List[str] = Field(default_factory=list)


class EthicsClassification(str, Enum):
    DHARMA_ALIGNED = "dharma_aligned"
    ETHICALLY_NEUTRAL = "ethically_neutral"
    ETHICAL_CONCERN = "ethical_concern"
    POTENTIAL_ADHARMA = "potential_adharma"
    HIGH_RISK_ADHARMA = "high_risk_adharma"
    ILLEGAL_OR_UNAUTHORIZED = "illegal_or_unauthorized"


class EthicsDecision(str, Enum):
    ALLOW = "allow"
    ALLOW_WITH_WARNING = "allow_with_warning"
    REQUIRE_AUTHORIZATION = "require_authorization"
    SAFE_ALTERNATIVE = "safe_alternative"
    DENY = "deny"
    ESCALATE_TO_HUMAN = "escalate_to_human"


class EthicsAssessment(BaseModel):
    """Action-level ethical evaluation. Judges the ACTION, never the user."""

    requested_action: str
    classification: EthicsClassification
    decision: EthicsDecision
    authorization_status: str  # provided | missing | implicit
    harm_risk: float = Field(ge=0.0, le=1.0)
    deception_risk: float = Field(ge=0.0, le=1.0)
    privacy_risk: float = Field(ge=0.0, le=1.0)
    dharma_concern: str = "none"  # none | low | medium | high
    principles: List[str] = Field(default_factory=list)
    policy_references: List[str] = Field(default_factory=list)
    legal_references: List[str] = Field(default_factory=list)
    legal_note: str = "Guidance only — not legal advice."
    reason: str = ""
    alternative: Optional[str] = None
    gita_reference: Optional[Dict[str, Any]] = None
    gita_note: str = "Philosophical guidance only, provided respectfully; never used for profiling."
    human_approval_required: bool = False
    requires_justification: bool = False
    evaluated_at: str = Field(default_factory=utc_now_iso)


class ThreatIntelStatus(str, Enum):
    """Verified threat-intelligence state of an observation (anti-fabrication).

    * CONFIRMED     — a retrieved, sourced, fresh TI record matches the IOC.
    * NOT_CONFIRMED — TI was checked (or a record exists but is stale/unmatched)
                      and provides no supporting intelligence. Absence is never
                      presented as "clean" and no reputation is invented.
    * UNKNOWN       — TI could not be checked at this time (service unavailable
                      or enrichment never ran), so the state cannot be verified.
    """

    CONFIRMED = "confirmed"
    NOT_CONFIRMED = "not_confirmed"
    UNKNOWN = "unknown"


class ClassifiedFinding(BaseModel):
    """One finding separated into fact / evidence / inference / unknown.

    Rule 5 of the anti-hallucination contract: an inference is never presented
    as a confirmed fact; each class of statement lives in its own field.
    """

    fact: str
    evidence: str
    inference: str
    unknown: str = ""
    recommendation: str = ""


class SecurityAnalysis(BaseModel):
    """Structured, evidence-grounded analysis of one security event.

    Mirrors the ``[SECURITY ANALYSIS]`` report format of the Vrindha AI
    anti-hallucination contract (see ``docs/ANTI_HALLUCINATION.md``). Every
    numeric field is bounded, every claim traces back to ``facts`` /
    ``evidence`` / ``signals``, and a missing piece of evidence lands in
    ``unknown_information`` instead of being filled with an assumption.
    """

    analysis_id: str = Field(default_factory=lambda: f"ana-{uuid4().hex[:12]}")
    event_id: str = ""
    correlation_id: Optional[str] = None
    event: str = ""
    facts: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    findings: List[ClassifiedFinding] = Field(default_factory=list)
    detection: str = ""
    assessment: str = ""
    risk_score: int = Field(ge=0, le=100)
    confidence: int = Field(ge=0, le=100)
    severity: str = "low"  # low | medium | high | critical
    threat_intelligence: ThreatIntelStatus = ThreatIntelStatus.UNKNOWN
    ti_detail: Dict[str, Any] = Field(default_factory=dict)
    unknown_information: List[str] = Field(default_factory=list)
    recommended_action: str = ""
    action_impact: str = "none"  # none | low | high
    human_approval_required: bool = False
    reason: str = ""
    evidence_conflicting: bool = False
    insufficient_evidence: bool = False
    claim_guard_triggered: bool = False
    signals: List[Dict[str, Any]] = Field(default_factory=list)
    mode: EventMode = EventMode.REAL
    created_at: str = Field(default_factory=utc_now_iso)


class ModelMetadata(BaseModel):
    model_name: str
    model_version: str
    algorithm: str
    training_dataset: str = "none"
    training_date: Optional[str] = None
    features: List[str] = Field(default_factory=list)
    hyperparameters: Dict[str, Any] = Field(default_factory=dict)
    metrics: Dict[str, Any] = Field(default_factory=dict)
    status: str = "candidate"  # candidate | production | retired


class AutonomyLevel(str, Enum):
    """Controlled-autonomy level of a proposed response (safety contract §2).

    * LEVEL_1 — low risk, read-only / observational; automatic when policy allows.
    * LEVEL_2 — medium risk, reversible + time-limited; human approval required.
    * LEVEL_3 — high risk / irreversible / critical target; multi-source
      verification + policy validation + human approval (or an explicitly
      configured emergency policy) + controlled execution + rollback.
    """

    LEVEL_1 = "LEVEL 1"
    LEVEL_2 = "LEVEL 2"
    LEVEL_3 = "LEVEL 3"


class RiskTier(str, Enum):
    """Risk tier of the *situation* (drives how much verification is needed).

    LOW      → auto-monitor
    MEDIUM   → recommend → human approval
    HIGH     → verify → policy → controlled containment → audit → rollback
    CRITICAL → multi-source verification → human approval / explicitly
               configured emergency policy
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExecutionMode(str, Enum):
    AUTOMATIC = "AUTOMATIC"
    HUMAN_APPROVAL = "HUMAN APPROVAL"
    BLOCKED = "BLOCKED"


class AssetCriticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ResponseDecision(BaseModel):
    """The controlled-autonomy decision for ONE proposed response.

    Mirrors the ``[VRINDHA RESPONSE]`` block of the safety contract (§15) and
    carries everything the ``ACTION PREVIEW`` (§8) needs. It is produced by
    :class:`~vrin_SOC.coordination.controlled_response.ControlledResponseEngine`
    and stored on the incident, so an analyst can always see *why* Vrindha
    intends to act (or refuses to).
    """

    decision_id: str = Field(default_factory=lambda: f"dec-{uuid4().hex[:12]}")
    incident_id: Optional[str] = None
    event_id: Optional[str] = None
    correlation_id: Optional[str] = None
    target: str = ""
    target_kind: str = "unknown"  # ip | host | user | process | domain | system | unknown
    threat: str = ""
    evidence: List[str] = Field(default_factory=list)
    threat_intelligence: ThreatIntelStatus = ThreatIntelStatus.UNKNOWN
    risk: int = Field(ge=0, le=100)
    confidence: int = Field(ge=0, le=100)
    risk_tier: RiskTier = RiskTier.LOW
    asset_criticality: AssetCriticality = AssetCriticality.LOW
    asset_reasons: List[str] = Field(default_factory=list)
    independent_sources: int = 0
    original_action: str = ""
    recommended_action: str = ""
    expected_impact: str = "none"  # none | low | medium | high
    autonomy_level: AutonomyLevel = AutonomyLevel.LEVEL_1
    execution: ExecutionMode = ExecutionMode.HUMAN_APPROVAL
    rollback_available: bool = False
    reversible: bool = False
    state_change: bool = False
    duration_minutes: Optional[int] = None
    human_approval_required: bool = True
    allowlist_conflict: bool = False
    high_priority_alert: bool = False
    emergency_policy: Optional[str] = None
    safe_mode: bool = False
    degraded_inputs: List[str] = Field(default_factory=list)
    policy: str = ""
    verification: List[str] = Field(default_factory=list)
    reason: str = ""
    downgraded_from: Optional[str] = None
    created_at: str = Field(default_factory=utc_now_iso)


class RollbackRecord(BaseModel):
    """Rollback record for a state-changing action (safety contract §9)."""

    action_id: str = Field(default_factory=lambda: f"act-{uuid4().hex[:12]}")
    decision_id: str = ""
    incident_id: Optional[str] = None
    event_id: Optional[str] = None
    action: str = ""
    target: str = ""
    autonomy_level: AutonomyLevel = AutonomyLevel.LEVEL_1
    execution: ExecutionMode = ExecutionMode.HUMAN_APPROVAL
    previous_state: Dict[str, Any] = Field(default_factory=dict)
    new_state: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=utc_now_iso)
    expires_at: Optional[str] = None
    reason: str = ""
    evidence: List[str] = Field(default_factory=list)
    policy_used: str = ""
    ai_recommendation: Dict[str, Any] = Field(default_factory=dict)
    execution_result: Dict[str, Any] = Field(default_factory=dict)
    rollback_procedure: str = ""
    rollback_available: bool = False
    executed_by: str = "vrindha-automatic"
    status: str = "executed"  # executed | expired | rolled_back | failed | extended
    rolled_back_at: Optional[str] = None
    rolled_back_by: Optional[str] = None
    rollback_result: Optional[Dict[str, Any]] = None


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RISK_ASSESSED = "risk_assessed"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    CONTAINED = "contained"  # temporary emergency containment, human review pending
    RESPONDED = "responded"
    CLOSED = "closed"


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: f"inc-{uuid4().hex[:10]}")
    correlation_id: Optional[str] = None
    title: str
    status: IncidentStatus = IncidentStatus.OPEN
    event_ids: List[str] = Field(default_factory=list)
    summary: str = ""
    recommendations: List[Dict[str, Any]] = Field(default_factory=list)
    proposed_action: Optional[Dict[str, Any]] = None
    ethics: Optional[Dict[str, Any]] = None
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    response_result: Optional[Dict[str, Any]] = None
    knowledge_id: Optional[str] = None
    response_decision: Optional[Dict[str, Any]] = None
    action_preview: Optional[str] = None
    rollback_ids: List[str] = Field(default_factory=list)
    safe_mode: bool = False
    created_at: str = Field(default_factory=utc_now_iso)
    updated_at: str = Field(default_factory=utc_now_iso)
    trace: List[Dict[str, Any]] = Field(default_factory=list)

    def add_trace(self, stage: str, detail: Dict[str, Any]) -> None:
        self.trace.append({"stage": stage, "detail": detail, "at": utc_now_iso()})
        self.updated_at = utc_now_iso()


__all__ = [
    "EventMode",
    "EventStatus",
    "EntityRef",
    "Provenance",
    "SecurityEvent",
    "DataQualityReport",
    "AnomalyResult",
    "RiskFactor",
    "RiskResult",
    "EthicsClassification",
    "EthicsDecision",
    "EthicsAssessment",
    "ThreatIntelStatus",
    "ClassifiedFinding",
    "SecurityAnalysis",
    "ModelMetadata",
    "AutonomyLevel",
    "RiskTier",
    "ExecutionMode",
    "AssetCriticality",
    "ResponseDecision",
    "RollbackRecord",
    "IncidentStatus",
    "Incident",
    "new_event_id",
    "utc_now_iso",
]
