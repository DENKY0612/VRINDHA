"""Vrindha Coordination Layer — HIVE coordinated multi-agent intelligence.

One organization, many specialists, shared intelligence, common event model,
central coordination, human accountability:

* Commander AI — coordinates (does not do everything itself)
* Infrastructure AI — observes infrastructure (telemetry)
* Threat Intelligence AI — explains external threat context (never fabricated)
* SOC Analyst AI — investigates
* Data Science AI — analyzes data, models risk, learns from validated outcomes
* Knowledge AI — remembers validated lessons
* Ethics & Compliance AI — governs consequential actions (Dharma + Gita,
  law/policy guidance, verified verse references only)
* Vrindha AI — anti-hallucination, evidence-grounded security analysis
  (FACT/INFERENCE/UNKNOWN separation, verified TI, risk+confidence,
  structured reports, audit trail, feedback loop)
* Controlled Response Engine — controlled autonomy: LEVEL 1 auto-monitor,
  LEVEL 2 recommend → human approval, LEVEL 3 verify → policy → human
  approval → controlled containment → audit → rollback; critical-asset and
  allowlist protection, reversibility first, explicit emergency policies,
  time limits, safe mode
* Human — authorizes every state-changing decision

All agents communicate through :mod:`.event_bus`, never directly with each
other. The existing Vrindha safety controls (Brain, Dharma Engine,
authorization layer, JWT auth) remain fully functional and are reused, not
replaced.
"""
from pathlib import Path
import sys

_repo = Path(__file__).resolve().parents[2]
if (_repo / "Vrin_TI").is_dir() and str(_repo) not in sys.path:
    sys.path.insert(0, str(_repo))

try:
    from vrin_SOC._imports import bind_package
except ImportError:  # flat image / unpackaged checkout
    bind_package = None

if bind_package is not None:
    bind_package(__name__)

from .controlled_response import (
    ACTION_CATALOG,
    VRINDHA_RESPONSE_PROMPT,
    AutonomyPolicy,
    ControlledResponseEngine,
    EmergencyPolicy,
    controlled_response_engine,
    render_action_preview,
    render_response,
)
from .data_science_ai import FEATURE_NAMES, DataScienceAI, RiskConfig, data_science_ai
from .event_bus import EventBus, InMemoryTransport, event_bus
from .ethics_ai import (
    DHARMA_PRINCIPLES,
    BhagavadGitaKnowledgeBase,
    DharmaRecognitionEngine,
    EthicsAI,
    gita_knowledge_base,
    ethics_ai,
)
from .infrastructure_ai import InfrastructureAI, infrastructure_ai
from .knowledge_ai import KnowledgeAI, knowledge_ai
from .observability import AgentMetrics, BaseAgent
from .schemas import (
    AnomalyResult,
    AssetCriticality,
    AutonomyLevel,
    ClassifiedFinding,
    ExecutionMode,
    ResponseDecision,
    RiskTier,
    RollbackRecord,
    DataQualityReport,
    EntityRef,
    EthicsAssessment,
    Incident,
    IncidentStatus,
    ModelMetadata,
    Provenance,
    RiskFactor,
    RiskResult,
    SecurityAnalysis,
    SecurityEvent,
    ThreatIntelStatus,
)
from .evidence_analysis import (
    VRINDHA_AI_PROMPT,
    VrindhaAI,
    enforce_claim_guard,
    render_report,
    vrindha_ai,
)
from .soc_analyst_ai import SOCAnalystAI, soc_analyst_ai
from .threat_intel_ai import ThreatIntelAI, threat_intel_ai

__all__ = [
    "FEATURE_NAMES",
    "DataScienceAI",
    "RiskConfig",
    "data_science_ai",
    "EventBus",
    "InMemoryTransport",
    "event_bus",
    "DHARMA_PRINCIPLES",
    "BhagavadGitaKnowledgeBase",
    "DharmaRecognitionEngine",
    "EthicsAI",
    "gita_knowledge_base",
    "ethics_ai",
    "InfrastructureAI",
    "infrastructure_ai",
    "KnowledgeAI",
    "knowledge_ai",
    "AgentMetrics",
    "BaseAgent",
    "AnomalyResult",
    "DataQualityReport",
    "EntityRef",
    "EthicsAssessment",
    "Incident",
    "IncidentStatus",
    "ModelMetadata",
    "Provenance",
    "RiskFactor",
    "RiskResult",
    "SecurityAnalysis",
    "SecurityEvent",
    "SOCAnalystAI",
    "soc_analyst_ai",
    "ThreatIntelAI",
    "threat_intel_ai",
    "ThreatIntelStatus",
    "ClassifiedFinding",
    "VRINDHA_AI_PROMPT",
    "VrindhaAI",
    "vrindha_ai",
    "render_report",
    "enforce_claim_guard",
    "ACTION_CATALOG",
    "VRINDHA_RESPONSE_PROMPT",
    "AutonomyPolicy",
    "ControlledResponseEngine",
    "EmergencyPolicy",
    "controlled_response_engine",
    "render_action_preview",
    "render_response",
    "AssetCriticality",
    "AutonomyLevel",
    "ExecutionMode",
    "ResponseDecision",
    "RiskTier",
    "RollbackRecord",
]
