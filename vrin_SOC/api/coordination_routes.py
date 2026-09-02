"""REST API for the coordination layer (Data Science, agents, Commander,
Ethics & Dharma, Knowledge, coordinator dashboard, safe demo).

All endpoints reuse the existing JWT authentication (deps.get_current_user /
get_current_admin). High-impact operations (human approval, demo trigger,
agent registration) are admin-only. Existing endpoints are untouched.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path as APIPath, Query
from pydantic import BaseModel, Field

from .deps import get_current_admin, get_current_user
from vrin_SOC.coordination.commander import commander_ai
from vrin_SOC.coordination.data_science_ai import data_science_ai
from vrin_SOC.coordination.demo import run_demonstration
from vrin_SOC.coordination.evidence_analysis import vrindha_ai
from vrin_SOC.coordination.ethics_ai import ethics_ai, gita_knowledge_base
from vrin_SOC.coordination.event_bus import event_bus
from vrin_SOC.coordination.infrastructure_ai import infrastructure_ai
from vrin_SOC.coordination.knowledge_ai import knowledge_ai
from vrin_SOC.coordination.schemas import SecurityEvent
from vrin_SOC.coordination.soc_analyst_ai import soc_analyst_ai
from vrin_SOC.coordination.threat_intel_ai import threat_intel_ai

logger = logging.getLogger(__name__)

router = APIRouter(tags=["coordination"])


def internal_error(context: str, exc: Exception) -> HTTPException:
    logger.exception("%s failed", context)
    return HTTPException(status_code=500, detail="Internal server error")


# ----------------------------------------------------------------------
# Request models
# ----------------------------------------------------------------------
class EventIngestRequest(BaseModel):
    event: Dict[str, Any] = Field(default_factory=dict)
    run_pipeline: bool = Field(default=False, description="Also run the full Commander pipeline")


class AnalyzeRequest(BaseModel):
    command: str = Field(min_length=1, max_length=2000)


class EthicsRequest(BaseModel):
    action: str = Field(min_length=1, max_length=2000)
    target: str = Field("", max_length=256)
    context: Dict[str, Any] = Field(default_factory=dict)
    authorization_status: str = Field("missing", pattern=r"^(missing|implicit|provided|explicit)$")
    gita_guidance: bool = True


class TeachRequest(BaseModel):
    topic: str = Field(min_length=3, max_length=500)
    gita_guidance: bool = True


class GitaSearchRequest(BaseModel):
    query: str = Field(min_length=2, max_length=300)
    limit: int = Field(5, ge=1, le=20)


class KnowledgeSearchRequest(BaseModel):
    pattern: str = Field(min_length=1, max_length=300)
    limit: int = Field(10, ge=1, le=50)


class KnowledgeRecordRequest(BaseModel):
    incident_id: str = Field(min_length=1, max_length=64)
    conclusion: str = Field(pattern=r"^(confirmed_attack|false_positive|unknown)$")
    summary: str = Field(min_length=1, max_length=2000)
    event_ids: List[str] = Field(default_factory=list)
    pattern: str = Field("", max_length=300)
    validated_by: str = Field(min_length=1, max_length=128)


class ApprovalRequest(BaseModel):
    approver: str = Field(min_length=1, max_length=128)
    conclusion: str = Field("confirmed_attack", pattern=r"^(confirmed_attack|false_positive|unknown)$")
    justification: str = Field("", max_length=2000)


class RejectRequest(BaseModel):
    approver: str = Field(min_length=1, max_length=128)
    reason: str = Field("", max_length=2000)


class DemoRequest(BaseModel):
    approver: str = Field("demo-human-approver", min_length=1, max_length=128)


class AnalysisFeedbackRequest(BaseModel):
    analyst: str = Field(min_length=1, max_length=128)
    decision: str = Field(pattern=r"^(true_positive|false_positive|insufficient_evidence|unknown)$")
    notes: str = Field("", max_length=2000)


# ----------------------------------------------------------------------
# Data Science AI
# ----------------------------------------------------------------------
@router.get("/data-science/health")
async def data_science_health(user=Depends(get_current_user)):
    return data_science_ai.health()


@router.get("/data-science/status")
async def data_science_status(user=Depends(get_current_user)):
    return await asyncio.to_thread(_ds_status)


def _ds_status() -> Dict[str, Any]:
    return {
        "agent": data_science_ai.health(),
        "data_quality": data_science_ai.data_quality(),
        "bus": event_bus.stats(),
        "models": data_science_ai.models(),
        "validated_samples": len(data_science_ai.validated_samples()),
    }


@router.get("/data-science/metrics")
async def data_science_metrics(user=Depends(get_current_user)):
    return await asyncio.to_thread(data_science_ai.evaluate)


@router.get("/data-science/models")
async def data_science_models(user=Depends(get_current_user)):
    return {"status": "success", "models": data_science_ai.models()}


@router.post("/data-science/events")
async def data_science_ingest(req: EventIngestRequest, user=Depends(get_current_user)):
    """Ingest one raw event: schema validation + data quality, recorded rejections."""
    try:
        return await asyncio.to_thread(_ds_ingest, req.event, req.run_pipeline)
    except Exception as exc:
        raise internal_error("data-science ingest", exc)


def _ds_ingest(event: Dict[str, Any], run_pipeline: bool) -> Dict[str, Any]:
    validated, quality = data_science_ai.ingest(event)
    if validated is None:
        return {"status": "rejected", "data_quality": quality.model_dump(),
                "note": "Rejection recorded with reason; nothing silently discarded."}
    result = {
        "status": "accepted",
        "event_id": validated.event_id,
        "event": validated.to_json(),
        "data_quality": quality.model_dump(),
    }
    if run_pipeline:
        result["pipeline"] = commander_ai.handle_event(event)
    return result


@router.post("/data-science/analyze")
async def data_science_analyze(req: AnalyzeRequest, user=Depends(get_current_user)):
    """Run the full coordinated pipeline (TI → DS → SOC → ethics → approval gate)."""
    try:
        return await asyncio.to_thread(commander_ai.handle_event, {"command": req.command, "event_type": "security_event"})
    except Exception as exc:
        raise internal_error("data-science analyze", exc)


def _event_from_payload(payload: Dict[str, Any]) -> SecurityEvent:
    """Accept either a full SecurityEvent payload or a flat legacy shape."""
    if isinstance(payload, dict) and ("data" in payload or "event_id" in payload or "entity" in payload):
        return SecurityEvent.model_validate(payload)
    data = dict(payload) if isinstance(payload, dict) else {}
    command = str(data.pop("command", None) or data.pop("text", None) or "")
    if command:
        data.setdefault("data", {})["command"] = command
        data.setdefault("event_type", "security_event")
    if not data:
        data = {"data": {"command": command}, "event_type": "security_event"}
    return SecurityEvent(**data)


@router.post("/data-science/anomaly")
async def data_science_anomaly(payload: Dict[str, Any], user=Depends(get_current_user)):
    try:
        event = _event_from_payload(payload)
        result = await asyncio.to_thread(data_science_ai.detect_anomaly, event)
        return result.model_dump()
    except Exception as exc:
        raise internal_error("data-science anomaly", exc)


@router.post("/data-science/risk")
async def data_science_risk(payload: Dict[str, Any], user=Depends(get_current_user)):
    try:
        event = _event_from_payload(payload)
        result = await asyncio.to_thread(data_science_ai.score_risk, event)
        return result.model_dump()
    except Exception as exc:
        raise internal_error("data-science risk", exc)


@router.post("/data-science/features")
async def data_science_features(payload: Dict[str, Any], user=Depends(get_current_user)):
    try:
        event = _event_from_payload(payload)
        return await asyncio.to_thread(data_science_ai.build_features, event)
    except Exception as exc:
        raise internal_error("data-science features", exc)


# ----------------------------------------------------------------------
# Agent observability
# ----------------------------------------------------------------------
@router.get("/agents/health")
async def agents_health(user=Depends(get_current_user)):
    agents = {
        "commander": commander_ai,
        "infrastructure": infrastructure_ai,
        "threat_intel": threat_intel_ai,
        "soc_analyst": soc_analyst_ai,
        "data_science": data_science_ai,
        "knowledge": knowledge_ai,
        "ethics": ethics_ai,
        "vrindha_ai": vrindha_ai,
    }
    return {
        "status": "success",
        "count": len(agents),
        "agents": {key: agent.health() for key, agent in agents.items()},
        "bus": event_bus.stats(),
    }


# ----------------------------------------------------------------------
# Commander — incidents, approval, rejection
# ----------------------------------------------------------------------
@router.post("/commander/events")
async def commander_event(event: Dict[str, Any], user=Depends(get_current_user)):
    """Ingest an event into the coordinated pipeline (human approval gate applies)."""
    try:
        return await asyncio.to_thread(commander_ai.handle_event, event)
    except Exception as exc:
        raise internal_error("commander event", exc)


@router.get("/commander/incidents")
async def commander_incidents(limit: int = Query(50, ge=1, le=200), user=Depends(get_current_user)):
    return await asyncio.to_thread(commander_ai.list_incidents, limit)


@router.get("/commander/incidents/{incident_id}")
async def commander_incident(incident_id: str = APIPath(max_length=64), user=Depends(get_current_user)):
    incident = await asyncio.to_thread(commander_ai.incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident.model_dump()


@router.post("/commander/approve")
async def commander_approve(req: ApprovalRequest, user=Depends(get_current_admin),
                            incident_id: str = Query(min_length=1, max_length=64)):
    """Human approval of a proposed high-impact defensive action (admin only)."""
    try:
        return await asyncio.to_thread(
            commander_ai.approve, incident_id, req.approver, req.conclusion, req.justification
        )
    except Exception as exc:
        raise internal_error("commander approve", exc)


@router.post("/commander/reject")
async def commander_reject(req: RejectRequest, user=Depends(get_current_admin),
                           incident_id: str = Query(min_length=1, max_length=64)):
    try:
        return await asyncio.to_thread(commander_ai.reject, incident_id, req.approver, req.reason)
    except Exception as exc:
        raise internal_error("commander reject", exc)


# ----------------------------------------------------------------------
# Ethics & Compliance (Dharma + verified Gita guidance)
# ----------------------------------------------------------------------
@router.post("/ethics/evaluate")
async def ethics_evaluate(req: EthicsRequest, user=Depends(get_current_user)):
    try:
        assessment = await asyncio.to_thread(
            ethics_ai.evaluate,
            req.action,
            req.target,
            req.context,
            req.authorization_status,
            req.gita_guidance,
        )
        return assessment.model_dump()
    except Exception as exc:
        raise internal_error("ethics evaluate", exc)


@router.get("/ethics/audit")
async def ethics_audit(limit: int = Query(50, ge=1, le=200), user=Depends(get_current_user)):
    return await asyncio.to_thread(ethics_ai.audit_log, limit)


@router.get("/ethics/gita/chapters")
async def gita_chapters(user=Depends(get_current_user)):
    return {
        "status": "success",
        "loaded": gita_knowledge_base.loaded,
        "chapters": gita_knowledge_base.chapter_index(),
        "verse_count": len(gita_knowledge_base.verses),
        "source": "stored dataset vrin_SOC/data/BhagavadGita/ (verified at load; nothing fabricated)",
    }


@router.get("/ethics/gita/{chapter}/{verse}")
async def gita_verse(chapter: int, verse: int, user=Depends(get_current_user)):
    if not (1 <= chapter <= 18 and 1 <= verse <= 300):
        raise HTTPException(status_code=422, detail="chapter must be 1-18, verse 1-300")
    record = gita_knowledge_base.reference(chapter, verse)
    if record is None:
        raise HTTPException(status_code=404,
                            detail=f"Bhagavad Gita {chapter}.{verse} is not in the stored dataset; no fabricated verse will be served")
    return record


@router.post("/ethics/gita/search")
async def gita_search(req: GitaSearchRequest, user=Depends(get_current_user)):
    results = gita_knowledge_base.search(req.query, limit=req.limit)
    return {
        "status": "success",
        "query": req.query,
        "count": len(results),
        "verses": results,
        "note": "Matches come only from the stored, verified dataset.",
    }


@router.post("/ethics/teach")
async def ethics_teach(req: TeachRequest, user=Depends(get_current_user)):
    return await asyncio.to_thread(ethics_ai.teach, req.topic, req.gita_guidance)


# ----------------------------------------------------------------------
# Knowledge AI
# ----------------------------------------------------------------------
@router.get("/knowledge/lessons")
async def knowledge_lessons(limit: int = Query(50, ge=1, le=200), user=Depends(get_current_user)):
    return await asyncio.to_thread(knowledge_ai.lessons, limit)


@router.post("/knowledge/search")
async def knowledge_search(req: KnowledgeSearchRequest, user=Depends(get_current_user)):
    return await asyncio.to_thread(knowledge_ai.search, req.pattern, req.limit)


@router.post("/knowledge/record")
async def knowledge_record(req: KnowledgeRecordRequest, user=Depends(get_current_admin)):
    """Store a VALIDATED outcome (admin only — validated knowledge is guarded)."""
    return await asyncio.to_thread(
        knowledge_ai.record_outcome,
        req.incident_id,
        req.conclusion,
        req.summary,
        req.event_ids,
        req.pattern,
        None,
        req.validated_by,
        True,
    )


# ----------------------------------------------------------------------
# Infrastructure AI
# ----------------------------------------------------------------------
@router.get("/infrastructure/telemetry")
async def infrastructure_telemetry(user=Depends(get_current_user)):
    """Collect REAL local telemetry once and return it (no bus publish)."""
    try:
        event = await asyncio.to_thread(infrastructure_ai.collect_telemetry)
        return event.to_json()
    except Exception as exc:
        raise internal_error("infrastructure telemetry", exc)


@router.post("/infrastructure/telemetry/emit")
async def infrastructure_emit(user=Depends(get_current_admin)):
    try:
        return await asyncio.to_thread(infrastructure_ai.emit_telemetry)
    except Exception as exc:
        raise internal_error("infrastructure telemetry emit", exc)


# ----------------------------------------------------------------------
# Coordinator dashboard + safe demo
# ----------------------------------------------------------------------
@router.get("/coordinator/dashboard")
async def coordinator_dashboard(user=Depends(get_current_user)):
    """Aggregated HIVE Intelligence panel for the dashboard."""
    try:
        return await asyncio.to_thread(_coordinator_dashboard)
    except Exception as exc:
        raise internal_error("coordinator dashboard", exc)


def _coordinator_dashboard() -> Dict[str, Any]:
    incidents = commander_ai.list_incidents(limit=20)
    open_incidents = [i for i in incidents.get("incidents", []) if i["status"] in
                      ("open", "investigating", "risk_assessed", "awaiting_approval", "approved", "responded")]
    history = list(event_bus._history)  # noqa: SLF001 — same-process, deliberate
    recent = history[-100:]
    anomalies = [e for e in recent if (e.analysis or {}).get("anomaly", {}).get("is_anomaly")]
    risks = [e for e in recent if e.risk]
    top_factors: Dict[str, float] = {}
    for event in risks:
        for factor in event.risk.get("factors", []):
            top_factors[factor["factor"]] = round(top_factors.get(factor["factor"], 0.0) + factor["contribution"], 3)
    quality = data_science_ai.data_quality()
    return {
        "status": "success",
        "agents": {key: agent.health() for key, agent in [
            ("commander", commander_ai), ("infrastructure", infrastructure_ai),
            ("threat_intel", threat_intel_ai), ("soc_analyst", soc_analyst_ai),
            ("data_science", data_science_ai), ("knowledge", knowledge_ai),
            ("ethics", ethics_ai), ("vrindha_ai", vrindha_ai),
        ]},
        "bus": event_bus.stats(),
        "totals": {
            "events_published": event_bus.published,
            "active_incidents": len(open_incidents),
            "anomalies": len(anomalies),
            "critical_risks": sum(1 for e in risks if e.risk.get("severity") in {"critical", "high"}),
            "average_risk": round(sum(float(e.risk.get("risk_score", 0)) for e in risks) / len(risks), 4) if risks else 0.0,
        },
        "incidents": open_incidents,
        "risk_timeline": [
            {"event_id": e.event_id, "timestamp": e.timestamp, "risk_score": float(e.risk.get("risk_score", 0)),
             "severity": e.risk.get("severity"), "entity": (e.entity.primary() if e.entity else None)}
            for e in risks[-15:]
        ],
        "anomaly_timeline": [
            {"event_id": e.event_id, "timestamp": e.timestamp,
             "anomaly_score": float(e.analysis["anomaly"].get("anomaly_score", 0))}
            for e in anomalies[-15:]
        ],
        "top_risk_factors": sorted(top_factors.items(), key=lambda kv: kv[1], reverse=True)[:8],
        "data_quality": {"rejected_total": quality["rejected_total"], "seen_events": quality["seen_events"]},
        "models": data_science_ai.models(),
    }


@router.post("/coordinator/demo")
async def coordinator_demo(req: DemoRequest, user=Depends(get_current_admin)):
    """Run the fully labeled SIMULATION end-to-end scenario (admin only)."""
    try:
        return await asyncio.to_thread(run_demonstration, req.approver)
    except Exception as exc:
        raise internal_error("coordinator demo", exc)


# ----------------------------------------------------------------------
# Vrindha AI — anti-hallucination, evidence-grounded analysis
# ----------------------------------------------------------------------
@router.get("/analysis/prompt")
async def analysis_prompt(user=Depends(get_current_user)):
    """The verbatim anti-hallucination operating contract (13 rules)."""
    return await asyncio.to_thread(vrindha_ai.prompt)


@router.post("/analysis/security")
async def analysis_security(payload: Dict[str, Any], user=Depends(get_current_user)):
    """Evidence-grounded structured analysis for one event.

    Accepts a full ``SecurityEvent`` payload (or the flat legacy shape). The
    result is a ``SecurityAnalysis`` plus its rendered ``[SECURITY ANALYSIS]``
    report. No defensive action is executed — high-impact recommendations are
    recommendations only (human approval required).
    """
    try:
        event = _event_from_payload(payload)
        analysis = await asyncio.to_thread(vrindha_ai.analyze, event)
        from vrin_SOC.coordination.evidence_analysis import render_report
        from vrin_SOC.coordination.schemas import SecurityAnalysis

        if not isinstance(analysis, SecurityAnalysis):
            return analysis  # graceful degradation error dict from run_guarded
        return {
            "status": "success",
            "analysis_id": analysis.analysis_id,
            "analysis": analysis.model_dump(mode="json"),
            "report": render_report(analysis),
        }
    except Exception as exc:
        raise internal_error("analysis security", exc)


@router.get("/analysis/audit")
async def analysis_audit(limit: int = Query(50, ge=1, le=200), user=Depends(get_current_user)):
    """Recent analysis audit records (rule 13), newest first."""
    return await asyncio.to_thread(vrindha_ai.list_audit, limit)


@router.get("/analysis/feedback")
async def analysis_feedback_list(limit: int = Query(50, ge=1, le=200), user=Depends(get_current_user)):
    """The analyst feedback database (rule 12), newest first."""
    return await asyncio.to_thread(vrindha_ai.list_feedback, limit)


@router.get("/analysis/{analysis_id}")
async def analysis_record(analysis_id: str = APIPath(min_length=1, max_length=64),
                          user=Depends(get_current_user)):
    """The full preserved audit record for one analysis (rule 13)."""
    record = await asyncio.to_thread(vrindha_ai.get_audit, analysis_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return record


@router.post("/analysis/{analysis_id}/feedback")
async def analysis_feedback(req: AnalysisFeedbackRequest,
                            analysis_id: str = APIPath(min_length=1, max_length=64),
                            user=Depends(get_current_user)):
    """Record an analyst decision (rule 12); the feedback log is append-only."""
    try:
        return await asyncio.to_thread(
            vrindha_ai.record_feedback, analysis_id, req.analyst, req.decision, req.notes
        )
    except Exception as exc:
        raise internal_error("analysis feedback", exc)
