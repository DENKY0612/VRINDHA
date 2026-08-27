"""Commander AI — central orchestration and incident lifecycle management.

The Commander does NOT perform specialized analysis itself; it coordinates the
specialists through the event bus (spec §4/§20):

    EVENT ARRIVES
      → ingest + validate (Data Science)
      → threat intelligence enrichment (Threat Intel AI)
      → anomaly + risk analysis (Data Science AI)
      → correlation + investigation (SOC Analyst AI)
      → incident summary (Commander)
      → ethics & compliance review (Ethics AI)
      → HUMAN APPROVAL (mandatory for high-impact actions)
      → authorized defensive response (existing automation actions)
      → knowledge storage + feedback loop (Knowledge AI / Data Science)

Every stage is traceable in the incident ``trace``; a failing stage degrades
gracefully (marked unavailable) instead of crashing the pipeline.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .data_science_ai import DataScienceAI, data_science_ai
from .event_bus import EventBus, event_bus
from .ethics_ai import EthicsAI, ethics_ai
from .infrastructure_ai import InfrastructureAI, infrastructure_ai
from .knowledge_ai import KnowledgeAI, knowledge_ai
from .observability import BaseAgent
from .schemas import (
    Incident,
    IncidentStatus,
    SecurityEvent,
    new_event_id,
    utc_now_iso,
)
from .soc_analyst_ai import SOCAnalystAI, soc_analyst_ai
from .threat_intel_ai import ThreatIntelAI, threat_intel_ai


def _db():
    from vrin_SOC.database import db

    return db


def _ensure_tables(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS coordination_incidents (
            incident_id TEXT PRIMARY KEY,
            correlation_id TEXT,
            title TEXT,
            status TEXT,
            payload TEXT,
            created_at TEXT,
            updated_at TEXT
        )
        """
    )


class CommanderAI(BaseAgent):
    name = "CommanderAI"
    kind = "orchestrator"
    capabilities = ["orchestration", "incident_lifecycle", "task_creation",
                    "approval_routing", "aggregation"]

    def __init__(self, bus: Optional[EventBus] = None,
                 data_science: Optional[DataScienceAI] = None,
                 threat_intel: Optional[ThreatIntelAI] = None,
                 soc_analyst: Optional[SOCAnalystAI] = None,
                 knowledge: Optional[KnowledgeAI] = None,
                 ethics: Optional[EthicsAI] = None) -> None:
        super().__init__(bus)
        self.data_science = data_science or data_science_ai
        self.threat_intel = threat_intel or threat_intel_ai
        self.soc_analyst = soc_analyst or soc_analyst_ai
        self.knowledge = knowledge or knowledge_ai
        self.ethics = ethics or ethics_ai
        db = _db()
        db._run_db(_ensure_tables)  # noqa: SLF001

    # ------------------------------------------------------------------
    # Pipeline
    # ------------------------------------------------------------------
    def handle_event(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Run the full coordinated pipeline for one raw event."""
        return self.run_guarded(self._handle_event, payload)

    def _handle_event(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        trace: List[Dict[str, Any]] = []

        # Stage 1 — ingestion & validation (Data Science AI)
        event, quality = self.data_science.ingest(payload)
        trace.append({"stage": "ingest", "agent": self.data_science.name,
                      "accepted": quality.accepted, "issues": quality.issues,
                      "duplicates": quality.duplicates})
        if event is None:
            return {
                "status": "rejected",
                "reason": quality.issues[0] if quality.issues else "validation failed",
                "data_quality": quality.model_dump(),
                "trace": trace,
                "note": "Recorded rejection; the event was not silently discarded.",
            }
        if not event.correlation_id:
            event.correlation_id = f"corr-{new_event_id()[4:]}"
        entity = event.entity
        title = f"{event.event_type} on {entity.primary() or 'system'}"

        # Reuse an open incident for the same correlation (multi-event
        # investigations share one lifecycle instead of fragmenting).
        incident = self.find_open_by_correlation(event.correlation_id)
        if incident is None:
            incident = Incident(title=title, correlation_id=event.correlation_id,
                                event_ids=[event.event_id])
            incident.add_trace("ingest", {"event_id": event.event_id, "quality": quality.model_dump()})
        else:
            if event.event_id not in incident.event_ids:
                incident.event_ids.append(event.event_id)
            incident.status = IncidentStatus.INVESTIGATING
            incident.add_trace("ingest", {"event_id": event.event_id,
                                          "quality": quality.model_dump(),
                                          "attached_to_existing": True})
        self._persist(incident)
        trace.append({"stage": "incident", "incident_id": incident.incident_id})

        # Stage 2 — threat intelligence enrichment (never fabricated)
        ti_result = self.threat_intel.enrich(event)
        incident.status = IncidentStatus.INVESTIGATING
        incident.add_trace("threat_intelligence", ti_result)
        trace.append({"stage": "threat_intel", "status": ti_result.get("status"),
                      "indicators": ti_result.get("indicators_checked"),
                      "malicious_found": ti_result.get("malicious_found"),
                      "mode": ti_result.get("enrichment_mode")})

        # Stage 3 — data science analysis (features → anomaly → risk)
        ds_result = self.data_science.analyze(event)
        incident.add_trace("data_science", ds_result)
        trace.append({"stage": "data_science", "status": ds_result.get("status"),
                      "risk_score": (event.risk or {}).get("risk_score"),
                      "severity": event.severity,
                      "anomaly": (event.analysis or {}).get("anomaly", {}).get("is_anomaly")})

        # Stage 4 — SOC investigation (correlation, evidence, recommendations)
        soc_result = self.soc_analyst.investigate(event)
        incident.status = IncidentStatus.RISK_ASSESSED
        recommendations = soc_result.get("recommendations", [])
        summary = soc_result.get("summary", "")
        incident.recommendations = recommendations
        incident.summary = summary
        incident.add_trace("soc_investigation", {
            "status": soc_result.get("status"),
            "recommendations": recommendations,
            "summary": summary,
        })
        trace.append({"stage": "soc_analyst", "status": soc_result.get("status"),
                      "recommendation_count": len(recommendations)})

        # Publish the fully analyzed event so every subscriber sees one
        # consistent, complete object (correlation timeline is shared state).
        delivery = self.bus.publish(event)
        trace.append({"stage": "bus_publish", "delivered_to": delivery["delivered_to"],
                      "errors": delivery["errors"]})

        # Stage 5 — ethics & compliance review of the proposed action
        proposed = next((r for r in recommendations if r.get("requires_human_approval")), None)
        proposed = proposed or (recommendations[0] if recommendations else None)
        if proposed and proposed.get("action") not in {"continue_monitoring"}:
            context = {
                "authorized": bool((event.data or {}).get("authorized") or payload.get("authorized")),
                "target_type": (event.data or {}).get("target_type"),
            }
            authorization_status = "provided" if context["authorized"] else "missing"
            ethics_assessment = self.ethics.evaluate(
                action=f"{proposed['action']} {proposed.get('target', '')}".strip(),
                target=str(proposed.get("target", "") or ""),
                context=context,
                authorization_status=authorization_status,
                event_id=event.event_id,
            )
            incident.ethics = ethics_assessment.model_dump()
            incident.proposed_action = proposed
            incident.add_trace("ethics", ethics_assessment.model_dump())
            trace.append({"stage": "ethics", "decision": ethics_assessment.decision.value,
                          "classification": ethics_assessment.classification.value,
                          "human_approval_required": ethics_assessment.human_approval_required})

            if ethics_assessment.decision.value in {"deny"}:
                incident.status = IncidentStatus.REJECTED
                incident.summary += " Ethics review denied the proposed action."
                self._persist(incident)
                return self._finish(incident, trace, status="denied_by_ethics",
                                    proposed=proposed, summary=incident.summary)

        # Stage 6 — human approval gate for high-impact actions
        if incident.proposed_action and incident.proposed_action.get("requires_human_approval"):
            incident.status = IncidentStatus.AWAITING_APPROVAL
            self._persist(incident)
            trace.append({"stage": "awaiting_approval",
                          "proposed_action": incident.proposed_action})
            return {
                "status": "awaiting_approval",
                "incident_id": incident.incident_id,
                "event_id": event.event_id,
                "correlation_id": event.correlation_id,
                "summary": incident.summary,
                "proposed_action": incident.proposed_action,
                "ethics": incident.ethics,
                "recommendations": incident.recommendations,
                "risk": event.risk,
                "anomaly": (event.analysis or {}).get("anomaly"),
                "trace": trace,
                "approval": "Call POST /commander/approve with this incident_id (human decision required).",
            }

        # No high-impact action needed yet.
        if event.correlation_id:
            # An explicit correlation means the investigation is ongoing —
            # keep the incident open so later correlated events attach to it.
            incident.status = IncidentStatus.OPEN
            incident.summary += " No high-impact action required yet; correlation in progress."
            self._persist(incident)
            return self._finish(incident, trace, status="open_monitoring",
                                proposed=None, summary=incident.summary)

        incident.status = IncidentStatus.CLOSED
        incident.summary += " No high-impact action required; incident closed under monitoring."
        self._persist(incident)
        self.knowledge.record_outcome(
            incident_id=incident.incident_id,
            conclusion="unknown",
            summary=incident.summary,
            event_ids=incident.event_ids,
            pattern=event.event_type,
            validated_by="commander_auto_close",
            validated=True,
        )
        return self._finish(incident, trace, status="closed_monitoring",
                            proposed=None, summary=incident.summary)

    # ------------------------------------------------------------------
    # Human approval → authorized response → knowledge + feedback
    # ------------------------------------------------------------------
    def approve(self, incident_id: str, approver: str, conclusion: str = "confirmed_attack",
                justification: str = "") -> Dict[str, Any]:
        """Human approves a proposed defensive action; it executes then and only then."""
        return self.run_guarded(self._approve, incident_id, approver, conclusion, justification)

    def _approve(self, incident_id: str, approver: str, conclusion: str,
                 justification: str) -> Dict[str, Any]:
        incident = self._load(incident_id)
        if incident is None:
            return {"status": "error", "reason": f"incident {incident_id} not found"}
        if incident.status != IncidentStatus.AWAITING_APPROVAL:
            return {"status": "error",
                    "reason": f"incident is {incident.status.value}; approval only valid while awaiting_approval"}
        if conclusion not in {"confirmed_attack", "false_positive", "unknown"}:
            return {"status": "error", "reason": "conclusion must be confirmed_attack | false_positive | unknown"}
        if not approver:
            return {"status": "error", "reason": "approver identity is required (human accountability)"}

        incident.status = IncidentStatus.APPROVED
        incident.approved_by = approver
        incident.approved_at = utc_now_iso()
        incident.add_trace("human_approval", {"approver": approver, "conclusion": conclusion,
                                              "justification": justification[:500]})

        proposed = incident.proposed_action or {}
        action = str(proposed.get("action", ""))
        result: Dict[str, Any]
        if action in {"block_ip"}:
            from vrin_SOC.automation.actions import automation_actions

            result = automation_actions.block_ip(str(proposed.get("target", "")))
        elif action in {"investigate_host", "continue_monitoring", "correlated_review"}:
            result = {"status": "success", "action": action,
                      "message": "Observation-only action acknowledged; no system change made."}
        else:
            result = {"status": "error", "action": action,
                      "message": f"Action '{action}' is not an approved defensive action; not executed."}

        incident.status = IncidentStatus.RESPONDED
        incident.response_result = result
        incident.add_trace("authorized_response", result)
        if conclusion == "false_positive":
            incident.status = IncidentStatus.CLOSED
        else:
            incident.status = IncidentStatus.CLOSED
        self._persist(incident)

        # Knowledge + feedback loop (validated by the human approver).
        knowledge_result = self.knowledge.record_outcome(
            incident_id=incident.incident_id,
            conclusion=conclusion,
            summary=incident.summary,
            event_ids=incident.event_ids,
            pattern=incident.title[:80],
            features=None,
            validated_by=approver,
            validated=True,
        )
        for event_id in incident.event_ids:
            self.data_science.record_outcome(
                event_id=event_id,
                label=conclusion,
                validated_by=approver,
                validated=True,
                detail={"incident_id": incident.incident_id, "conclusion": conclusion},
            )
        incident.knowledge_id = knowledge_result.get("lesson_id")
        self._persist(incident)  # keep the stored incident consistent with the knowledge link

        # Bus: incident resolved → Knowledge AI subscriber mirrors the outcome.
        self.bus.emit(
            event_type="incident_resolved",
            source_agent=self.name,
            correlation_id=incident.correlation_id,
            data={
                "incident_id": incident.incident_id,
                "conclusion": conclusion,
                "summary": incident.summary[:1000],
                "pattern": incident.title[:80],
                "validated_by": approver,
                "validated": True,
                "SIMULATION": bool(incident.summary and "SIMULATION" in incident.summary.upper()),
            },
        )
        return {
            "status": "success",
            "incident_id": incident.incident_id,
            "approved_by": approver,
            "conclusion": conclusion,
            "response_result": result,
            "knowledge": knowledge_result,
            "incident_status": incident.status.value,
        }

    def reject(self, incident_id: str, approver: str, reason: str = "") -> Dict[str, Any]:
        return self.run_guarded(self._reject, incident_id, approver, reason)

    def _reject(self, incident_id: str, approver: str, reason: str) -> Dict[str, Any]:
        incident = self._load(incident_id)
        if incident is None:
            return {"status": "error", "reason": f"incident {incident_id} not found"}
        incident.status = IncidentStatus.REJECTED
        incident.approved_by = approver
        incident.approved_at = utc_now_iso()
        incident.summary += f" Rejected by {approver}: {reason or 'no reason given'}"
        self._persist(incident)
        self.knowledge.record_outcome(
            incident_id=incident.incident_id, conclusion="false_positive",
            summary=incident.summary, event_ids=incident.event_ids,
            pattern=incident.title[:80], validated_by=approver, validated=True,
        )
        return {"status": "success", "incident_id": incident.incident_id,
                "incident_status": incident.status.value}

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def find_open_by_correlation(self, correlation_id: str) -> Optional[Incident]:
        """Open (not closed/rejected) incident for a correlation, if any."""
        if not correlation_id:
            return None
        db = _db()

        def query(conn):
            row = conn.execute(
                "SELECT payload FROM coordination_incidents WHERE correlation_id = ? "
                "AND status NOT IN ('closed', 'rejected') ORDER BY updated_at DESC LIMIT 1",
                (correlation_id,),
            ).fetchone()
            return row[0] if row else None

        try:
            raw = db._run_db(query)  # noqa: SLF001
        except Exception:  # noqa: BLE001
            return None
        if not raw:
            return None
        try:
            return Incident.model_validate(json.loads(raw))
        except Exception:  # noqa: BLE001
            return None

    def list_incidents(self, limit: int = 50) -> Dict[str, Any]:
        db = _db()

        def query(conn):
            return conn.execute(
                "SELECT incident_id, correlation_id, title, status, created_at, updated_at "
                "FROM coordination_incidents ORDER BY updated_at DESC LIMIT ?", (limit,),
            ).fetchall()

        try:
            rows = db._run_db(query)  # noqa: SLF001
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "reason": str(exc)[:256]}
        return {
            "status": "success",
            "count": len(rows),
            "incidents": [
                {"incident_id": r[0], "correlation_id": r[1], "title": r[2], "status": r[3],
                 "created_at": r[4], "updated_at": r[5]}
                for r in rows
            ],
        }

    def incident(self, incident_id: str) -> Optional[Incident]:
        return self._load(incident_id)

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------
    def _persist(self, incident: Incident) -> None:
        db = _db()

        def upsert(conn):
            conn.execute(
                "INSERT INTO coordination_incidents (incident_id, correlation_id, title, status, payload, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(incident_id) DO UPDATE SET status=excluded.status, payload=excluded.payload, updated_at=excluded.updated_at",
                (incident.incident_id, incident.correlation_id, incident.title,
                 incident.status.value, incident.model_dump_json(), incident.created_at, incident.updated_at),
            )

        try:
            db._run_db(upsert)  # noqa: SLF001
        except Exception:  # noqa: BLE001
            self.metrics.record_error("incident persist failed")

    def _load(self, incident_id: str) -> Optional[Incident]:
        db = _db()

        def query(conn):
            row = conn.execute(
                "SELECT payload FROM coordination_incidents WHERE incident_id = ?", (incident_id,),
            ).fetchone()
            return row[0] if row else None

        try:
            raw = db._run_db(query)  # noqa: SLF001
        except Exception:  # noqa: BLE001
            return None
        if not raw:
            return None
        try:
            return Incident.model_validate(json.loads(raw))
        except Exception:  # noqa: BLE001
            return None

    def _finish(self, incident: Incident, trace: List[Dict[str, Any]], status: str,
                proposed: Optional[Dict[str, Any]], summary: str) -> Dict[str, Any]:
        return {
            "status": status,
            "incident_id": incident.incident_id,
            "event_ids": incident.event_ids,
            "correlation_id": incident.correlation_id,
            "summary": summary,
            "proposed_action": proposed,
            "incident_status": incident.status.value,
            "trace": trace,
        }

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------
    def health(self) -> Dict[str, Any]:
        base = super().health()
        base["pipeline_agents"] = {
            "data_science": self.data_science.health(),
            "threat_intel": self.threat_intel.health(),
            "soc_analyst": self.soc_analyst.health(),
            "knowledge": self.knowledge.health(),
            "ethics": self.ethics.health(),
            "infrastructure": infrastructure_ai.health(),
        }
        return base


commander_ai = CommanderAI()
