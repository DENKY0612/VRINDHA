"""Safe end-to-end demonstration scenario (spec §39).

Simulates: multiple failed logins + unusual outbound traffic from a host.

    INFRASTRUCTURE AI  detects abnormal host behavior (SIMULATED telemetry)
    COMMANDER AI       ingests and creates an investigation
    THREAT INTEL AI    enriches the destination indicator (or labels it
                       unavailable — never fabricated)
    DATA SCIENCE AI    computes anomaly score + explainable risk
    SOC ANALYST AI     correlates authentication + network events
    COMMANDER AI       builds the incident summary
    ETHICS AI          checks authorization and policy
    HUMAN              approves the proposed defensive action
    DEFENSIVE RESPONSE executes the authorized action (sandbox-simulated)
    KNOWLEDGE AI       stores the validated outcome
    DATA SCIENCE AI    receives the validated label for future evaluation

Every synthetic payload carries ``SIMULATION: true`` and
``provenance.mode = "simulated"``. Nothing here is presented as real
intelligence or real telemetry.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from uuid import uuid4

from .commander import commander_ai
from .data_science_ai import data_science_ai
from .infrastructure_ai import infrastructure_ai


def _base_time() -> datetime:
    return (datetime.now(timezone.utc) - timedelta(minutes=2)).replace(microsecond=0)


def build_demo_payloads() -> List[Dict[str, Any]]:
    """Two SIMULATED events: auth failures, then unusual outbound connection."""
    t0 = _base_time()
    host, victim_ip = "lab-host-01", "10.0.0.50"
    c2_ip, c2_port = "45.33.32.156", 4444
    correlation_id = "corr-demo-brute-force-c2"
    run_id = uuid4().hex[:8]  # unique per run so content-hash dedup stays meaningful
    return [
        {
            "event_type": "security_event",
            "correlation_id": correlation_id,
            "timestamp": t0.isoformat(),
            "source_agent": "infrastructure_ai",
            "source_system": host,
            "entity": {"host": host, "ip": victim_ip},
            "severity": "high",
            "authorized": True,
            "data": {
                "SIMULATION": True,
                "run_id": run_id,
                "authentication": {
                    "failed_login_count": 10,
                    "successful_login_count": 1,
                },
                "network": {
                    "source_ips": ["203.0.113.77"],
                    "connection_count": 25,
                },
            },
            "provenance": {
                "source": "synthetic_generator",
                "collection_method": "simulation",
                "source_agent": "infrastructure_ai",
                "agent_version": "1.0",
                "mode": "simulated",
            },
        },
        {
            "event_type": "security_event",
            "correlation_id": correlation_id,
            "timestamp": (t0 + timedelta(minutes=1)).isoformat(),
            "source_agent": "infrastructure_ai",
            "source_system": host,
            "entity": {"host": host, "ip": victim_ip},
            "severity": "high",
            "authorized": True,
            "data": {
                "SIMULATION": True,
                "run_id": run_id,
                "network": {
                    "outbound": {"ip": c2_ip, "port": c2_port},
                    "unusual_port_count": 1,
                    "bytes_sent_kb": 18432,
                    "bytes_received_kb": 128,
                },
                "note": f"Unusual outbound connection to {c2_ip}:{c2_port} (SIMULATION)",
            },
            "provenance": {
                "source": "synthetic_generator",
                "collection_method": "simulation",
                "source_agent": "infrastructure_ai",
                "agent_version": "1.0",
                "mode": "simulated",
            },
        },
    ]


def run_demonstration(approver: str = "demo-human-approver") -> Dict[str, Any]:
    """Run the full labeled-SIMULATION pipeline and return the stage trace."""
    stages: List[Dict[str, Any]] = []
    incident_id: str | None = None
    awaiting: Dict[str, Any] | None = None

    # 1) Infrastructure AI emits SIMULATED telemetry events.
    for payload in build_demo_payloads():
        result = commander_ai.handle_event(payload)
        stages.append({"stage": "pipeline", "input_event_type": payload["event_type"], "result": result})
        if result.get("incident_id"):
            incident_id = result["incident_id"]
        if result.get("status") == "awaiting_approval":
            awaiting = result

    # 2) Human approval (explicit, recorded).
    if awaiting and incident_id:
        approval = commander_ai.approve(
            incident_id,
            approver=approver,
            conclusion="confirmed_attack",
            justification="SIMULATION: analyst confirmed malicious behavior in the authorized lab range",
        )
        stages.append({"stage": "human_approval", "result": approval})
    else:
        stages.append({"stage": "human_approval", "result": {"status": "not_required",
                                                              "note": "No high-impact action proposed; nothing to approve."}})

    # 3) Outcome: knowledge + validated feedback.
    evaluation = data_science_ai.evaluate()
    stages.append({"stage": "model_evaluation_after_feedback", "result": evaluation})

    return {
        "status": "success",
        "SIMULATION": True,
        "simulation_note": "All events in this scenario are synthetic and labeled SIMULATED. "
                           "No real telemetry, threat intelligence, or network action occurred.",
        "incident_id": incident_id,
        "stages": stages,
        "final_incident": commander_ai.incident(incident_id).model_dump() if incident_id else None,
        "knowledge_lessons": knowledge_lessons_recent(3),
    }


def knowledge_lessons_recent(limit: int = 5) -> List[Dict[str, Any]]:
    from .knowledge_ai import knowledge_ai

    result = knowledge_ai.lessons(limit=limit)
    return result.get("lessons", [])
