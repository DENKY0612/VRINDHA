"""
Risk-based Response Engine (Blue Team)

Vrindha does not try to make AI 100% accurate and then auto-contain.  It
reduces AI error impact by separating analysis from authority:

Detection/Correlation/AI → Risk + Confidence → Human Validation → Controlled Response

Low-impact work (log, alert, monitor, collect evidence) may happen immediately.
High-impact containment (block IP, isolate interface, kill process, disable
account) is only executed after an analyst explicitly approves it.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional
from uuid import uuid4

from .actions import automation_actions
from vrin_SOC.core.error_handler import ErrorHandler
from vrin_SOC.ml.risk_scoring import risk_scoring


class ResponseEngine:
    HIGH_IMPACT_ACTIONS = {"block_ip", "kill_process", "isolate_interface", "disable_account", "quarantine_host"}

    def __init__(self):
        self.name = "ResponseEngine"

    def respond(self, threat_data: dict) -> dict:
        """Prepare a response and enforce the human-validation gate.

        This method may alert/log immediately, but it will not execute a
        high-impact containment action unless the caller supplies an explicit
        validation context (``human_validated=True`` and approval metadata). For
        normal usage, call :meth:`validate_and_respond` after the analyst's
        True Positive / False Positive decision.
        """
        try:
            if not isinstance(threat_data, dict):
                threat_data = {"raw": threat_data}

            assessment = self._ensure_risk_assessment(threat_data)
            proposed_action = self._propose_action(threat_data, assessment)
            risk_level = str(assessment.get("risk_level", "Low")).upper()
            validation = self._validation_status(threat_data)

            if proposed_action["action"] in self.HIGH_IMPACT_ACTIONS and not validation["approved"]:
                alert_result = automation_actions.send_alert(
                    f"{risk_level} risk requires analyst validation before {proposed_action['action']}: "
                    f"{proposed_action.get('target') or 'target unavailable'}"
                )
                return {
                    "engine": self.name,
                    "status": "awaiting_human_validation",
                    "risk": risk_level,
                    "risk_score": assessment.get("risk_score"),
                    "confidence_score": assessment.get("confidence_score"),
                    "human_validation_required": True,
                    "validation_flow": "Security Data → Detection → Correlation → AI Analysis → Risk Score → Human Validation → Controlled Response",
                    "proposed_action": proposed_action,
                    "actions_taken": [alert_result],
                    "message": (
                        f"{risk_level} risk ({assessment.get('risk_score')}/100) identified. "
                        f"Containment is parked until a human analyst validates the alert."
                    ),
                    "risk_assessment": assessment,
                    "timestamp": datetime.now().isoformat(),
                    "safety": "High-impact response blocked until analyst approval",
                }

            if proposed_action["action"] in self.HIGH_IMPACT_ACTIONS and validation["approved"]:
                if validation.get("analyst"):
                    self._record_feedback(
                        validation.get("alert_id") or threat_data.get("alert_id") or f"alert-{uuid4().hex[:10]}",
                        validation.get("verdict") or "true_positive",
                        validation.get("analyst") or "analyst",
                        validation.get("notes") or "",
                        assessment,
                        threat_data,
                    )
                return self._execute_validated_action(threat_data, assessment, proposed_action, validation)

            # Low-impact path: log/alert/monitor only.
            if risk_level in {"HIGH", "CRITICAL"}:
                message = "High risk but no executable containment target; alerting and collecting more evidence"
            elif risk_level == "MEDIUM":
                message = "Medium risk - alert sent, monitor and correlate before containment"
            else:
                message = "Low risk - logged only, no automated containment"
            alert_result = automation_actions.send_alert(f"{risk_level} risk advisory: {message}. Event: {str(threat_data)[:300]}")
            return {
                "engine": self.name,
                "status": "success",
                "risk": risk_level,
                "risk_score": assessment.get("risk_score"),
                "confidence_score": assessment.get("confidence_score"),
                "human_validation_required": False,
                "proposed_action": proposed_action,
                "actions_taken": [alert_result],
                "message": message,
                "risk_assessment": assessment,
                "timestamp": datetime.now().isoformat(),
                "safety": "Only low-impact alert/log/monitor action executed automatically",
            }
        except Exception as e:
            return ErrorHandler.handle_exception(e, "ResponseEngine.respond")

    def validate_and_respond(
        self,
        threat_data: dict,
        analyst: str,
        decision: str = "approve",
        verdict: str = "true_positive",
        notes: str = "",
    ) -> dict:
        """Record analyst feedback and execute/reject a proposed response.

        ``decision``: ``approve`` executes the controlled response; ``reject``
        stores feedback and performs no containment.  ``verdict`` becomes the
        continuous-learning label.
        """
        try:
            if not isinstance(threat_data, dict):
                threat_data = {"raw": threat_data}
            decision_normalized = (decision or "").strip().lower()
            if decision_normalized not in {"approve", "reject"}:
                return {"status": "error", "message": "decision must be approve or reject"}
            analyst = (analyst or "").strip()
            if not analyst:
                return {"status": "error", "message": "analyst is required"}

            assessment = self._ensure_risk_assessment(threat_data)
            proposed_action = self._propose_action(threat_data, assessment)
            alert_id = threat_data.get("alert_id") or threat_data.get("event_id") or f"alert-{uuid4().hex[:10]}"
            self._record_feedback(alert_id, verdict if decision_normalized == "approve" else "rejected",
                                  analyst, notes, assessment, threat_data)

            if decision_normalized == "reject":
                alert_result = automation_actions.send_alert(
                    f"Analyst {analyst} rejected containment for {alert_id}; verdict={verdict}"
                )
                return {
                    "engine": self.name,
                    "status": "rejected",
                    "human_validation_required": False,
                    "approved": False,
                    "alert_id": alert_id,
                    "risk": str(assessment.get("risk_level", "Low")).upper(),
                    "risk_score": assessment.get("risk_score"),
                    "proposed_action": proposed_action,
                    "actions_taken": [alert_result],
                    "message": "Analyst rejected the response; no high-impact action was executed",
                    "risk_assessment": assessment,
                    "timestamp": datetime.now().isoformat(),
                }

            validated = {"approved": True, "analyst": analyst, "verdict": verdict, "notes": notes, "alert_id": alert_id}
            return self._execute_validated_action(threat_data, assessment, proposed_action, validated)
        except Exception as e:
            return ErrorHandler.handle_exception(e, "ResponseEngine.validate_and_respond")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _ensure_risk_assessment(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        existing = threat_data.get("risk_assessment") if isinstance(threat_data.get("risk_assessment"), dict) else None
        if existing and "risk_score" in existing:
            return existing
        payload = dict(threat_data)
        # Preserve legacy caller fields as declared severity inputs to the risk engine.
        if "severity" not in payload:
            payload["severity"] = threat_data.get("risk_level") or threat_data.get("risk") or threat_data.get("threat_level") or "low"
        return risk_scoring.score(payload)

    def _propose_action(self, threat_data: Dict[str, Any], assessment: Dict[str, Any]) -> Dict[str, Any]:
        requested = str(threat_data.get("requested_action") or threat_data.get("action") or "").lower()
        ip = threat_data.get("source_ip") or threat_data.get("ip") or threat_data.get("src_ip") or ""
        pid = threat_data.get("pid")
        risk_level = str(assessment.get("risk_level", "Low")).upper()

        if "kill" in requested and pid:
            return {"action": "kill_process", "target": int(pid), "reason": "requested/identified suspicious process"}
        if any(term in requested for term in ["isolate", "quarantine"]):
            target = threat_data.get("interface") or threat_data.get("host") or ip
            return {"action": "isolate_interface", "target": target, "reason": "containment requested for suspected compromise"}
        if ip and risk_level in {"HIGH", "CRITICAL"}:
            return {"action": "block_ip", "target": ip, "reason": "high-risk source IP containment recommendation"}
        if risk_level == "MEDIUM":
            return {"action": "alert_and_monitor", "target": ip, "reason": "medium risk does not justify automatic containment"}
        return {"action": "log_only", "target": ip, "reason": "insufficient risk or no safe containment target"}

    def _validation_status(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        decision = str(threat_data.get("analyst_decision") or threat_data.get("decision") or "").lower()
        analyst = threat_data.get("analyst") or threat_data.get("approved_by") or ""
        approved = bool(threat_data.get("human_validated") or threat_data.get("approved")) and decision not in {"reject", "rejected", "no"}
        if decision in {"approve", "approved", "yes"}:
            approved = True
        approved = approved and bool(str(analyst).strip())
        return {
            "approved": approved,
            "analyst": analyst,
            "verdict": threat_data.get("verdict") or "true_positive",
            "notes": threat_data.get("notes") or "",
            "alert_id": threat_data.get("alert_id") or threat_data.get("event_id"),
        }

    def _execute_validated_action(
        self,
        threat_data: Dict[str, Any],
        assessment: Dict[str, Any],
        proposed_action: Dict[str, Any],
        validation: Dict[str, Any],
    ) -> Dict[str, Any]:
        actions_taken = []
        action = proposed_action["action"]
        target = proposed_action.get("target")
        if action == "block_ip":
            result = automation_actions.block_ip(str(target))
            actions_taken.append(result)
            if result.get("status") != "error":
                try:
                    from vrin_SOC.database.db import add_blocked_ip
                    add_blocked_ip(str(target), f"Human-validated response by {validation.get('analyst') or 'analyst'}: {str(threat_data)[:180]}")
                except Exception:
                    pass
        elif action == "kill_process":
            actions_taken.append(automation_actions.kill_process(int(target)))
        elif action == "isolate_interface":
            actions_taken.append(automation_actions.isolate_network_interface(str(target)))
        else:
            actions_taken.append(automation_actions.send_alert(f"Validated advisory action: {action} for {target}"))

        actions_taken.append(automation_actions.send_alert(
            f"Human-validated response executed: {action} target={target} analyst={validation.get('analyst') or 'unknown'}"
        ))
        return {
            "engine": self.name,
            "status": "success" if all(a.get("status") != "error" for a in actions_taken) else "error",
            "risk": str(assessment.get("risk_level", "Low")).upper(),
            "risk_score": assessment.get("risk_score"),
            "confidence_score": assessment.get("confidence_score"),
            "human_validation_required": False,
            "approved": True,
            "approved_by": validation.get("analyst"),
            "verdict": validation.get("verdict"),
            "proposed_action": proposed_action,
            "actions_taken": actions_taken,
            "message": f"Controlled response executed after analyst validation: {action}",
            "risk_assessment": assessment,
            "timestamp": datetime.now().isoformat(),
            "safety": "High-impact action executed only after human validation",
        }

    def _record_feedback(
        self,
        alert_id: str,
        verdict: str,
        analyst: str,
        notes: str,
        assessment: Dict[str, Any],
        threat_data: Dict[str, Any],
    ) -> None:
        try:
            from vrin_SOC.database.db import add_alert_feedback
            add_alert_feedback(
                alert_id=alert_id,
                verdict=verdict,
                analyst=analyst,
                notes=notes,
                risk_score=assessment.get("risk_score"),
                source_ip=str(threat_data.get("source_ip") or threat_data.get("ip") or ""),
                signal_summary=assessment.get("signal_summary") or assessment.get("signals") or {},
            )
        except Exception:
            # Feedback persistence must not crash the response path; the API
            # result still exposes the validation metadata.
            pass


response_engine = ResponseEngine()
