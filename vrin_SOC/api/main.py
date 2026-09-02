"""FastAPI backend for the Vrindha SOC system."""
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, Literal, Optional
import asyncio
import logging
from contextlib import asynccontextmanager
import os
import re
import time

if __name__ == "__main__" and (__package__ in {None, ""}):
    import runpy
    import sys
    _repo = Path(__file__).resolve().parents[2]
    if str(_repo) not in sys.path:
        sys.path.insert(0, str(_repo))
    raise SystemExit(runpy.run_module("vrin_SOC.api.main", run_name="__main__"))

from fastapi import Depends, FastAPI, Header, HTTPException, Path as APIPath, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


from .auth import (
    BootstrapClosedError,
    DuplicateUserError,
    InvalidPasswordError,
    InvalidRoleError,
    InvalidUsernameError,
    auth_module,
)
# Auth dependencies are shared with the coordination router; main re-exports
# them so existing imports of the names from this module keep working.
from .deps import bearer_scheme, get_current_admin, get_current_user
from vrin_SOC.core.brain import brain
from vrin_SOC.core.gita_engine import gita_engine
from vrin_SOC.database.db import add_log, get_blocked_ips, get_logs, get_threats
from vrin_SOC.ml.anomaly_detector import anomaly_detector
from vrin_SOC.ml.data_pipeline import data_pipeline
from vrin_SOC.autonomous.agent import autonomous_agent
from vrin_SOC.autonomous.scheduler import Scheduler
from vrin_SOC.autonomous.task_manager import task_manager
from vrin_SOC.ml.prediction_model import prediction_model
from vrin_SOC.ml.risk_scoring import risk_scoring
from vrin_SOC.ml.visualization import visualization_engine
from vrin_SOC.core.intelligence_bus import intelligence_gateway
from vrin_SOC.hive.coordinator import hive as hive_coordinator
from vrin_SOC.api.coordination_routes import router as coordination_router
from vrin_SOC.api.blockchain_routes import router as blockchain_router
from Vrin_TI.models import IntelligenceEvent, LookupRequest, SightingRequest
from Vrin_TI.normalization import InvalidIndicator

logger = logging.getLogger(__name__)


@asynccontextmanager
async def _lifespan(application: FastAPI):
    """Controlled autonomy §10 — temporary actions expire on their own.

    A small background loop rolls back due temporary actions (time limits)
    and asks for human re-evaluation. Disable with
    ``VRINDHA_RESPONSE_EXPIRY_INTERVAL=0`` (tests).
    """
    task = None
    interval = float(os.getenv("VRINDHA_RESPONSE_EXPIRY_INTERVAL", "60") or 0)
    if interval > 0:
        from vrin_SOC.coordination.controlled_response import controlled_response_engine

        async def loop() -> None:
            while True:
                try:
                    await asyncio.sleep(interval)
                    await asyncio.to_thread(controlled_response_engine.expire_due)
                except asyncio.CancelledError:
                    raise
                except Exception:  # noqa: BLE001 — the loop must survive transient failures
                    continue

        task = asyncio.create_task(loop())
    try:
        yield
    finally:
        if task is not None:
            task.cancel()


app = FastAPI(title="Vrindha AI SOC System", description="Ethical agentic cybersecurity platform",
              version="1.1.0", lifespan=_lifespan)

origins = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "").split(",") if origin.strip()]
if origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )


class CommandRequest(BaseModel):
    command: str = Field(min_length=1, max_length=2000)
    # Kept for backward-compatible validation, but deliberately rejected.
    auto_confirm: bool = False


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class RegisterRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)
    role: Literal["admin", "user"] = "user"


class AutonomyModeRequest(BaseModel):
    mode: Literal["autonomous", "defensive"] = Field(..., description="Autonomy mode to persist and apply")


class TeamActionRequest(BaseModel):
    action: str = Field(min_length=1, max_length=64)
    target: str = Field("", max_length=256)
    details: str = Field("", max_length=2000)


class TeamConfirmRequest(BaseModel):
    decision: Literal["yes", "no"] = "yes"


class IncidentValidationRequest(BaseModel):
    threat_data: Dict[str, Any] = Field(default_factory=dict)
    decision: Literal["approve", "reject"] = "approve"
    verdict: Literal["true_positive", "false_positive", "benign", "unknown"] = "true_positive"
    analyst: str = Field("", max_length=128)
    notes: str = Field("", max_length=2000)


class RiskFeedbackRequest(BaseModel):
    alert_id: str = Field(min_length=1, max_length=128)
    verdict: Literal["true_positive", "false_positive", "benign", "unknown"] = "unknown"
    notes: str = Field("", max_length=2000)
    risk_score: Optional[float] = Field(default=None, ge=0, le=100)
    source_ip: str = Field("", max_length=64)
    signal_summary: Dict[str, Any] = Field(default_factory=dict)


RED_TEAM_ACTIONS = {
    "nmap": "scan network {target}",
    "recon": "scan network {target}",
    "whois": "whois {target}",
    "nikto": "scan vulnerabilities {target}",
    "vuln": "scan vulnerabilities {target}",
    "gobuster": "gobuster {target}",
    "dirb": "dirb {target}",
    "amass": "amass {target}",
    "sublist3r": "sublist3r {target}",
    "tcpdump": "tcpdump {target}",
    "hashcat": "hashcat {details}",
    "assist": "exploit assist {details} on {target}",
    "exploit": "exploit assist {details} on {target}",
}

BLUE_TEAM_ACTIONS = {
    "detect": "detect threats {details} from {target}",
    "block": "block ip {target}",
    "firewall": "firewall check",
    "ids": "ids monitor",
    "idps": "ids monitor",
    "endpoint": "rootkit scan",
    "rootkit": "rootkit scan",
    "respond": "incident response {target}",
    "logs": "show logs",
    "anomaly": "analyze anomaly",
}


def _render_team_command(template: str, target: str, details: str) -> str:
    command = template.format(target=(target or "").strip(), details=(details or "").strip())
    return re.sub(r"\s+", " ", command).strip()


def _run_team_command(command: str, user: Dict[str, Any]) -> Dict[str, Any]:
    result = brain.process(command, session_id=str(user["sub"]), user_token=str(user["sub"]))
    data = result.get("data") if isinstance(result.get("data"), dict) else {}
    threat = data.get("threat") if isinstance(data.get("threat"), dict) else {}
    add_log(command, str(result.get("message", ""))[:2000], threat.get("risk_level", "Low"), result.get("action", ""), result.get("mode", ""))
    return result


# NOTE: bearer_scheme / get_current_user / get_current_admin are defined in
# ``vrin_SOC.api.deps`` and re-exported above for backward compatibility.


def internal_error(context: str, exc: Exception) -> HTTPException:
    logger.exception("%s failed", context)
    return HTTPException(status_code=500, detail="Internal server error")


# Small per-process login throttle. A reverse proxy should add distributed rate
# limiting in multi-worker production deployments.
_login_attempts: Dict[str, deque] = defaultdict(deque)
# Never let the throttle map grow without bound: a flood from rotating
# source addresses would otherwise exhaust memory.
_MAX_TRACKED_CLIENTS = 10_000


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and content_length.isdigit() and int(content_length) > 1_000_000:
        return JSONResponse(status_code=413, content={"detail": "Request body too large"})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.get("/")
async def root():
    return {"message": "Vrindha AI SOC System - Running", "mode": "defensive", "version": "1.1.0"}


@app.get("/status")
async def get_status():
    """Public, minimal health/status endpoint used by container health checks."""
    result = brain.process("status", session_id="health")
    result.get("data", {}).pop("memory", None)
    return JSONResponse(content=result)


@app.post("/register", status_code=201, tags=["auth"])
async def register(
    req: RegisterRequest,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
):
    """Create a user account.

    While the user store is empty this endpoint is public and registers the
    first administrator (returning an access token). Once any user exists,
    public registration closes and only an authenticated administrator may
    create further users.
    """
    try:
        if not auth_module.has_users():
            user = auth_module.create_user(req.username, req.password, role="admin", require_empty=True)
            token = auth_module.create_access_token({"sub": user["username"], "role": "admin"})
            return {
                "status": "success",
                "message": "First administrator registered",
                "user": user,
                "access_token": token,
                "token_type": "bearer",
            }

        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=401,
                detail="Public registration is closed; authenticate as an administrator",
                headers={"WWW-Authenticate": "Bearer"},
            )
        payload = auth_module.verify_token(credentials.credentials)
        if not payload:
            raise HTTPException(status_code=401, detail="Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
        admin = auth_module.load_users().get(payload.get("sub", ""))
        if not admin or not admin.get("active", True):
            raise HTTPException(status_code=401, detail="Account is disabled or no longer exists", headers={"WWW-Authenticate": "Bearer"})
        if admin.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Only administrators can create users")
        user = auth_module.create_user(req.username, req.password, role=req.role)
        return {"status": "success", "message": f"User {user['username']} created", "user": user}
    except BootstrapClosedError:
        raise HTTPException(
            status_code=401,
            detail="Public registration is closed; authenticate as an administrator",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except DuplicateUserError:
        raise HTTPException(status_code=409, detail="Username already exists")
    except InvalidUsernameError:
        raise HTTPException(
            status_code=422,
            detail="Username must be 3-64 characters, start with a letter or number, "
            "and contain only letters, numbers, '.', '_', or '-'",
        )
    except InvalidPasswordError:
        raise HTTPException(status_code=422, detail="Password must be at least 12 characters")
    except InvalidRoleError:
        raise HTTPException(status_code=422, detail="Role must be 'admin' or 'user'")


@app.post("/command")
async def run_command(req: CommandRequest, user=Depends(get_current_user)):
    # Admin unrestricted: Admin can use auto_confirm as per user request to not restrict admin
    is_admin = user.get("role") == "admin"
    if req.auto_confirm and not is_admin:
        raise HTTPException(status_code=400, detail="auto_confirm is disabled; send 'yes' as a separate authenticated request")
    try:
        result = brain.process(req.command, auto_confirm=req.auto_confirm if is_admin else False, session_id=str(user["sub"]), user_token=str(user["sub"]))
        data = result.get("data") if isinstance(result.get("data"), dict) else {}
        threat = data.get("threat") if isinstance(data.get("threat"), dict) else {}
        add_log(req.command, str(result.get("message", ""))[:2000], threat.get("risk_level", "Low"), result.get("action", ""), result.get("mode", ""))
        return result
    except Exception as exc:
        raise internal_error("command", exc)


@app.get("/logs")
async def fetch_logs(limit: int = Query(50, ge=1, le=500), user=Depends(get_current_user)):
    try:
        logs = get_logs(limit)
        return {"status": "success", "count": len(logs), "logs": logs}
    except Exception as exc:
        raise internal_error("logs", exc)


@app.post("/login")
async def login(req: LoginRequest, request: Request):
    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    if len(_login_attempts) >= _MAX_TRACKED_CLIENTS:
        # Drop stale buckets wholesale; the active window is 60 seconds.
        _login_attempts.clear()
    attempts = _login_attempts[client]
    while attempts and now - attempts[0] > 60:
        attempts.popleft()
    if len(attempts) >= 10:
        raise HTTPException(status_code=429, detail="Too many login attempts; retry later")
    user = auth_module.authenticate_user(req.username, req.password)
    if not user:
        attempts.append(now)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    attempts.clear()
    token = auth_module.create_access_token({"sub": user["username"], "role": user.get("role", "user")})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user["username"],
        "role": user.get("role", "user"),
    }


@app.get("/gita/random")
async def random_verse():
    return gita_engine.get_random_verse()


@app.get("/gita/verse/{chapter}/{verse}")
async def get_verse(chapter: int, verse: int):
    return gita_engine.get_verse(chapter, verse)


@app.get("/dashboard-data")
async def dashboard_data(user=Depends(get_current_user)):
    try:
        return {"visualization": visualization_engine.get_all_dashboard_data(), "recent_logs": get_logs(10), "system_status": brain.process("status", session_id=str(user["sub"])), "gita": gita_engine.get_random_verse()}
    except Exception as exc:
        raise internal_error("dashboard data", exc)


@app.get("/incident/endpoint-scan")
async def incident_endpoint_scan(user=Depends(get_current_user)):
    try:
        from vrin_SOC.agents.endpoint_security import endpoint_security
        return endpoint_security.scan()
    except Exception as exc:
        raise internal_error("incident endpoint scan", exc)


@app.get("/incident/ids")
async def incident_ids(prevent: bool = Query(True),
                      interface: str = Query("eth0", max_length=32,
                                             pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$"),
                      user=Depends(get_current_user)):
    try:
        from vrin_SOC.automation.ids_monitor import ids_monitor
        return ids_monitor.monitor(interface=interface, prevent=prevent)
    except Exception as exc:
        raise internal_error("incident ids", exc)


@app.get("/incident/idps")
async def incident_idps(prevent: bool = Query(True),
                       interface: str = Query("eth0", max_length=32,
                                              pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$"),
                       user=Depends(get_current_user)):
    try:
        from vrin_SOC.automation.ids_monitor import ids_monitor
        return ids_monitor.monitor(interface=interface, prevent=prevent)
    except Exception as exc:
        raise internal_error("incident idps", exc)


@app.get("/incident/firewall")
async def incident_firewall(user=Depends(get_current_user)):
    try:
        from vrin_SOC.automation.firewall import firewall_module
        return firewall_module.check_and_block()
    except Exception as exc:
        raise internal_error("incident firewall", exc)


@app.get("/incident/overview")
async def incident_overview(user=Depends(get_current_admin)):
    try:
        from vrin_SOC.agents.endpoint_security import endpoint_security
        from vrin_SOC.automation.ids_monitor import ids_monitor
        from vrin_SOC.automation.firewall import firewall_module
        return {
            "status": "success",
            "endpoint_scan": endpoint_security.scan(),
            "idps_monitor": ids_monitor.monitor(),
            "firewall_check": firewall_module.check_and_block(),
        }
    except Exception as exc:
        raise internal_error("incident overview", exc)


@app.post("/incident/respond")
async def incident_respond(payload: Dict[str, Any], user=Depends(get_current_admin)):
    try:
        from vrin_SOC.automation.response_engine import response_engine
        return response_engine.respond(payload)
    except Exception as exc:
        raise internal_error("incident respond", exc)


@app.post("/incident/respond/validate")
async def incident_respond_validate(req: IncidentValidationRequest, user=Depends(get_current_admin)):
    """Human validation gate for high-impact Blue Team response.

    The initial ``/incident/respond`` call prepares and explains a proposed
    action. This endpoint records the analyst verdict and only then executes
    approved containment.
    """
    try:
        from vrin_SOC.automation.response_engine import response_engine
        analyst = req.analyst.strip() or str(user["sub"])
        return response_engine.validate_and_respond(
            req.threat_data,
            analyst=analyst,
            decision=req.decision,
            verdict=req.verdict,
            notes=req.notes,
        )
    except Exception as exc:
        raise internal_error("incident respond validate", exc)


@app.get("/autonomy/status")
async def autonomy_status(user=Depends(get_current_user)):
    try:
        return {"status": "success", "data": autonomous_agent.status()}
    except Exception as exc:
        raise internal_error("autonomy status", exc)


@app.post("/autonomy/start")
async def autonomy_start(user=Depends(get_current_admin)):
    try:
        return {"status": "success", "data": autonomous_agent.start()}
    except Exception as exc:
        raise internal_error("autonomy start", exc)


@app.post("/autonomy/stop")
async def autonomy_stop(user=Depends(get_current_admin)):
    try:
        return {"status": "success", "data": autonomous_agent.stop()}
    except Exception as exc:
        raise internal_error("autonomy stop", exc)


@app.post("/autonomy/emergency-stop")
async def autonomy_emergency_stop(user=Depends(get_current_admin)):
    try:
        return {"status": "success", "data": autonomous_agent.emergency_stop()}
    except Exception as exc:
        raise internal_error("autonomy emergency stop", exc)


@app.post("/autonomy/reset")
async def autonomy_reset(user=Depends(get_current_admin)):
    try:
        return {"status": "success", "data": autonomous_agent.reset_emergency()}
    except Exception as exc:
        raise internal_error("autonomy reset", exc)


@app.post("/autonomy/run-goal")
async def autonomy_run_goal(goal_id: int, user=Depends(get_current_admin)):
    try:
        scheduler = Scheduler()
        return scheduler.run_goal(goal_id)
    except Exception as exc:
        raise internal_error("autonomy run goal", exc)


@app.post("/autonomy/run-pending-tasks")
async def autonomy_run_pending_tasks(user=Depends(get_current_admin)):
    try:
        scheduler = Scheduler()
        return scheduler.run_pending_tasks()
    except Exception as exc:
        raise internal_error("autonomy run pending tasks", exc)


@app.post("/autonomy/recover-tasks")
async def autonomy_recover_tasks(user=Depends(get_current_admin)):
    try:
        scheduler = Scheduler()
        return scheduler.recover_stuck_tasks()
    except Exception as exc:
        raise internal_error("autonomy recover tasks", exc)


@app.post("/autonomy/set-mode")
async def autonomy_set_mode(req: AutonomyModeRequest, user=Depends(get_current_admin)):
    try:
        result = autonomous_agent.set_mode(req.mode)
        brain.mode = req.mode
        return {"status": "success", "data": result}
    except Exception as exc:
        raise internal_error("autonomy set mode", exc)


@app.post("/ml/anomaly")
async def check_anomaly(payload: Dict[str, Any], user=Depends(get_current_user)):
    return anomaly_detector.detect(payload.get("command") or payload.get("text") or str(payload))


@app.post("/ml/risk")
async def check_risk(payload: Dict[str, Any], user=Depends(get_current_user)):
    return risk_scoring.score(payload)


@app.post("/ml/risk/feedback")
async def record_risk_feedback(req: RiskFeedbackRequest, user=Depends(get_current_user)):
    """Store analyst validation feedback for continuous improvement."""
    from vrin_SOC.database.db import add_alert_feedback
    analyst = str(user["sub"])
    return add_alert_feedback(
        alert_id=req.alert_id,
        verdict=req.verdict,
        analyst=analyst,
        notes=req.notes,
        risk_score=req.risk_score,
        source_ip=req.source_ip,
        signal_summary=req.signal_summary,
    )


@app.get("/ml/risk/feedback")
async def list_risk_feedback(limit: int = Query(50, ge=1, le=500), user=Depends(get_current_user)):
    from vrin_SOC.database.db import get_alert_feedback
    return {"status": "success", "feedback": get_alert_feedback(limit)}


@app.get("/ml/predict")
async def predict_threat(user=Depends(get_current_user)):
    return prediction_model.predict(get_logs(50))


@app.get("/ml/pipeline")
async def pipeline_status(user=Depends(get_current_user)):
    return {"clean_data": data_pipeline.clean_data(), "csv_export": data_pipeline.to_csv()}


@app.get("/tools/verify")
async def verify_tools(user=Depends(get_current_user)):
    from vrin_SOC.tools.installer import verify_all_tools
    return verify_all_tools()


@app.get("/team/state", tags=["teams"])
async def team_state(user=Depends(get_current_user)):
    from vrin_SOC.tools.installer import verify_all_tools
    pending = brain.pending_for(str(user["sub"]))
    preview = None
    if pending:
        preview = {
            "command": pending.get("original_command"),
            "target": pending.get("target"),
            "timestamp": pending.get("timestamp"),
        }
    return {
        "status": "success",
        "pending": preview,
        "blocked_ips": get_blocked_ips(50),
        "threats": get_threats(30),
        "recent_logs": get_logs(20),
        "tools": verify_all_tools(),
    }


@app.post("/team/red", tags=["teams"])
async def team_red(req: TeamActionRequest, user=Depends(get_current_user)):
    action = req.action.strip().lower()
    template = RED_TEAM_ACTIONS.get(action)
    if not template:
        raise HTTPException(status_code=422, detail=f"Unknown red-team action '{req.action}'")
    target = req.target.strip()
    if action in {"nmap", "recon", "nikto", "vuln", "gobuster", "dirb"} and not target:
        target = "127.0.0.1"
    if action == "whois" and not target:
        target = "example.com"
    if action == "tcpdump" and not target:
        target = "lo"
    if action in {"amass", "sublist3r"} and not target:
        raise HTTPException(status_code=422, detail="A domain is required")
    try:
        return _run_team_command(_render_team_command(template, target, req.details), user)
    except Exception as exc:
        raise internal_error("team red", exc)


@app.post("/team/blue", tags=["teams"])
async def team_blue(req: TeamActionRequest, user=Depends(get_current_user)):
    action = req.action.strip().lower()
    template = BLUE_TEAM_ACTIONS.get(action)
    if not template:
        raise HTTPException(status_code=422, detail=f"Unknown blue-team action '{req.action}'")
    if action == "block" and not req.target.strip():
        raise HTTPException(status_code=422, detail="An IP is required to block")
    try:
        return _run_team_command(_render_team_command(template, req.target, req.details), user)
    except Exception as exc:
        raise internal_error("team blue", exc)


@app.post("/team/confirm", tags=["teams"])
async def team_confirm(req: TeamConfirmRequest, user=Depends(get_current_user)):
    if not brain.pending_for(str(user["sub"])):
        raise HTTPException(status_code=409, detail="No pending Red Team confirmation for this session")
    try:
        return _run_team_command("yes" if req.decision == "yes" else "no", user)
    except Exception as exc:
        raise internal_error("team confirm", exc)


# -------------------------------------------------------------------------
# Dedicated SOC ↔ independent Vrin_TI gateway. Existing SOC routes and
# safety/authorization behavior above remain unchanged.
# -------------------------------------------------------------------------
def require_ti_service(x_vrindha_service_token: str = Header(default="")) -> str:
    if not intelligence_gateway.service_token:
        raise HTTPException(status_code=503, detail="TI service authentication is not configured")
    if not intelligence_gateway.authenticate_service(x_vrindha_service_token):
        raise HTTPException(status_code=401, detail="invalid service credentials")
    return "threat_intelligence"


@app.get("/intelligence/health", tags=["intelligence-gateway"])
async def intelligence_health(_service=Depends(require_ti_service)):
    """Service-authenticated, non-recursive health for the TI HTTP transport."""
    return intelligence_gateway.transport_health()


@app.post("/intelligence/events", tags=["intelligence-gateway"])
async def intelligence_event(event: IntelligenceEvent, _service=Depends(require_ti_service)):
    """TI → SOC/Correlation event ingress. This endpoint never executes actions."""
    return await intelligence_gateway.receive_ti_event(event)


@app.get("/threat-intel/health", tags=["threat-intelligence"])
async def threat_intel_health(user=Depends(get_current_user)):
    return await intelligence_gateway.health()


@app.get("/threat-intel/status", tags=["threat-intelligence"])
async def threat_intel_status(user=Depends(get_current_user)):
    try:
        return await intelligence_gateway.resource("/threat-intel/status")
    except Exception:
        return await intelligence_gateway.health()


@app.post("/threat-intel/lookup", tags=["threat-intelligence"])
async def threat_intel_lookup(req: LookupRequest, user=Depends(get_current_user)):
    try:
        return await intelligence_gateway.lookup(req.indicator, req.indicator_type)
    except InvalidIndicator as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.get("/threat-intel/indicators/{indicator:path}", tags=["threat-intelligence"])
async def threat_intel_indicator(indicator: str = APIPath(max_length=4096), indicator_type: Optional[str] = Query(default=None),
                                 user=Depends(get_current_user)):
    try:
        return await intelligence_gateway.lookup(indicator, indicator_type)
    except InvalidIndicator as exc:
        raise HTTPException(status_code=422, detail=str(exc))


@app.post("/threat-intel/events", tags=["threat-intelligence"])
async def soc_to_ti_event(event: IntelligenceEvent, user=Depends(get_current_user)):
    """Authenticated analyst/SOC observation routed to TI with durable fallback."""
    event.source = "soc"
    event.context = {**event.context, "soc_user": str(user["sub"])}
    return await intelligence_gateway.send_observation(event)


@app.post("/threat-intel/sighting", tags=["threat-intelligence"])
async def soc_to_ti_sighting(req: SightingRequest, user=Depends(get_current_user)):
    event = IntelligenceEvent(event_type="ioc_observation", source="soc", indicator=req.indicator, asset=req.asset,
        timestamp=req.timestamp, confidence=req.confidence, correlation_id=req.correlation_id,
        context={**req.context, "soc_user": str(user["sub"])})
    return await intelligence_gateway.send_observation(event)


@app.get("/threat-intel/feeds", tags=["threat-intelligence"])
async def threat_intel_feeds(user=Depends(get_current_user)):
    try:
        return await intelligence_gateway.resource("/threat-intel/feeds")
    except Exception as exc:
        return {"feeds": [], "status": "degraded", "error": str(exc)[:256]}


@app.post("/threat-intel/feeds/{feed}/sync", tags=["threat-intelligence"])
async def threat_intel_sync(feed: str = APIPath(pattern=r"^[a-z0-9_-]{1,64}$"), user=Depends(get_current_admin)):
    try:
        return await intelligence_gateway.sync_feed(feed)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"TI feed service unavailable: {str(exc)[:128]}")


@app.get("/threat-intel/correlations", tags=["threat-intelligence"])
async def threat_intel_correlations(user=Depends(get_current_user)):
    try:
        return await intelligence_gateway.resource("/threat-intel/correlations")
    except Exception:
        return {"correlations": intelligence_gateway.database.correlations(), "status": "degraded"}


@app.get("/threat-intel/sightings", tags=["threat-intelligence"])
async def threat_intel_sightings(user=Depends(get_current_user)):
    try:
        return await intelligence_gateway.resource("/threat-intel/sightings")
    except Exception:
        return {"sightings": intelligence_gateway.database.list_sightings(), "status": "degraded"}


@app.get("/threat-intel/vulnerabilities", tags=["threat-intelligence"])
async def threat_intel_vulnerabilities(kev_only: bool = False, user=Depends(get_current_user)):
    try:
        suffix = "?kev_only=true" if kev_only else ""
        return await intelligence_gateway.resource(f"/threat-intel/vulnerabilities{suffix}")
    except Exception:
        return {"vulnerabilities": intelligence_gateway.database.vulnerabilities(kev_only), "status": "degraded"}


@app.get("/threat-intel/actors", tags=["threat-intelligence"])
async def threat_intel_actors(user=Depends(get_current_user)):
    try:
        return await intelligence_gateway.resource("/threat-intel/actors")
    except Exception:
        return {"actors": intelligence_gateway.database.list_entities("threat-actor"), "status": "degraded"}


@app.get("/threat-intel/campaigns", tags=["threat-intelligence"])
async def threat_intel_campaigns(user=Depends(get_current_user)):
    try:
        return await intelligence_gateway.resource("/threat-intel/campaigns")
    except Exception:
        return {"campaigns": intelligence_gateway.database.list_entities("campaign"), "status": "degraded"}


@app.get("/threat-intel/malware", tags=["threat-intelligence"])
async def threat_intel_malware(user=Depends(get_current_user)):
    try:
        return await intelligence_gateway.resource("/threat-intel/malware")
    except Exception:
        return {"malware": intelligence_gateway.database.list_entities("malware"), "status": "degraded"}


@app.get("/threat-intel/mitre/{technique}", tags=["threat-intelligence"])
async def threat_intel_mitre(technique: str = APIPath(pattern=r"^T\d{4}(?:\.\d{3})?$"), user=Depends(get_current_user)):
    try:
        return await intelligence_gateway.resource(f"/threat-intel/mitre/{technique.upper()}")
    except Exception as exc:
        return {"technique": technique.upper(), "matches": [], "status": "degraded", "error": str(exc)[:256]}


@app.get("/threat-intel/reports", tags=["threat-intelligence"])
async def threat_intel_reports(user=Depends(get_current_user)):
    try:
        return await intelligence_gateway.resource("/threat-intel/reports")
    except Exception:
        return {"reports": intelligence_gateway.database.reports(), "status": "degraded"}


# -------------------------------------------------------------------------
# Hive coordination layer — agent registry, swarm dispatch, health.
# -------------------------------------------------------------------------
class HiveAgentRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    kind: str = Field(min_length=1, max_length=64)
    capabilities: list = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class HiveDispatchRequest(BaseModel):
    command: str = Field(min_length=1, max_length=2000)
    priority: str = Field("normal", pattern=r"^(low|normal|high|critical)$")
    capabilities: list = Field(default_factory=list)


@app.get("/hive/health", tags=["hive"])
async def hive_health(user=Depends(get_current_user)):
    """Hive coordination layer health check."""
    return hive_coordinator.health()


@app.get("/hive/snapshot", tags=["hive"])
async def hive_snapshot(user=Depends(get_current_user)):
    """Full point-in-time snapshot of the agent hive."""
    return hive_coordinator.snapshot()


@app.get("/hive/agents", tags=["hive"])
async def hive_agents(kind: Optional[str] = None, user=Depends(get_current_user)):
    """List registered agents, optionally filtered by kind."""
    return hive_coordinator.list_agents(kind=kind)


@app.get("/hive/agents/{name}", tags=["hive"])
async def hive_agent_status(name: str = APIPath(max_length=128), user=Depends(get_current_user)):
    """Status of a single registered agent."""
    return hive_coordinator.agent_status(name)


@app.post("/hive/agents", status_code=201, tags=["hive"])
async def hive_register_agent(req: HiveAgentRequest, user=Depends(get_current_admin)):
    """Register a new agent in the hive (admin only)."""
    return hive_coordinator.register_agent(req.name, req.kind, req.capabilities, req.metadata)


@app.delete("/hive/agents/{name}", tags=["hive"])
async def hive_deregister_agent(name: str = APIPath(max_length=128), user=Depends(get_current_admin)):
    """Remove an agent from the hive registry (admin only)."""
    return hive_coordinator.deregister_agent(name)


@app.post("/hive/agents/{name}/heartbeat", tags=["hive"])
async def hive_heartbeat(name: str = APIPath(max_length=128), user=Depends(get_current_user)):
    """Record a heartbeat for an agent."""
    return hive_coordinator.heartbeat_agent(name)


@app.post("/hive/dispatch", tags=["hive"])
async def hive_dispatch(req: HiveDispatchRequest, user=Depends(get_current_user)):
    """Dispatch a task to matching agents through the swarm."""
    return hive_coordinator.dispatch(req.command, req.priority, req.capabilities or None)


@app.get("/hive/tasks", tags=["hive"])
async def hive_tasks(status: Optional[str] = None, user=Depends(get_current_user)):
    """List hive tasks, optionally filtered by status."""
    return hive_coordinator.list_tasks(status=status)


@app.post("/hive/reap", tags=["hive"])
async def hive_reap(user=Depends(get_current_admin)):
    """Reap stale agent heartbeats (admin only)."""
    return hive_coordinator.reap_stale()


# Coordination layer (HIVE multi-agent: Commander, Infrastructure, Threat
# Intelligence, SOC Analyst, Data Science, Knowledge, Ethics & Dharma).
app.include_router(coordination_router)

# Local, dependency-free blockchain ledger (integrity anchor, localhost-only).
app.include_router(blockchain_router)


dashboard_path = Path(__file__).parent.parent / "dashboard"
if dashboard_path.exists():
    app.mount("/dashboard", StaticFiles(directory=str(dashboard_path), html=True), name="dashboard")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.getenv("API_HOST", "0.0.0.0"), port=int(os.getenv("API_PORT", "8000")))
