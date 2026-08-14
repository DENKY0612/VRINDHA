"""FastAPI backend for the Vrindha SOC system."""
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, Literal, Optional
import logging
import os
import sys
import time

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

sys.path.append(str(Path(__file__).parent.parent))

from api.auth import (
    BootstrapClosedError,
    DuplicateUserError,
    InvalidPasswordError,
    InvalidRoleError,
    InvalidUsernameError,
    auth_module,
)
from core.brain import brain
from core.gita_engine import gita_engine
from database.db import add_log, get_logs
from ml.anomaly_detector import anomaly_detector
from ml.data_pipeline import data_pipeline
from autonomous.agent import autonomous_agent
from autonomous.scheduler import Scheduler
from autonomous.task_manager import task_manager
from ml.prediction_model import prediction_model
from ml.risk_scoring import risk_scoring
from ml.visualization import visualization_engine

logger = logging.getLogger(__name__)
app = FastAPI(title="Vrindha AI SOC System", description="Ethical agentic cybersecurity platform", version="1.1.0")

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


# OpenAPI Bearer security scheme; FastAPI exposes the Authorize control in
# Swagger UI because protected endpoints depend on this scheme.
bearer_scheme = HTTPBearer(
    auto_error=False,
    scheme_name="BearerAuth",
    description="JWT returned by POST /login or first-user POST /register",
)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Dict[str, Any]:
    """Validate the Bearer JWT and return its claims plus the live user role.

    Tokens are rejected when the account was disabled or removed, so disabling
    a user also revokes their existing tokens.
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Bearer authentication required", headers={"WWW-Authenticate": "Bearer"})
    payload = auth_module.verify_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    user = auth_module.load_users().get(payload.get("sub", ""))
    if not user or not user.get("active", True):
        raise HTTPException(status_code=401, detail="Account is disabled or no longer exists", headers={"WWW-Authenticate": "Bearer"})
    return {**payload, "role": user.get("role", payload.get("role", "user"))}


def get_current_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required")
    return user


def internal_error(context: str, exc: Exception) -> HTTPException:
    logger.exception("%s failed", context)
    return HTTPException(status_code=500, detail="Internal server error")


# Small per-process login throttle. A reverse proxy should add distributed rate
# limiting in multi-worker production deployments.
_login_attempts: Dict[str, deque] = defaultdict(deque)


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
        from agents.endpoint_security import endpoint_security
        return endpoint_security.scan()
    except Exception as exc:
        raise internal_error("incident endpoint scan", exc)


@app.get("/incident/ids")
async def incident_ids(prevent: bool = Query(True), interface: str = "eth0", user=Depends(get_current_user)):
    try:
        from automation.ids_monitor import ids_monitor
        return ids_monitor.monitor(interface=interface, prevent=prevent)
    except Exception as exc:
        raise internal_error("incident ids", exc)


@app.get("/incident/idps")
async def incident_idps(prevent: bool = Query(True), interface: str = "eth0", user=Depends(get_current_user)):
    try:
        from automation.ids_monitor import ids_monitor
        return ids_monitor.monitor(interface=interface, prevent=prevent)
    except Exception as exc:
        raise internal_error("incident idps", exc)


@app.get("/incident/firewall")
async def incident_firewall(user=Depends(get_current_user)):
    try:
        from automation.firewall import firewall_module
        return firewall_module.check_and_block()
    except Exception as exc:
        raise internal_error("incident firewall", exc)


@app.get("/incident/overview")
async def incident_overview(user=Depends(get_current_admin)):
    try:
        from agents.endpoint_security import endpoint_security
        from automation.ids_monitor import ids_monitor
        from automation.firewall import firewall_module
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
        from automation.response_engine import response_engine
        return response_engine.respond(payload)
    except Exception as exc:
        raise internal_error("incident respond", exc)


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


@app.get("/ml/predict")
async def predict_threat(user=Depends(get_current_user)):
    return prediction_model.predict(get_logs(50))


@app.get("/ml/pipeline")
async def pipeline_status(user=Depends(get_current_user)):
    return {"clean_data": data_pipeline.clean_data(), "csv_export": data_pipeline.to_csv()}


@app.get("/tools/verify")
async def verify_tools(user=Depends(get_current_user)):
    from tools.installer import verify_all_tools
    return verify_all_tools()


dashboard_path = Path(__file__).parent.parent / "dashboard"
if dashboard_path.exists():
    app.mount("/dashboard", StaticFiles(directory=str(dashboard_path), html=True), name="dashboard")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.getenv("API_HOST", "0.0.0.0"), port=int(os.getenv("API_PORT", "8000")))
