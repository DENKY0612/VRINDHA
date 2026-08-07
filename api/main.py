"""FastAPI backend for the Vrindha SOC system."""
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, Optional
import logging
import os
import sys
import time

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

sys.path.append(str(Path(__file__).parent.parent))

from api.auth import auth_module
from core.brain import brain
from core.gita_engine import gita_engine
from database.db import add_log, get_logs
from ml.anomaly_detector import anomaly_detector
from ml.data_pipeline import data_pipeline
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


def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer authentication required", headers={"WWW-Authenticate": "Bearer"})
    payload = auth_module.verify_token(authorization[7:].strip())
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token", headers={"WWW-Authenticate": "Bearer"})
    return payload


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
    return {"access_token": token, "token_type": "bearer", "user": user["username"]}


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
