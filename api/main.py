"""
FastAPI Backend - Per DAY 24-26 and START UP.pdf FastAPI Backend Prompt
Features: REST API endpoints, connect to AI Brain, return JSON responses
Endpoints: POST /command → run AI command, GET /logs → fetch logs, GET /status → system status
Requirements: Use FastAPI, async support, proper error handling, modular structure
Also includes: Authentication, Dashboard data, ML intelligence endpoints
"""
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any
import sys
from pathlib import Path

# Ensure imports
sys.path.append(str(Path(__file__).parent.parent))

from core.brain import brain
from database.db import get_logs, add_log
from api.auth import auth_module
from core.gita_engine import gita_engine
from ml.visualization import visualization_engine
from ml.anomaly_detector import anomaly_detector
from ml.risk_scoring import risk_scoring
from ml.prediction_model import prediction_model
from ml.data_pipeline import data_pipeline

app = FastAPI(
    title="Vrindha AI SOC System",
    description="Agentic AI Cybersecurity System - Startup-ready SOC platform with Dharma Engine",
    version="1.0.0"
)

# CORS for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic models
class CommandRequest(BaseModel):
    command: str
    auto_confirm: bool = False
    target: Optional[str] = None

class LoginRequest(BaseModel):
    username: str
    password: str

# Auth dependency
def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization:
        # Allow unauthenticated for MVP, but log
        return {"sub": "anonymous", "role": "guest"}
    # Expected Bearer <token>
    token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization
    payload = auth_module.verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    return payload

@app.get("/")
async def root():
    return {
        "message": "Vrindha AI SOC System - Running",
        "mode": "defensive",
        "version": "1.0.0",
        "endpoints": ["/command", "/logs", "/status", "/login", "/dashboard-data", "/gita/random", "/ml/anomaly", "/ml/risk"]
    }

@app.get("/status")
async def get_status(user=Depends(get_current_user)):
    result = brain.process("status")
    return JSONResponse(content=result)

@app.post("/command")
async def run_command(req: CommandRequest, user=Depends(get_current_user)):
    try:
        result = brain.process(req.command, auto_confirm=req.auto_confirm)
        # Log
        try:
            add_log(req.command, str(result.get("message",""))[:2000], result.get("data", {}).get("threat", {}).get("risk_level", "Low") if isinstance(result.get("data"), dict) else "Low", result.get("action",""), result.get("mode",""))
        except Exception as e:
            print(f"Log error: {e}")
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/logs")
async def fetch_logs(limit: int = 50, user=Depends(get_current_user)):
    try:
        logs = get_logs(limit)
        return {"status": "success", "count": len(logs), "logs": logs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/login")
async def login(req: LoginRequest):
    user = auth_module.authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = auth_module.create_access_token(data={"sub": user["username"], "role": user.get("role","user")})
    return {"access_token": token, "token_type": "bearer", "user": user["username"]}

@app.get("/gita/random")
async def random_verse():
    verse = gita_engine.get_random_verse()
    return verse

@app.get("/gita/verse/{chapter}/{verse}")
async def get_verse(chapter: int, verse: int):
    result = gita_engine.get_verse(chapter, verse)
    return result

@app.get("/dashboard-data")
async def dashboard_data(user=Depends(get_current_user)):
    try:
        viz = visualization_engine.get_all_dashboard_data()
        logs = get_logs(10)
        status = brain.process("status")
        return {
            "visualization": viz,
            "recent_logs": logs,
            "system_status": status,
            "gita": gita_engine.get_random_verse()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/ml/anomaly")
async def check_anomaly(payload: Dict[str, Any], user=Depends(get_current_user)):
    try:
        text = payload.get("command") or payload.get("text") or str(payload)
        result = anomaly_detector.detect(text)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/ml/risk")
async def check_risk(payload: Dict[str, Any], user=Depends(get_current_user)):
    try:
        result = risk_scoring.score(payload)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/ml/predict")
async def predict_threat(user=Depends(get_current_user)):
    try:
        logs = get_logs(50)
        result = prediction_model.predict(logs)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/ml/pipeline")
async def pipeline_status(user=Depends(get_current_user)):
    try:
        result = data_pipeline.clean_data()
        csv_res = data_pipeline.to_csv()
        return {"clean_data": result, "csv_export": csv_res}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/tools/verify")
async def verify_tools(user=Depends(get_current_user)):
    try:
        from tools.installer import verify_all_tools
        return verify_all_tools()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Mount dashboard static if exists
dashboard_path = Path(__file__).parent.parent / "dashboard"
if dashboard_path.exists():
    try:
        app.mount("/dashboard", StaticFiles(directory=str(dashboard_path), html=True), name="dashboard")
    except Exception as e:
        print(f"Could not mount dashboard: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
