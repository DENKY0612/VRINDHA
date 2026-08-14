"""Independent authenticated FastAPI service for Vrin_TI."""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, Dict, Optional
import asyncio

from fastapi import Depends, FastAPI, Header, HTTPException, Path, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import PlainTextResponse

from .engine import ThreatIntelligenceEngine, engine as default_engine
from .metrics import metrics
from .models import EnrichmentRequest, IntelligenceEvent, LookupRequest, SightingRequest, ThreatIndicator
from .normalization import InvalidIndicator
from .security import SecurityError, SlidingWindowRateLimiter, constant_time_token_valid


def create_app(ti_engine: ThreatIntelligenceEngine = default_engine) -> FastAPI:
    limiter = SlidingWindowRateLimiter(ti_engine.config.rate_limit_per_minute)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        await ti_engine.start()
        try:
            yield
        finally:
            await ti_engine.stop()

    app = FastAPI(title="Vrindha Threat Intelligence", version="1.0.0",
                  description="Independent defensive CTI and SOC correlation service",
                  docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.ti_engine = ti_engine
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ti_engine.config.allowed_hosts or ["127.0.0.1", "localhost"])

    async def require_service(request: Request, x_vrindha_service_token: str = Header(default="")) -> str:
        if not ti_engine.config.service_token:
            raise HTTPException(status_code=503, detail="service authentication is not configured")
        if not constant_time_token_valid(x_vrindha_service_token, ti_engine.config.service_token):
            ti_engine.database.audit("unknown", "api.authenticate", request.url.path, "denied")
            raise HTTPException(status_code=401, detail="invalid service credentials")
        client = request.client.host if request.client else "unknown"
        if not limiter.allow(client):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        return "service"

    @app.middleware("http")
    async def hardening(request: Request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > ti_engine.config.request_max_bytes:
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=413, content={"detail": "request body too large"})
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response

    @app.get("/", dependencies=[Depends(require_service)])
    async def root():
        return {"service": "vrindha-threat-intelligence", "version": "1.0.0", "defensive_only": True}

    @app.get("/health/live", dependencies=[Depends(require_service)])
    async def liveness():
        return {"service": "threat_intelligence", "alive": True}

    @app.get("/threat-intel/health", dependencies=[Depends(require_service)])
    async def health():
        return await ti_engine.health()

    @app.get("/threat-intel/status", dependencies=[Depends(require_service)])
    async def status():
        return {"health": await ti_engine.health(), "metrics": {**ti_engine.database.metrics(), **metrics.snapshot()},
                "feeds": ti_engine.feeds.status()}

    @app.post("/threat-intel/lookup", dependencies=[Depends(require_service)])
    async def lookup(req: LookupRequest):
        try:
            return ti_engine.lookup(req.indicator, req.indicator_type)
        except InvalidIndicator as exc:
            raise HTTPException(status_code=422, detail=str(exc))

    @app.get("/threat-intel/indicators/{indicator:path}", dependencies=[Depends(require_service)])
    async def get_indicator(indicator: str = Path(max_length=4096), indicator_type: Optional[str] = Query(default=None)):
        try:
            return ti_engine.lookup(indicator, indicator_type)
        except InvalidIndicator as exc:
            raise HTTPException(status_code=422, detail=str(exc))

    @app.post("/threat-intel/indicators", status_code=201, dependencies=[Depends(require_service)])
    async def ingest(indicator: ThreatIndicator):
        try:
            return await ti_engine.ingest_indicator(indicator)
        except InvalidIndicator as exc:
            raise HTTPException(status_code=422, detail=str(exc))

    @app.post("/threat-intel/enrich", dependencies=[Depends(require_service)])
    async def enrich(req: EnrichmentRequest):
        try:
            return await ti_engine.enrich(req.indicator, req.indicator_type, req.allow_external)
        except InvalidIndicator as exc:
            raise HTTPException(status_code=422, detail=str(exc))

    @app.post("/threat-intel/sighting", status_code=201, dependencies=[Depends(require_service)])
    async def sighting(req: SightingRequest):
        event = IntelligenceEvent(event_type="ioc_observation", source=req.source, indicator=req.indicator, asset=req.asset,
            timestamp=req.timestamp, confidence=req.confidence, correlation_id=req.correlation_id, context=req.context)
        try:
            return await ti_engine.process_soc_event(event)
        except SecurityError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    @app.post("/intelligence/events", dependencies=[Depends(require_service)])
    async def receive_event(event: IntelligenceEvent):
        try:
            return await ti_engine.process_soc_event(event)
        except SecurityError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    @app.get("/intelligence/health", dependencies=[Depends(require_service)])
    async def gateway_health():
        health_data = await ti_engine.health()
        return {"gateway": "connected", "ti": health_data}

    @app.get("/threat-intel/feeds", dependencies=[Depends(require_service)])
    async def feeds():
        return {"feeds": ti_engine.feeds.status()}

    @app.post("/threat-intel/feeds/{feed}/sync", dependencies=[Depends(require_service)])
    async def sync_feed(feed: str = Path(pattern=r"^[a-z0-9_-]{1,64}$")):
        try:
            return await ti_engine.feeds.sync(feed)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown feed")

    @app.get("/threat-intel/actors", dependencies=[Depends(require_service)])
    async def actors(limit: int = Query(100, ge=1, le=1000)):
        return {"actors": ti_engine.database.list_entities("threat-actor", limit)}

    @app.get("/threat-intel/campaigns", dependencies=[Depends(require_service)])
    async def campaigns(limit: int = Query(100, ge=1, le=1000)):
        return {"campaigns": ti_engine.database.list_entities("campaign", limit)}

    @app.get("/threat-intel/malware", dependencies=[Depends(require_service)])
    async def malware(limit: int = Query(100, ge=1, le=1000)):
        return {"malware": ti_engine.database.list_entities("malware", limit)}

    @app.get("/threat-intel/vulnerabilities", dependencies=[Depends(require_service)])
    async def vulnerabilities(kev_only: bool = False, limit: int = Query(100, ge=1, le=1000)):
        return {"vulnerabilities": ti_engine.database.vulnerabilities(kev_only, limit)}

    @app.get("/threat-intel/mitre/{technique}", dependencies=[Depends(require_service)])
    async def mitre(technique: str = Path(pattern=r"^T\d{4}(?:\.\d{3})?$")):
        technique = technique.upper()
        entities = ti_engine.database.list_entities("attack-pattern", 10_000)
        matches = [item for item in entities if technique in str(item.get("external_ids", [])).upper() or technique in str(item.get("data", {})).upper()]
        return {"technique": technique, "matches": matches}

    @app.get("/threat-intel/correlations", dependencies=[Depends(require_service)])
    async def correlations(limit: int = Query(100, ge=1, le=1000)):
        return {"correlations": ti_engine.database.correlations(limit)}

    @app.get("/threat-intel/sightings", dependencies=[Depends(require_service)])
    async def sightings(limit: int = Query(100, ge=1, le=1000)):
        return {"sightings": ti_engine.database.list_sightings(limit)}

    @app.get("/threat-intel/reports", dependencies=[Depends(require_service)])
    async def reports(limit: int = Query(100, ge=1, le=1000)):
        return {"reports": ti_engine.database.reports(limit)}

    @app.post("/threat-intel/reports/{indicator_id}", dependencies=[Depends(require_service)])
    async def report(indicator_id: str = Path(pattern=r"^indicator--[A-Za-z0-9-]{8,100}$")):
        try:
            return ti_engine.make_report(indicator_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="indicator not found")

    @app.get("/threat-intel/graph/{ref}", dependencies=[Depends(require_service)])
    async def graph(ref: str, depth: int = Query(3, ge=0, le=6)):
        return ti_engine.graph.traverse(ref, depth)

    @app.post("/threat-intel/stix/import", dependencies=[Depends(require_service)])
    async def import_stix(payload: Dict[str, Any], source: str = Query("api", max_length=128), reliability: float = Query(0.7, ge=0, le=1)):
        try:
            return await asyncio.to_thread(ti_engine.stix.ingest, payload, source, reliability)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

    @app.get("/threat-intel/stix/export/{indicator_id}", dependencies=[Depends(require_service)])
    async def export_stix(indicator_id: str):
        indicator = ti_engine.database.get_indicator_by_id(indicator_id)
        if not indicator:
            raise HTTPException(status_code=404, detail="indicator not found")
        try:
            from .stix import internal_to_stix
            return internal_to_stix(indicator)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))

    @app.get("/threat-intel/integrations", dependencies=[Depends(require_service)])
    async def integrations():
        return await ti_engine.monitor.snapshot(include_external=False)

    @app.post("/threat-intel/yara/scan", dependencies=[Depends(require_service)])
    async def yara_scan(payload: Dict[str, Any]):
        path = payload.get("path")
        if not isinstance(path, str) or len(path) > 4096:
            raise HTTPException(status_code=422, detail="a bounded file path is required")
        return await asyncio.to_thread(ti_engine.monitor.yara.scan, path)

    @app.get("/threat-intel/sigma/rules", dependencies=[Depends(require_service)])
    async def sigma_rules():
        return {"rules": await asyncio.to_thread(ti_engine.monitor.sigma.load)}

    @app.get("/threat-intel/doctor", dependencies=[Depends(require_service)])
    async def doctor():
        return await ti_engine.monitor.doctor()

    @app.get("/metrics", response_class=PlainTextResponse, dependencies=[Depends(require_service)])
    async def prometheus_metrics():
        for name, value in ti_engine.database.metrics().items():
            if name in metrics.NAMES:
                metrics.set(name, value)
        return metrics.prometheus()

    @app.websocket("/ws/threat-intelligence")
    async def intelligence_websocket(websocket: WebSocket):
        # Header-only auth prevents service tokens from appearing in access-log URLs.
        token = websocket.headers.get("x-vrindha-service-token", "")
        if not constant_time_token_valid(token, ti_engine.config.service_token):
            await websocket.close(code=4401, reason="authentication required")
            return
        client = websocket.client.host if websocket.client else "unknown"
        if not limiter.allow(f"ws:{client}"):
            await websocket.close(code=4429, reason="rate limit exceeded")
            return
        await websocket.accept()
        stream = ti_engine.bus.subscribe()
        try:
            while True:
                try:
                    event = await asyncio.wait_for(anext(stream), timeout=ti_engine.config.websocket_heartbeat_seconds)
                    await websocket.send_json({"type": "event", "event": event.model_dump(mode="json")})
                except asyncio.TimeoutError:
                    await websocket.send_json({"type": "heartbeat", "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()})
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            await stream.aclose()

    return app


app = create_app()
