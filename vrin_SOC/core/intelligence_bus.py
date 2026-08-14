"""SOC-side adapter for the independent Vrin_TI Intelligence Gateway.

The existing SOC remains authoritative for SOC workflows. This adapter only
validates/exchanges intelligence, enriches alerts and durably queues outages;
it never executes a command, firewall change, scan, exploit or response action.
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Deque, Dict, Optional
from urllib.parse import urlsplit
import asyncio
import logging
import os
import sys

# Vrin_TI is a sibling system, not a child package of the SOC. Add only the
# repository root so the dedicated bridge can import the shared event contract
# when the SOC is launched from its own working directory.
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from Vrin_TI.config import config as ti_config
from Vrin_TI.database import ThreatDatabase
from Vrin_TI.models import IntelligenceEvent
from Vrin_TI.normalization import canonical_type, detect_type, normalize_indicator
from Vrin_TI.security import constant_time_token_valid

logger = logging.getLogger(__name__)


class IntelligenceGateway:
    def __init__(self, database: Optional[ThreatDatabase] = None, ti_url: Optional[str] = None,
                 service_token: Optional[str] = None):
        self.ti_url = (ti_url or os.getenv("VRINDHA_TI_URL", "http://127.0.0.1:8010")).rstrip("/")
        self.service_token = service_token if service_token is not None else os.getenv("VRINDHA_TI_API_KEY", "")
        self.database = database or ThreatDatabase(ti_config.database_path)
        self.recent_ti_events: Deque[Dict[str, Any]] = deque(maxlen=1000)
        self.last_soc_event: Optional[datetime] = None
        self.last_ti_event: Optional[datetime] = None
        self.state = "disconnected"
        self.last_error = ""
        self._validate_url()

    def _validate_url(self) -> None:
        parsed = urlsplit(self.ti_url)
        host = parsed.hostname or ""
        local = host in {"localhost", "127.0.0.1", "::1"}
        try:
            local = local or ip_address(host).is_loopback
        except ValueError:
            pass
        if parsed.scheme == "http" and local:
            return
        if parsed.scheme != "https" or not host or parsed.username or parsed.password:
            raise ValueError("remote Vrin_TI URL must use HTTPS without embedded credentials")

    def authenticate_service(self, provided: str) -> bool:
        return constant_time_token_valid(provided, self.service_token)

    async def _request(self, method: str, path: str, json_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self.service_token:
            raise RuntimeError("VRINDHA_TI_API_KEY is not configured")
        try:
            import httpx
        except ImportError as exc:
            raise RuntimeError("httpx is unavailable") from exc
        async with httpx.AsyncClient(base_url=self.ti_url, timeout=5, verify=True, follow_redirects=False,
                                     headers={"X-Vrindha-Service-Token": self.service_token, "User-Agent": "Vrindha-SOC-Gateway/1.0"}) as client:
            response = await client.request(method, path, json=json_data)
            response.raise_for_status()
            value = response.json()
            return value if isinstance(value, dict) else {"data": value}

    async def send_observation(self, event: IntelligenceEvent) -> Dict[str, Any]:
        """SOC→TI, with durable local queue fallback during any TI outage."""
        self.last_soc_event = datetime.now(timezone.utc)
        try:
            result = await self._request("POST", "/intelligence/events", event.model_dump(mode="json"))
            self.state = "connected"
            self.last_error = ""
            return result
        except Exception as exc:
            self.state = "degraded"
            self.last_error = str(exc)[:512]
            try:
                queued = await asyncio.to_thread(self.database.queue_event, event, "inbound")
                return {"status": "queued", "degraded": True, "reason": "TI endpoint unavailable; event retained in durable queue",
                        "event_id": str(event.event_id), "queued": queued, "error": self.last_error}
            except Exception as database_exc:
                self.state = "error"
                return {"status": "error", "degraded": True,
                        "reason": "TI endpoint and durable queue are unavailable; SOC continues without TI",
                        "event_id": str(event.event_id), "queued": False,
                        "error": self.last_error, "database_error": str(database_exc)[:512]}

    async def receive_ti_event(self, event: IntelligenceEvent) -> Dict[str, Any]:
        """TI→SOC/CORRELATION. Store enrichment, but execute no action."""
        self.last_ti_event = datetime.now(timezone.utc)
        payload = event.model_dump(mode="json")
        self.recent_ti_events.append(payload)
        risk_analysis = None
        try:
            from database.db import add_log
            await asyncio.to_thread(add_log, f"TI:{event.event_type}", str(payload)[:2000], str(event.severity).title(), "intelligence_received", "blue")
            if event.event_type == "risk_update":
                from ml.risk_scoring import risk_scoring
                risk_analysis = await asyncio.to_thread(risk_scoring.score, payload)
        except Exception:
            # Existing SOC logging/risk failure must not reject otherwise valid TI.
            logger.exception("SOC could not persist or score a validated TI event")
        self.state = "connected"
        return {"status": "accepted", "event_id": str(event.event_id), "correlation_id": str(event.correlation_id),
                "routed_to": ["soc", "correlation"] + (["risk"] if event.event_type == "risk_update" else []),
                "soc_risk_analysis": risk_analysis, "defensive_action_executed": False,
                "requires_human_approval": bool(event.context.get("requires_human_approval", True))}

    async def lookup(self, value: str, indicator_type: Optional[str] = None) -> Dict[str, Any]:
        try:
            return await self._request("POST", "/threat-intel/lookup", {"indicator": value, "indicator_type": indicator_type})
        except Exception as exc:
            self.state = "degraded"
            self.last_error = str(exc)[:512]
            kind = canonical_type(indicator_type).value if indicator_type else detect_type(value).value
            normalized = normalize_indicator(kind, value)
            local = await asyncio.to_thread(self.database.get_indicator, kind, normalized)
            if local:
                return {"found": True, "malicious": local["active"] and local["threat_score"] >= 40,
                        "degraded": True, "source": "local_ti_database", **local}
            return {"found": False, "indicator_type": kind, "normalized_value": normalized, "malicious": False,
                    "confidence": 0, "threat_score": 0, "sources": [], "sightings": [], "degraded": True}

    async def resource(self, path: str) -> Dict[str, Any]:
        if not path.startswith("/threat-intel/") or ".." in path:
            raise ValueError("invalid TI resource path")
        return await self._request("GET", path)

    async def sync_feed(self, feed: str) -> Dict[str, Any]:
        if not feed.replace("_", "").replace("-", "").isalnum() or len(feed) > 64:
            raise ValueError("invalid feed name")
        return await self._request("POST", f"/threat-intel/feeds/{feed}/sync")

    def transport_health(self) -> Dict[str, Any]:
        """Non-recursive liveness for the TI HTTP transport handshake."""
        return {"service": "soc_ti_gateway", "status": "connected", "authenticated": bool(self.service_token),
                "local_queue_depth": self.database.queue_depth(), "defensive_action_capability": False}

    async def health(self) -> Dict[str, Any]:
        try:
            remote = await self._request("GET", "/threat-intel/health")
            self.state = "connected"
            self.last_error = ""
        except Exception as exc:
            self.state = "degraded"
            self.last_error = str(exc)[:512]
            remote = None
        return {"service": "soc_ti_gateway", "status": self.state, "ti_url": self.ti_url,
                "remote_ti": remote, "local_queue_depth": self.database.queue_depth(),
                "last_soc_event": self.last_soc_event.isoformat() if self.last_soc_event else None,
                "last_ti_event": self.last_ti_event.isoformat() if self.last_ti_event else None,
                "last_error": self.last_error, "authenticated": bool(self.service_token),
                "defensive_action_capability": False}


intelligence_gateway = IntelligenceGateway()
