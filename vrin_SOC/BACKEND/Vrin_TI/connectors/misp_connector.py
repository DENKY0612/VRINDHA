"""Optional MISP connector; never required for local TI operation."""
from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urlsplit
import os


class MISPConnector:
    def __init__(self, url: Optional[str] = None, api_key: Optional[str] = None):
        self.url = (url or os.getenv("MISP_URL", "")).rstrip("/")
        self.api_key = api_key or os.getenv("MISP_API_KEY", "")

    @property
    def enabled(self) -> bool:
        return bool(self.url and self.api_key)

    def _validate(self) -> None:
        parsed = urlsplit(self.url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("MISP requires an HTTPS URL without embedded credentials")

    async def health(self) -> Dict[str, Any]:
        if not self.enabled:
            return {"status": "disabled"}
        try:
            self._validate()
            import httpx
            async with httpx.AsyncClient(timeout=5, verify=True, follow_redirects=False,
                                         headers={"Authorization": self.api_key, "Accept": "application/json"}) as client:
                response = await client.get(f"{self.url}/servers/getVersion")
            return {"status": "connected" if response.status_code < 400 else "degraded", "http_status": response.status_code}
        except Exception as exc:
            return {"status": "error", "error": str(exc)[:256]}

    async def import_stix(self, event_id: str) -> Dict[str, Any]:
        """Fetch a configured MISP event as STIX JSON; caller performs validation."""
        if not self.enabled:
            return {"status": "disabled"}
        self._validate()
        if not event_id.replace("-", "").isalnum() or len(event_id) > 128:
            raise ValueError("invalid MISP event id")
        import httpx
        async with httpx.AsyncClient(timeout=30, verify=True, follow_redirects=False,
                                     headers={"Authorization": self.api_key, "Accept": "application/json"}) as client:
            response = await client.get(f"{self.url}/events/restSearch", params={"eventid": event_id, "returnFormat": "stix2"})
            response.raise_for_status()
            return {"status": "success", "stix": response.json()}

    async def export_stix(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        if not self.enabled:
            return {"status": "disabled"}
        self._validate()
        import httpx
        async with httpx.AsyncClient(timeout=30, verify=True, follow_redirects=False,
                                     headers={"Authorization": self.api_key, "Accept": "application/json"}) as client:
            response = await client.post(f"{self.url}/events/add_stix", json=bundle)
            return {"status": "success" if response.status_code < 400 else "error", "http_status": response.status_code}
