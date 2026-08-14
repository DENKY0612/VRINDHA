"""Optional OpenCTI GraphQL connector."""
from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urlsplit
import os


class OpenCTIConnector:
    def __init__(self, url: Optional[str] = None, token: Optional[str] = None):
        self.url = (url or os.getenv("OPENCTI_URL", "")).rstrip("/")
        self.token = token or os.getenv("OPENCTI_TOKEN", "")

    @property
    def enabled(self) -> bool:
        return bool(self.url and self.token)

    def _validate(self) -> None:
        parsed = urlsplit(self.url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("OpenCTI requires an HTTPS URL without embedded credentials")

    async def graphql(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not self.enabled:
            return {"status": "disabled"}
        self._validate()
        if len(query) > 32_768:
            raise ValueError("GraphQL query is too large")
        import httpx
        async with httpx.AsyncClient(timeout=30, verify=True, follow_redirects=False,
                                     headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"}) as client:
            response = await client.post(f"{self.url}/graphql", json={"query": query, "variables": variables or {}})
            response.raise_for_status()
            return response.json()

    async def health(self) -> Dict[str, Any]:
        if not self.enabled:
            return {"status": "disabled"}
        try:
            result = await self.graphql("query Health { about { version } }")
            return {"status": "connected" if not result.get("errors") else "degraded",
                    "version": result.get("data", {}).get("about", {}).get("version")}
        except Exception as exc:
            return {"status": "error", "error": str(exc)[:256]}

    async def lookup_indicator(self, value: str) -> Dict[str, Any]:
        query = "query Indicator($search: String!) { indicators(search: $search, first: 20) { edges { node { id name pattern confidence } } } }"
        return await self.graphql(query, {"search": value[:4096]})
