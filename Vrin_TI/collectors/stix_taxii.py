"""Generic STIX/TAXII 2.1 collection adapter."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlencode, urlsplit
import os

from .base import CollectedItem, CollectionBatch, FeedCollector, FeedError, fetch_json


class STIXTAXIICollector(FeedCollector):
    name = "stix_taxii"

    def __init__(self, collection_url: str = "", **kwargs):
        super().__init__(**kwargs)
        self.collection_url = collection_url or os.getenv("VRINDHA_TAXII_COLLECTION_URL", "")

    async def collect(self, cursor: Optional[str] = None) -> CollectionBatch:
        if not self.collection_url:
            raise FeedError("TAXII collection URL is not configured")
        host = urlsplit(self.collection_url).hostname
        if not host:
            raise FeedError("TAXII collection URL is invalid")
        base = self.collection_url.rstrip("/") + "/objects/"
        headers = {"Accept": "application/taxii+json;version=2.1"}
        token = os.getenv("VRINDHA_TAXII_TOKEN", "")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        started = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        params = {"added_after": cursor} if cursor else {}
        objects = []
        more = False
        for _page in range(20):
            url = base + ("?" + urlencode(params) if params else "")
            data = await fetch_json(url, allowed_hosts=[host], timeout=self.timeout, headers=headers, max_bytes=50_000_000)
            if not isinstance(data, dict) or not isinstance(data.get("objects"), list):
                raise FeedError("TAXII response has no objects array")
            objects.extend(data["objects"])
            if len(objects) > 50_000:
                raise FeedError("TAXII collection exceeded the object limit")
            more = bool(data.get("more"))
            next_token = data.get("next")
            if not more:
                break
            if not isinstance(next_token, str) or not next_token:
                raise FeedError("TAXII response set more=true without a next token")
            params = {"next": next_token}
        if more:
            raise FeedError("TAXII pagination exceeded 20 pages")
        bundle = {"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000000", "objects": objects}
        return CollectionBatch([CollectedItem("stix", bundle)], cursor=started,
                               metadata={"more": False, "objects": len(objects)})
