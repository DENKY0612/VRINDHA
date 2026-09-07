"""MITRE ATT&CK Enterprise STIX 2.1 collector."""
from __future__ import annotations

from typing import Optional

from .base import CollectedItem, CollectionBatch, FeedCollector, FeedError, fetch_json


class MITREAttackCollector(FeedCollector):
    name = "mitre_attack"
    URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"

    async def collect(self, cursor: Optional[str] = None) -> CollectionBatch:
        data = await fetch_json(self.URL, allowed_hosts=["raw.githubusercontent.com"], timeout=self.timeout, max_bytes=80_000_000)
        if not isinstance(data, dict) or data.get("type") != "bundle":
            raise FeedError("MITRE ATT&CK payload is not a STIX bundle")
        return CollectionBatch([CollectedItem("stix", data)], metadata={"objects": len(data.get("objects", []))})
