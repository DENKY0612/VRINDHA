"""Filtered Suricata EVE JSON collector."""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional
import asyncio
import json

from .base import CollectedItem, CollectionBatch, FeedCollector, FeedError


class SuricataCollector(FeedCollector):
    name = "suricata"
    EVENT_TYPES = {"alert", "dns", "http", "tls", "flow", "anomaly", "fileinfo"}

    def __init__(self, eve_path: str, **kwargs):
        super().__init__(**kwargs)
        self.eve_path = Path(eve_path).expanduser() if eve_path else None

    def _read(self, offset: int) -> tuple[List[str], int]:
        if not self.eve_path or not self.eve_path.is_file():
            raise FeedError("Suricata eve.json was not found or is disabled")
        size = self.eve_path.stat().st_size
        if offset > size:  # rotation
            offset = 0
        with self.eve_path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            lines = handle.readlines(10_000_000)
            return lines[-20_000:], handle.tell()

    async def collect(self, cursor: Optional[str] = None) -> CollectionBatch:
        lines, offset = await asyncio.to_thread(self._read, int(cursor or 0))
        items: List[CollectedItem] = []
        for line in lines:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            event_type = event.get("event_type")
            if event_type not in self.EVENT_TYPES:
                continue
            context = {"sensor": "suricata", "event_type": event_type, "timestamp": event.get("timestamp"),
                       "alert": event.get("alert"), "flow_id": event.get("flow_id"), "proto": event.get("proto")}
            candidates = []
            if event_type == "dns" and event.get("dns", {}).get("rrname"):
                candidates.append(("domain", event["dns"]["rrname"]))
            if event_type == "http":
                http = event.get("http", {})
                if http.get("hostname"):
                    candidates.append(("domain", http["hostname"]))
                    if http.get("url"):
                        candidates.append(("url", f"http://{http['hostname']}{http['url']}"))
            if event_type == "tls" and event.get("tls", {}).get("sni"):
                candidates.append(("domain", event["tls"]["sni"]))
            if event_type == "fileinfo":
                info = event.get("fileinfo", {})
                for key, kind in (("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256")):
                    if info.get(key):
                        candidates.append((kind, info[key]))
            if event_type in {"alert", "flow", "anomaly"}:
                for field in ("src_ip", "dest_ip"):
                    if event.get(field):
                        candidates.append(("ip", event[field]))
            for kind, value in candidates:
                items.append(CollectedItem("event", {"indicator_type": kind, "value": value, "source": "suricata",
                    "timestamp": event.get("timestamp"), "confidence": 0.9 if event_type == "alert" else 0.55,
                    "severity": "high" if event.get("alert", {}).get("severity") == 1 else "medium", "context": context}))
        return CollectionBatch(items, cursor=str(offset), metadata={"lines": len(lines), "events": len(items)})
