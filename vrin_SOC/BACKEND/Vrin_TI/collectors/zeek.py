"""Filtered Zeek JSON log collector."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional
import asyncio
import json

from .base import CollectedItem, CollectionBatch, FeedCollector, FeedError


class ZeekCollector(FeedCollector):
    name = "zeek"
    FILES = ("conn.log", "dns.log", "http.log", "ssl.log", "x509.log", "ssh.log", "files.log")

    def __init__(self, log_dir: str, **kwargs):
        super().__init__(**kwargs)
        self.log_dir = Path(log_dir).expanduser() if log_dir else None

    def _read(self, cursors: Dict[str, int]) -> tuple[List[tuple[str, str]], Dict[str, int]]:
        if not self.log_dir or not self.log_dir.is_dir():
            raise FeedError("Zeek log directory was not found or is disabled")
        result: List[tuple[str, str]] = []
        updated = dict(cursors)
        for name in self.FILES:
            path = self.log_dir / name
            if not path.is_file():
                continue
            offset = int(cursors.get(name, 0))
            if offset > path.stat().st_size:
                offset = 0
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                result.extend((name, line) for line in handle.readlines(5_000_000)[-10_000:])
                updated[name] = handle.tell()
        return result, updated

    async def collect(self, cursor: Optional[str] = None) -> CollectionBatch:
        try:
            cursors = json.loads(cursor) if cursor else {}
        except json.JSONDecodeError:
            cursors = {}
        lines, updated = await asyncio.to_thread(self._read, cursors)
        items: List[CollectedItem] = []
        for filename, line in lines:
            if line.startswith("#"):
                continue  # TSV Zeek requires field metadata; only JSON mode is supported.
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            candidates = []
            if filename == "dns.log" and event.get("query"):
                candidates.append(("domain", event["query"]))
            elif filename == "http.log" and event.get("host"):
                candidates.append(("domain", event["host"]))
                if event.get("uri"):
                    candidates.append(("url", f"http://{event['host']}{event['uri']}"))
            elif filename == "ssl.log" and event.get("server_name"):
                candidates.append(("domain", event["server_name"]))
            elif filename == "x509.log":
                for field in ("certificate.sha256", "fingerprint"):
                    if event.get(field):
                        candidates.append(("sha256", event[field]))
            elif filename == "files.log":
                for field, kind in (("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256")):
                    if event.get(field):
                        candidates.append((kind, event[field]))
            elif filename == "conn.log" and event.get("id.resp_h"):
                candidates.append(("ip", event["id.resp_h"]))
            context = {"sensor": "zeek", "log": filename, "uid": event.get("uid"), "timestamp": event.get("ts"),
                       "service": event.get("service"), "conn_state": event.get("conn_state")}
            for kind, value in candidates:
                items.append(CollectedItem("event", {"indicator_type": kind, "value": value, "source": "zeek",
                    "timestamp": event.get("ts"), "confidence": 0.55, "severity": "informational", "context": context}))
        return CollectionBatch(items, cursor=json.dumps(updated, separators=(",", ":")), metadata={"lines": len(lines), "events": len(items)})
