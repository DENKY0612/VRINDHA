"""Local-first modular IOC enrichment with bounded TTL cache."""
from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit
import base64
import hashlib
import os
import time

from ..collectors.base import fetch_json
from ..database import ThreatDatabase
from ..normalization import canonical_type, normalize_indicator
from ..privacy import PrivacyGate


class TTLCache:
    def __init__(self, maxsize: int = 5000):
        self.maxsize = maxsize
        self.values: OrderedDict[str, Tuple[float, Dict[str, Any]]] = OrderedDict()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        item = self.values.get(key)
        if not item:
            return None
        expires, value = item
        if expires <= time.monotonic():
            self.values.pop(key, None)
            return None
        self.values.move_to_end(key)
        return value

    def put(self, key: str, value: Dict[str, Any], ttl: int) -> None:
        self.values[key] = (time.monotonic() + ttl, value)
        self.values.move_to_end(key)
        while len(self.values) > self.maxsize:
            self.values.popitem(last=False)


class EnrichmentManager:
    def __init__(self, database: ThreatDatabase, privacy: PrivacyGate):
        self.database = database
        self.privacy = privacy
        self.cache = TTLCache()

    def local_enrich(self, indicator_type: str, value: str) -> Dict[str, Any]:
        kind = canonical_type(indicator_type).value
        normalized = normalize_indicator(kind, value)
        result: Dict[str, Any] = {"type": kind, "normalized_value": normalized, "source": "local", "timestamp": datetime.now(timezone.utc).isoformat()}
        if kind in {"ipv4", "ipv6"}:
            address = ip_address(normalized)
            result.update({"version": address.version, "is_private": address.is_private, "is_global": address.is_global,
                           "is_loopback": address.is_loopback, "is_link_local": address.is_link_local,
                           "external_lookup_eligible": address.is_global})
        elif kind == "domain":
            labels = normalized.split(".")
            result.update({"labels": len(labels), "registrable_hint": ".".join(labels[-2:]), "punycode": normalized.startswith("xn--") or ".xn--" in normalized})
        elif kind == "url":
            parsed = urlsplit(normalized)
            result.update({"scheme": parsed.scheme, "hostname": parsed.hostname, "port": parsed.port,
                           "path_depth": len([part for part in parsed.path.split("/") if part]), "has_query": bool(parsed.query)})
        elif kind in {"md5", "sha1", "sha256"}:
            result.update({"algorithm": kind, "bits": {"md5": 128, "sha1": 160, "sha256": 256}[kind]})
        elif kind == "cve":
            record = next((item for item in self.database.vulnerabilities(limit=1000) if item["cve_id"] == normalized), None)
            result.update({"vulnerability": record, "kev": bool(record and record.get("kev")), "cvss": record.get("cvss") if record else None})
        elif kind == "certificate":
            result.update({"fingerprint": normalized, "note": "certificate metadata requires a locally observed x509 record"})
        return result

    async def _virus_total(self, kind: str, value: str) -> Dict[str, Any]:
        key = os.getenv("VIRUSTOTAL_API_KEY", "")
        if not key:
            return {"provider": "virustotal", "status": "disabled", "reason": "API key not configured"}
        endpoint_type = {"ipv4": "ip_addresses", "ipv6": "ip_addresses", "domain": "domains", "md5": "files", "sha1": "files", "sha256": "files"}.get(kind)
        if kind == "url":
            endpoint_type = "urls"
            value = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        if not endpoint_type:
            return {"provider": "virustotal", "status": "unsupported"}
        data = await fetch_json(f"https://www.virustotal.com/api/v3/{endpoint_type}/{value}", allowed_hosts=["www.virustotal.com"],
                                timeout=15, headers={"x-apikey": key}, max_bytes=2_000_000)
        attributes = data.get("data", {}).get("attributes", {}) if isinstance(data, dict) else {}
        return {"provider": "virustotal", "status": "ok", "reputation": attributes.get("reputation"),
                "last_analysis_stats": attributes.get("last_analysis_stats"), "last_analysis_date": attributes.get("last_analysis_date")}

    async def _abuseipdb(self, kind: str, value: str) -> Dict[str, Any]:
        key = os.getenv("ABUSEIPDB_API_KEY", "")
        if not key or kind not in {"ipv4", "ipv6"}:
            return {"provider": "abuseipdb", "status": "disabled" if not key else "unsupported"}
        data = await fetch_json(f"https://api.abuseipdb.com/api/v2/check?ipAddress={value}&maxAgeInDays=90",
                                allowed_hosts=["api.abuseipdb.com"], timeout=15,
                                headers={"Key": key, "Accept": "application/json"}, max_bytes=1_000_000)
        record = data.get("data", {}) if isinstance(data, dict) else {}
        return {"provider": "abuseipdb", "status": "ok", "abuse_confidence_score": record.get("abuseConfidenceScore"),
                "total_reports": record.get("totalReports"), "last_reported_at": record.get("lastReportedAt")}

    async def enrich(self, indicator_type: str, value: str, allow_external: bool = False) -> Dict[str, Any]:
        kind = canonical_type(indicator_type).value
        normalized = normalize_indicator(kind, value)
        cache_key = hashlib.sha256(f"{kind}:{normalized}:{allow_external}".encode()).hexdigest()
        cached = self.cache.get(cache_key)
        if cached:
            return {**cached, "cached": True}
        local = self.local_enrich(kind, normalized)
        result: Dict[str, Any] = {"local": local, "external": [], "cached": False}
        if allow_external:
            for provider, lookup in (("virustotal", self._virus_total), ("abuseipdb", self._abuseipdb)):
                decision = self.privacy.allow(kind, normalized, provider, explicit_request=True)
                if not decision.allowed:
                    result["external"].append({"provider": provider, "status": "denied", "reason": decision.reason, "classification": decision.classification})
                    continue
                try:
                    result["external"].append(await lookup(kind, normalized))
                except Exception as exc:
                    result["external"].append({"provider": provider, "status": "error", "error": str(exc)[:256]})
        self.cache.put(cache_key, result, 900 if allow_external else 3600)
        return result
