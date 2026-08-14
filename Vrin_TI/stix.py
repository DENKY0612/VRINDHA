"""STIX 2.1 ↔ internal TI model adapter.

No STIX pattern or external value is evaluated as code.  Only a deliberately
small equality-pattern grammar is accepted for IOC extraction; all other valid
STIX objects remain queryable entities without being interpreted.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID
import json
import re

from .database import ThreatDatabase
from .models import ThreatIndicator
from .normalization import InvalidIndicator

SUPPORTED_TYPES = {
    "indicator", "malware", "threat-actor", "campaign", "attack-pattern",
    "vulnerability", "tool", "infrastructure", "relationship", "observed-data",
    "sighting", "report", "location", "identity", "course-of-action", "grouping",
    "note", "opinion", "marking-definition", "language-content",
    # ATT&CK publishes these versioned STIX custom object types alongside the
    # standard attack-pattern/software/group/campaign objects.
    "x-mitre-tactic", "x-mitre-matrix", "x-mitre-data-source",
    "x-mitre-data-component", "x-mitre-collection", "x-mitre-analytic",
    "x-mitre-detection-strategy", "x-mitre-asset", "x-mitre-log-source",
}
PATTERN_RE = re.compile(
    r"^\[(ipv4-addr|ipv6-addr|domain-name|url|email-addr):value\s*=\s*'((?:[^'\\]|\\.)+)'\]$",
    re.I,
)
HASH_PATTERN_RE = re.compile(
    r"^\[file:hashes\.(?:'|\")?(MD5|SHA-1|SHA-256)(?:'|\")?\s*=\s*'([A-Fa-f0-9]+)'\]$",
    re.I,
)
TYPE_MAP = {"ipv4-addr": "ipv4", "ipv6-addr": "ipv6", "domain-name": "domain", "url": "url", "email-addr": "email"}
HASH_MAP = {"MD5": "md5", "SHA-1": "sha1", "SHA-256": "sha256"}


class STIXValidationError(ValueError):
    pass


def _dt(value: Any) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise STIXValidationError(f"invalid STIX timestamp: {value}") from exc


def validate_stix_object(obj: Dict[str, Any]) -> None:
    if not isinstance(obj, dict):
        raise STIXValidationError("STIX object must be an object")
    object_type = obj.get("type")
    if object_type not in SUPPORTED_TYPES:
        raise STIXValidationError(f"unsupported STIX type: {object_type}")
    identifier = obj.get("id")
    if not isinstance(identifier, str) or not identifier.startswith(f"{object_type}--") or len(identifier) > 128:
        raise STIXValidationError("malformed STIX identifier")
    try:
        UUID(identifier.split("--", 1)[1])
    except (ValueError, IndexError) as exc:
        raise STIXValidationError("STIX identifier suffix must be a UUID") from exc
    spec = obj.get("spec_version", "2.1")
    if spec != "2.1":
        raise STIXValidationError("only STIX 2.1 is accepted")


def parse_bundle(payload: str | bytes | Dict[str, Any], max_bytes: int = 80_000_000, max_objects: int = 50_000) -> List[Dict[str, Any]]:
    if isinstance(payload, bytes):
        if len(payload) > max_bytes:
            raise STIXValidationError("STIX payload exceeds size limit")
        payload = payload.decode("utf-8")
    if isinstance(payload, str):
        if len(payload.encode("utf-8")) > max_bytes:
            raise STIXValidationError("STIX payload exceeds size limit")
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise STIXValidationError("malformed STIX JSON") from exc
    if not isinstance(payload, dict):
        raise STIXValidationError("STIX payload must be an object")
    if payload.get("type") == "bundle":
        objects = payload.get("objects")
        if not isinstance(objects, list):
            raise STIXValidationError("bundle.objects must be an array")
    else:
        objects = [payload]
    if len(objects) > max_objects:
        raise STIXValidationError("STIX object count exceeds limit")
    accepted: List[Dict[str, Any]] = []
    for obj in objects:
        validate_stix_object(obj)
        if len(json.dumps(obj, default=str).encode("utf-8")) > 262_144:
            raise STIXValidationError(f"STIX object {obj.get('id')} exceeds 256 KiB")
        accepted.append(obj)
    return accepted


def pattern_to_indicator(pattern: str) -> Optional[Tuple[str, str]]:
    match = PATTERN_RE.fullmatch(pattern.strip())
    if match:
        # STIX string escapes are data, never passed to an evaluator.
        value = match.group(2).replace("\\'", "'").replace("\\\\", "\\")
        return TYPE_MAP[match.group(1).lower()], value
    match = HASH_PATTERN_RE.fullmatch(pattern.strip())
    if match:
        return HASH_MAP[match.group(1).upper()], match.group(2)
    return None


def internal_to_stix(indicator: Dict[str, Any]) -> Dict[str, Any]:
    kind = indicator["indicator_type"]
    value = str(indicator["normalized_value"]).replace("\\", "\\\\").replace("'", "\\'")
    object_types = {"ipv4": "ipv4-addr", "ipv6": "ipv6-addr", "domain": "domain-name", "url": "url", "email": "email-addr"}
    if kind in object_types:
        pattern = f"[{object_types[kind]}:value = '{value}']"
    elif kind in {"md5", "sha1", "sha256"}:
        hash_name = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}[kind]
        pattern = f"[file:hashes.'{hash_name}' = '{value}']"
    else:
        raise STIXValidationError(f"internal type {kind} has no STIX indicator pattern mapping")
    return {
        "type": "indicator", "spec_version": "2.1", "id": indicator["indicator_id"],
        "created": indicator["created_at"], "modified": indicator["updated_at"],
        "name": f"{kind}: {value[:120]}", "description": indicator.get("description", ""),
        "indicator_types": ["malicious-activity"], "pattern_type": "stix", "pattern": pattern,
        "valid_from": indicator["first_seen"], "valid_until": indicator.get("expires_at"),
        "confidence": round(float(indicator.get("confidence", 0.5)) * 100),
        "revoked": bool(indicator.get("revoked", False)), "labels": indicator.get("tags", []),
        "external_references": [{"source_name": item["name"], **({"url": item["url"]} if item.get("url") else {})}
                                for item in indicator.get("sources", [])],
    }


class STIXAdapter:
    def __init__(self, database: ThreatDatabase):
        self.database = database

    def ingest(self, payload: str | bytes | Dict[str, Any], source: str, reliability: float = 0.8) -> Dict[str, Any]:
        objects = parse_bundle(payload)
        stats = {"objects": len(objects), "indicators": 0, "entities": 0, "relationships": 0, "vulnerabilities": 0, "skipped_patterns": 0, "errors": []}
        # Entities first so relationship endpoints are available for graph queries.
        for obj in objects:
            object_type = obj["type"]
            try:
                if object_type == "indicator":
                    extracted = pattern_to_indicator(str(obj.get("pattern", "")))
                    if not extracted:
                        stats["skipped_patterns"] += 1
                        self.database.upsert_entity(obj["id"], object_type, obj.get("name", obj["id"]), obj.get("description", ""), obj.get("external_references", []), obj)
                        continue
                    kind, value = extracted
                    references = obj.get("external_references") or []
                    source_url = next((item.get("url") for item in references if isinstance(item, dict) and item.get("url")), None)
                    labels = [str(item)[:128] for item in (obj.get("labels") or [])]
                    indicator = ThreatIndicator(
                        indicator_id=obj["id"], indicator_type=kind, indicator_value=value, source=source,
                        source_url=source_url, source_reliability=reliability,
                        confidence=max(0, min(1, float(obj.get("confidence", 50)) / 100)),
                        first_seen=_dt(obj.get("valid_from") or obj.get("created")),
                        last_seen=_dt(obj.get("modified") or obj.get("created")),
                        expires_at=_dt(obj["valid_until"]) if obj.get("valid_until") else None,
                        tags=labels, description=str(obj.get("description", ""))[:16_384],
                        verification_status="revoked" if obj.get("revoked") else "active",
                        active=not bool(obj.get("revoked")), revoked=bool(obj.get("revoked")), raw_data=obj,
                    )
                    self.database.upsert_indicator(indicator)
                    stats["indicators"] += 1
                elif object_type == "vulnerability":
                    name = str(obj.get("name", ""))
                    external_ids = [ref.get("external_id") for ref in obj.get("external_references", []) if isinstance(ref, dict)]
                    cve = next((item for item in [name, *external_ids] if isinstance(item, str) and item.upper().startswith("CVE-")), None)
                    self.database.upsert_entity(obj["id"], object_type, name or obj["id"], obj.get("description", ""), obj.get("external_references", []), obj)
                    if cve:
                        self.database.upsert_vulnerability(cve.upper(), {"references": obj.get("external_references", []), "published": obj.get("created"), "modified": obj.get("modified"), "stix_id": obj["id"]})
                    stats["vulnerabilities"] += 1
                elif object_type == "relationship":
                    self.database.add_relationship(obj["id"], str(obj.get("source_ref", "")), str(obj.get("relationship_type", "related-to")),
                                                   str(obj.get("target_ref", "")), float(obj.get("confidence", 50)) / 100, [source, obj.get("description", "")])
                    stats["relationships"] += 1
                else:
                    self.database.upsert_entity(obj["id"], object_type, str(obj.get("name", obj["id"])), str(obj.get("description", "")), obj.get("external_references", []), obj)
                    stats["entities"] += 1
            except (ValueError, InvalidIndicator, KeyError) as exc:
                stats["errors"].append({"id": obj.get("id"), "error": str(exc)[:512]})
        return stats
