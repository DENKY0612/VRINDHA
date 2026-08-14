"""Validated domain and SOC↔TI contract models."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID, uuid4
import json

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IndicatorType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    FILE = "file"
    MUTEX = "mutex"
    CERTIFICATE = "certificate"
    CVE = "cve"
    MITRE_TECHNIQUE = "mitre-technique"
    MITRE_SOFTWARE = "mitre-software"
    THREAT_ACTOR = "threat-actor"
    CAMPAIGN = "campaign"


class Lifecycle(str, Enum):
    NEW = "new"
    ACTIVE = "active"
    STALE = "stale"
    EXPIRED = "expired"
    REVOKED = "revoked"
    FALSE_POSITIVE = "false_positive"
    CONFIRMED = "confirmed"


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventType(str, Enum):
    IOC_OBSERVATION = "ioc_observation"
    IOC_MATCH = "ioc_match"
    IOC_UPDATE = "ioc_update"
    THREAT_UPDATE = "threat_update"
    THREAT_EXPIRED = "threat_expired"
    THREAT_ENRICHMENT = "threat_enrichment"
    CVE_UPDATE = "cve_update"
    MALWARE_UPDATE = "malware_update"
    ACTOR_UPDATE = "actor_update"
    CAMPAIGN_UPDATE = "campaign_update"
    ATTACK_MAPPING = "attack_mapping"
    SIGHTING_CREATED = "sighting_created"
    CORRELATION_DETECTED = "correlation_detected"
    RISK_UPDATE = "risk_update"
    INCIDENT_CREATED = "incident_created"
    FEED_HEALTH = "feed_health"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=True)


class SourceReference(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    url: Optional[str] = Field(default=None, max_length=2048)
    reliability: float = Field(default=0.5, ge=0, le=1)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)


class ConfidencePoint(StrictModel):
    timestamp: datetime = Field(default_factory=utcnow)
    confidence: float = Field(ge=0, le=1)
    reason: str = Field(default="ingestion", max_length=512)


class IndicatorReference(StrictModel):
    type: IndicatorType
    value: str = Field(min_length=1, max_length=4096)

    @field_validator("value")
    @classmethod
    def reject_control_characters(cls, value: str) -> str:
        if any(ord(char) < 32 for char in value):
            raise ValueError("indicator contains control characters")
        return value


class AssetReference(StrictModel):
    id: str = Field(min_length=1, max_length=256)
    ip: Optional[str] = Field(default=None, max_length=64)
    hostname: Optional[str] = Field(default=None, max_length=253)
    criticality: float = Field(default=0.5, ge=0, le=1)
    exposed: bool = False


class Sighting(StrictModel):
    sighting_id: UUID = Field(default_factory=uuid4)
    indicator_id: Optional[str] = Field(default=None, max_length=128)
    asset: Optional[AssetReference] = None
    timestamp: datetime = Field(default_factory=utcnow)
    source: str = Field(min_length=1, max_length=128)
    confidence: float = Field(default=0.5, ge=0, le=1)
    context: Dict[str, Any] = Field(default_factory=dict)
    correlation_id: UUID = Field(default_factory=uuid4)

    @field_validator("context")
    @classmethod
    def limit_context(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        if len(json.dumps(value, default=str)) > 32_768:
            raise ValueError("sighting context is too large")
        return value


class ThreatIndicator(StrictModel):
    indicator_id: Optional[str] = Field(default=None, max_length=128)
    indicator_type: IndicatorType
    indicator_value: str = Field(min_length=1, max_length=4096)
    normalized_value: Optional[str] = Field(default=None, max_length=4096)
    source: str = Field(min_length=1, max_length=128)
    source_url: Optional[str] = Field(default=None, max_length=2048)
    source_reliability: float = Field(default=0.5, ge=0, le=1)
    confidence: float = Field(default=0.5, ge=0, le=1)
    threat_score: float = Field(default=0, ge=0, le=100)
    severity: Severity = Severity.INFORMATIONAL
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    expires_at: Optional[datetime] = None
    ttl: Optional[int] = Field(default=None, ge=60, le=31_536_000)
    tags: List[str] = Field(default_factory=list, max_length=100)
    malware_family: List[str] = Field(default_factory=list, max_length=100)
    threat_actor: List[str] = Field(default_factory=list, max_length=100)
    campaign: List[str] = Field(default_factory=list, max_length=100)
    mitre_attack_ids: List[str] = Field(default_factory=list, max_length=100)
    related_cves: List[str] = Field(default_factory=list, max_length=100)
    related_indicators: List[str] = Field(default_factory=list, max_length=100)
    description: str = Field(default="", max_length=16_384)
    false_positive_probability: float = Field(default=0, ge=0, le=1)
    verification_status: Lifecycle = Lifecycle.NEW
    active: bool = True
    sightings: List[Sighting] = Field(default_factory=list, max_length=1000)
    sources: List[SourceReference] = Field(default_factory=list, max_length=100)
    confidence_history: List[ConfidencePoint] = Field(default_factory=list, max_length=1000)
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    revoked: bool = False

    @model_validator(mode="after")
    def validate_times_and_raw(self) -> "ThreatIndicator":
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen cannot precede first_seen")
        if len(json.dumps(self.raw_data, default=str)) > 262_144:
            raise ValueError("raw_data exceeds 256 KiB")
        self.tags = sorted(set(self.tags))
        self.mitre_attack_ids = sorted(set(item.upper() for item in self.mitre_attack_ids))
        self.related_cves = sorted(set(item.upper() for item in self.related_cves))
        return self


class IntelligenceEvent(StrictModel):
    event_type: EventType
    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=utcnow)
    source: str = Field(min_length=1, max_length=64)
    indicator: Optional[IndicatorReference] = None
    asset: Optional[AssetReference] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    severity: Severity = Severity.INFORMATIONAL
    confidence: float = Field(default=0.5, ge=0, le=1)
    correlation_id: UUID = Field(default_factory=uuid4)
    schema_version: Literal["1.0"] = "1.0"

    @model_validator(mode="after")
    def require_indicator_for_ioc_events(self) -> "IntelligenceEvent":
        if self.event_type in {EventType.IOC_OBSERVATION, EventType.IOC_MATCH, EventType.SIGHTING_CREATED} and not self.indicator:
            raise ValueError("indicator is required for IOC events")
        if len(json.dumps(self.context, default=str)) > 65_536:
            raise ValueError("event context exceeds 64 KiB")
        return self


class LookupRequest(StrictModel):
    indicator: str = Field(min_length=1, max_length=4096)
    indicator_type: Optional[IndicatorType] = None


class EnrichmentRequest(LookupRequest):
    allow_external: bool = False


class SightingRequest(StrictModel):
    indicator: IndicatorReference
    asset: Optional[AssetReference] = None
    timestamp: datetime = Field(default_factory=utcnow)
    source: str = Field(default="soc", min_length=1, max_length=128)
    confidence: float = Field(default=0.7, ge=0, le=1)
    context: Dict[str, Any] = Field(default_factory=dict)
    correlation_id: UUID = Field(default_factory=uuid4)


class FeedStatus(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    enabled: bool
    interval: int = Field(ge=60)
    timeout: int = Field(ge=1, le=300)
    retry_count: int = Field(ge=0, le=10)
    reliability: float = Field(ge=0, le=1)
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    status: Literal["idle", "running", "healthy", "stale", "degraded", "error", "disabled"]
    last_error: str = Field(default="", max_length=1024)
    items_ingested: int = Field(default=0, ge=0)


class AIConclusion(StrictModel):
    conclusion: str = Field(min_length=1, max_length=16_384)
    confidence: float = Field(ge=0, le=1)
    evidence: List[str] = Field(min_length=1, max_length=1000)
    sources: List[str] = Field(min_length=1, max_length=100)
    timestamp: datetime = Field(default_factory=utcnow)
    reasoning_summary: str = Field(min_length=1, max_length=4096)
