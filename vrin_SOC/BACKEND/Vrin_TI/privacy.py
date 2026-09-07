"""Privacy gate for opt-in external enrichment/submission."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from ipaddress import ip_address
from urllib.parse import urlsplit

from .normalization import canonical_type, normalize_indicator


class Classification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    SECRET = "secret"


@dataclass(frozen=True)
class SubmissionDecision:
    allowed: bool
    classification: str
    reason: str
    provider: str


class PrivacyGate:
    def __init__(self, external_enabled: bool, submission_enabled: bool):
        self.external_enabled = external_enabled
        self.submission_enabled = submission_enabled

    def classify(self, indicator_type: str, value: str) -> Classification:
        kind = canonical_type(indicator_type).value
        normalized = normalize_indicator(kind, value)
        if kind in {"ipv4", "ipv6"}:
            address = ip_address(normalized)
            if address.is_private or address.is_loopback or address.is_link_local:
                return Classification.INTERNAL
        if kind == "domain" and (normalized.endswith(".local") or ".internal." in normalized or normalized.endswith(".internal")):
            return Classification.INTERNAL
        if kind == "url":
            parsed = urlsplit(normalized)
            if parsed.query or any(token in parsed.path.lower() for token in ("user", "private", "secret", "token")):
                return Classification.SENSITIVE
        if kind in {"email", "file"}:
            return Classification.SENSITIVE
        return Classification.PUBLIC

    def allow(self, indicator_type: str, value: str, provider: str, explicit_request: bool = False) -> SubmissionDecision:
        classification = self.classify(indicator_type, value)
        if not self.external_enabled:
            return SubmissionDecision(False, classification.value, "external enrichment is disabled", provider)
        if not self.submission_enabled or not explicit_request:
            return SubmissionDecision(False, classification.value, "external submission requires global opt-in and an explicit request", provider)
        if classification != Classification.PUBLIC:
            return SubmissionDecision(False, classification.value, "internal or sensitive artifact cannot be submitted", provider)
        return SubmissionDecision(True, classification.value, "public artifact and explicit opt-in", provider)
