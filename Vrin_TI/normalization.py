"""Strict IOC detection, validation, normalization and deterministic identity."""
from __future__ import annotations

from urllib.parse import quote, unquote, urlsplit, urlunsplit
from uuid import NAMESPACE_URL, uuid5
import ipaddress
import re

from .models import IndicatorType

DOMAIN_RE = re.compile(r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$", re.I)
EMAIL_RE = re.compile(r"^[^\s@]{1,64}@[^\s@]{1,253}$")
CVE_RE = re.compile(r"^CVE[-_ ]?(\d{4})[-_ ]?(\d{4,})$", re.I)
MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.I)
HEX_RE = re.compile(r"^[a-fA-F0-9]+$")

ALIASES = {
    "ipv4": IndicatorType.IPV4, "ip": IndicatorType.IPV4, "ip4": IndicatorType.IPV4,
    "ipv6": IndicatorType.IPV6, "ip6": IndicatorType.IPV6,
    "domain": IndicatorType.DOMAIN, "fqdn": IndicatorType.DOMAIN, "hostname": IndicatorType.DOMAIN,
    "url": IndicatorType.URL, "uri": IndicatorType.URL,
    "email": IndicatorType.EMAIL, "email-addr": IndicatorType.EMAIL,
    "md5": IndicatorType.MD5, "sha1": IndicatorType.SHA1, "sha-1": IndicatorType.SHA1,
    "sha256": IndicatorType.SHA256, "sha-256": IndicatorType.SHA256,
    "file": IndicatorType.FILE, "mutex": IndicatorType.MUTEX,
    "certificate": IndicatorType.CERTIFICATE, "x509": IndicatorType.CERTIFICATE,
    "cve": IndicatorType.CVE, "vulnerability": IndicatorType.CVE,
    "mitre technique": IndicatorType.MITRE_TECHNIQUE, "mitre-technique": IndicatorType.MITRE_TECHNIQUE,
    "mitre software": IndicatorType.MITRE_SOFTWARE, "mitre-software": IndicatorType.MITRE_SOFTWARE,
    "threat actor": IndicatorType.THREAT_ACTOR, "threat-actor": IndicatorType.THREAT_ACTOR,
    "campaign": IndicatorType.CAMPAIGN,
}


class InvalidIndicator(ValueError):
    pass


def canonical_type(value: str | IndicatorType) -> IndicatorType:
    if isinstance(value, IndicatorType):
        return value
    key = str(value).strip().lower()
    if key not in ALIASES:
        try:
            return IndicatorType(key)
        except ValueError as exc:
            raise InvalidIndicator(f"unsupported indicator type: {value}") from exc
    return ALIASES[key]


def detect_type(value: str) -> IndicatorType:
    candidate = value.strip()
    try:
        address = ipaddress.ip_address(candidate.strip("[]"))
        return IndicatorType.IPV4 if address.version == 4 else IndicatorType.IPV6
    except ValueError:
        pass
    if CVE_RE.fullmatch(candidate):
        return IndicatorType.CVE
    if MITRE_RE.fullmatch(candidate):
        return IndicatorType.MITRE_TECHNIQUE
    if len(candidate) in {32, 40, 64} and HEX_RE.fullmatch(candidate):
        return {32: IndicatorType.MD5, 40: IndicatorType.SHA1, 64: IndicatorType.SHA256}[len(candidate)]
    if "://" in candidate:
        return IndicatorType.URL
    if EMAIL_RE.fullmatch(candidate):
        return IndicatorType.EMAIL
    if DOMAIN_RE.fullmatch(candidate):
        return IndicatorType.DOMAIN
    raise InvalidIndicator("unable to detect indicator type; provide indicator_type")


def _domain(value: str) -> str:
    candidate = value.strip().rstrip(".").lower()
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidIndicator("invalid internationalized domain") from exc
    if not DOMAIN_RE.fullmatch(candidate) or ".." in candidate:
        raise InvalidIndicator("invalid domain")
    return candidate


def _url(value: str) -> str:
    if len(value) > 4096:
        raise InvalidIndicator("URL too long")
    try:
        parsed = urlsplit(value.strip())
    except ValueError as exc:
        raise InvalidIndicator("malformed URL") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise InvalidIndicator("URL scheme must be http or https")
    if parsed.username is not None or parsed.password is not None:
        raise InvalidIndicator("URL userinfo is not accepted")
    if not parsed.hostname:
        raise InvalidIndicator("URL host is required")
    host = parsed.hostname
    try:
        normalized_host = ipaddress.ip_address(host).compressed
        if ":" in normalized_host:
            normalized_host = f"[{normalized_host}]"
    except ValueError:
        normalized_host = _domain(host)
    try:
        port = parsed.port
    except ValueError as exc:
        raise InvalidIndicator("invalid URL port") from exc
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = normalized_host if not port or default_port else f"{normalized_host}:{port}"
    path = quote(unquote(parsed.path or "/"), safe="/%:@!$&'()*+,;=-._~")
    # Fragments are client-side and not sent in HTTP; omit them for IOC identity.
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def normalize_indicator(indicator_type: str | IndicatorType, value: str) -> str:
    kind = canonical_type(indicator_type)
    if not isinstance(value, str) or not value.strip():
        raise InvalidIndicator("indicator value is empty")
    if any(ord(char) < 32 for char in value):
        raise InvalidIndicator("indicator contains control characters")
    candidate = value.strip()
    if kind in {IndicatorType.IPV4, IndicatorType.IPV6}:
        try:
            address = ipaddress.ip_address(candidate.strip("[]"))
        except ValueError as exc:
            raise InvalidIndicator("invalid IP address") from exc
        expected = 4 if kind == IndicatorType.IPV4 else 6
        if address.version != expected:
            raise InvalidIndicator(f"expected IPv{expected}")
        return address.compressed
    if kind == IndicatorType.DOMAIN:
        return _domain(candidate)
    if kind == IndicatorType.URL:
        return _url(candidate)
    if kind == IndicatorType.EMAIL:
        if not EMAIL_RE.fullmatch(candidate):
            raise InvalidIndicator("invalid email address")
        local, domain = candidate.rsplit("@", 1)
        return f"{local}@{_domain(domain)}"
    if kind in {IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256}:
        lengths = {IndicatorType.MD5: 32, IndicatorType.SHA1: 40, IndicatorType.SHA256: 64}
        if len(candidate) != lengths[kind] or not HEX_RE.fullmatch(candidate):
            raise InvalidIndicator(f"invalid {kind.value} hash")
        return candidate.lower()
    if kind == IndicatorType.CVE:
        match = CVE_RE.fullmatch(candidate)
        if not match:
            raise InvalidIndicator("invalid CVE identifier")
        return f"CVE-{match.group(1)}-{match.group(2)}"
    if kind == IndicatorType.MITRE_TECHNIQUE:
        if not MITRE_RE.fullmatch(candidate):
            raise InvalidIndicator("invalid MITRE ATT&CK technique")
        return candidate.upper()
    if len(candidate) > 4096:
        raise InvalidIndicator("indicator is too long")
    # Names, mutexes, certificate fingerprints, and software retain case where
    # it may be meaningful, with only surrounding whitespace normalized.
    return candidate


def indicator_key(indicator_type: str | IndicatorType, value: str) -> str:
    kind = canonical_type(indicator_type)
    normalized = normalize_indicator(kind, value)
    return f"{kind.value}:{normalized}"


def deterministic_indicator_id(indicator_type: str | IndicatorType, value: str) -> str:
    # STIX 2.1 IDs require a UUID after the object-type prefix. UUIDv5 keeps
    # deterministic deduplication while remaining interoperable.
    return f"indicator--{uuid5(NAMESPACE_URL, 'vrindha-ti:' + indicator_key(indicator_type, value))}"
