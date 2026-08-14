"""Configuration for the independent Vrin_TI service.

Environment variables override the optional YAML file.  Secrets are read only
from the environment; values in YAML are intentionally ignored for secret
fields so credentials are not accidentally committed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List
import os

PACKAGE_ROOT = Path(__file__).resolve().parent


def _bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int, minimum: int = 0) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


def _yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        import yaml  # type: ignore
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (ImportError, OSError, ValueError):
        return {}


def _nested(data: Dict[str, Any], path: str, default: Any) -> Any:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _ti_path(value: Any) -> Path:
    """Resolve relative TI paths inside Vrin_TI, independent of process cwd."""
    candidate = Path(str(value)).expanduser()
    if not candidate.is_absolute():
        candidate = PACKAGE_ROOT / candidate
    return candidate.resolve()


@dataclass(frozen=True)
class TIConfig:
    enabled: bool
    host: str
    port: int
    database_path: Path
    log_dir: Path
    transport: str
    redis_url: str
    nats_url: str
    soc_url: str
    service_token: str
    allowed_hosts: List[str]
    request_max_bytes: int
    rate_limit_per_minute: int
    replay_window_seconds: int
    websocket_heartbeat_seconds: int
    external_enrichment: bool
    external_submission: bool
    retention_days: int
    feed_concurrency: int
    collect_on_start: bool
    feeds: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    suricata_eve_path: str = ""
    zeek_log_dir: str = ""
    yara_rules_path: str = ""
    sigma_rules_path: str = ""
    allowed_scan_paths: List[str] = field(default_factory=list)

    @property
    def api_base(self) -> str:
        return f"http://{self.host}:{self.port}"


def load_config(path: Path | None = None) -> TIConfig:
    config_path = _ti_path(path or os.getenv("VRINDHA_TI_CONFIG", PACKAGE_ROOT / "config" / "threat_intelligence.yaml"))
    raw = _yaml(config_path)
    db_default = PACKAGE_ROOT / "database" / "threat_intelligence.db"
    logs_default = PACKAGE_ROOT / "logs" / "threat_intelligence"
    feed_defaults: Dict[str, Dict[str, Any]] = {
        "cisa_kev": {"enabled": True, "interval": 3600, "timeout": 20, "retry_count": 3, "reliability": 0.98},
        "nvd": {"enabled": False, "interval": 3600, "timeout": 30, "retry_count": 3, "reliability": 0.95},
        "mitre_attack": {"enabled": True, "interval": 21600, "timeout": 30, "retry_count": 3, "reliability": 0.98},
        "stix_taxii": {"enabled": False, "interval": 1800, "timeout": 30, "retry_count": 3, "reliability": 0.8},
        "suricata": {"enabled": False, "interval": 300, "timeout": 10, "retry_count": 1, "reliability": 0.85},
        "zeek": {"enabled": False, "interval": 300, "timeout": 10, "retry_count": 1, "reliability": 0.85},
    }
    configured_feeds = _nested(raw, "feeds", {})
    if isinstance(configured_feeds, dict):
        for name, values in configured_feeds.items():
            if name in feed_defaults and isinstance(values, dict):
                feed_defaults[name].update(values)

    allowed_hosts = os.getenv("VRINDHA_TI_ALLOWED_HOSTS", str(_nested(raw, "api.allowed_hosts", "127.0.0.1,localhost")))
    scan_paths = os.getenv("VRINDHA_TI_ALLOWED_SCAN_PATHS", str(_nested(raw, "integrations.allowed_scan_paths", PACKAGE_ROOT / "quarantine")))
    yara_rules = os.getenv("YARA_RULES_PATH", str(_nested(raw, "integrations.yara.rules_path", "")))
    return TIConfig(
        enabled=_bool("VRINDHA_TI_ENABLED", bool(_nested(raw, "enabled", True))),
        host=os.getenv("VRINDHA_TI_HOST", str(_nested(raw, "api.host", "127.0.0.1"))),
        port=_int("VRINDHA_TI_PORT", int(_nested(raw, "api.port", 8010)), 1),
        database_path=_ti_path(os.getenv("VRINDHA_TI_DATABASE", str(_nested(raw, "database.path", db_default)))),
        log_dir=_ti_path(os.getenv("VRINDHA_TI_LOG_DIR", str(_nested(raw, "logging.directory", logs_default)))),
        transport=os.getenv("VRINDHA_INTELLIGENCE_BUS", str(_nested(raw, "transport.mode", "auto"))).lower(),
        redis_url=os.getenv("VRINDHA_REDIS_URL", ""),
        nats_url=os.getenv("VRINDHA_NATS_URL", ""),
        soc_url=os.getenv("VRINDHA_SOC_URL", str(_nested(raw, "soc.url", "http://127.0.0.1:8000"))).rstrip("/"),
        service_token=os.getenv("VRINDHA_TI_API_KEY", ""),
        allowed_hosts=[item.strip() for item in allowed_hosts.split(",") if item.strip()],
        request_max_bytes=_int("VRINDHA_TI_REQUEST_MAX_BYTES", int(_nested(raw, "api.request_max_bytes", 1_000_000)), 4096),
        rate_limit_per_minute=_int("VRINDHA_TI_RATE_LIMIT", int(_nested(raw, "api.rate_limit_per_minute", 120)), 1),
        replay_window_seconds=_int("VRINDHA_TI_REPLAY_WINDOW", int(_nested(raw, "security.replay_window_seconds", 300)), 30),
        websocket_heartbeat_seconds=_int("VRINDHA_TI_WS_HEARTBEAT", int(_nested(raw, "api.websocket_heartbeat_seconds", 30)), 5),
        external_enrichment=_bool("VRINDHA_TI_EXTERNAL_ENRICHMENT", bool(_nested(raw, "privacy.external_enrichment", False))),
        external_submission=_bool("VRINDHA_TI_EXTERNAL_SUBMISSION", bool(_nested(raw, "privacy.external_submission", False))),
        retention_days=_int("VRINDHA_TI_RETENTION_DAYS", int(_nested(raw, "database.retention_days", 365)), 30),
        feed_concurrency=_int("VRINDHA_TI_FEED_CONCURRENCY", int(_nested(raw, "feeds_concurrency", 3)), 1),
        collect_on_start=_bool("VRINDHA_TI_COLLECT_ON_START", bool(_nested(raw, "collect_on_start", False))),
        feeds=feed_defaults,
        suricata_eve_path=os.getenv("SURICATA_EVE_PATH", str(_nested(raw, "integrations.suricata.eve_path", ""))),
        zeek_log_dir=os.getenv("ZEEK_LOG_DIR", str(_nested(raw, "integrations.zeek.log_dir", ""))),
        yara_rules_path=str(_ti_path(yara_rules)) if yara_rules else "",
        sigma_rules_path=str(_ti_path(os.getenv("SIGMA_RULES_PATH", str(_nested(raw, "integrations.sigma.rules_path", PACKAGE_ROOT / "rules" / "sigma"))))),
        allowed_scan_paths=[str(_ti_path(item.strip())) for item in scan_paths.split(",") if item.strip()],
    )


config = load_config()
