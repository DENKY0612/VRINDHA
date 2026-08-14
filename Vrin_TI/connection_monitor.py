"""Health monitor for required and optional TI dependencies."""
from __future__ import annotations

from typing import Any, Dict
import asyncio
import os
import shutil

from .config import TIConfig
from .connectors import MISPConnector, OpenCTIConnector
from .core.intelligence_bus import TransportManager
from .database import ThreatDatabase
from .integrations import SigmaRuleLoader, YARAIntegration

STATES = {"connected", "degraded", "disconnected", "error", "disabled"}


class ConnectionMonitor:
    def __init__(self, config: TIConfig, database: ThreatDatabase, bus: TransportManager, feeds):
        self.config = config
        self.database = database
        self.bus = bus
        self.feeds = feeds
        self.misp = MISPConnector()
        self.opencti = OpenCTIConnector()
        self.yara = YARAIntegration(config.yara_rules_path, config.allowed_scan_paths)
        self.sigma = SigmaRuleLoader(config.sigma_rules_path)

    def _tool(self, name: str, configured: bool = True) -> Dict[str, Any]:
        if not configured:
            return {"status": "disabled"}
        path = shutil.which(name)
        if not path:
            return {"status": "disconnected", "availability": "missing"}
        if not os.access(path, os.X_OK):
            return {"status": "error", "availability": "permission_error", "path": path}
        return {"status": "connected", "availability": "installed", "path": path}

    def _db(self) -> Dict[str, Any]:
        try:
            with self.database.read_connection() as connection:
                connection.execute("SELECT 1").fetchone()
            return {"status": "connected", "path": str(self.database.path)}
        except Exception as exc:
            return {"status": "error", "error": str(exc)[:256]}

    async def snapshot(self, include_external: bool = False) -> Dict[str, Any]:
        bus = await self.bus.health()
        result: Dict[str, Any] = {
            "database": self._db(), "bus": bus,
            "feeds": {item["name"]: {"status": {"healthy": "connected", "running": "connected", "idle": "degraded",
                                                        "stale": "disconnected", "disabled": "disabled", "error": "error",
                                                        "degraded": "degraded"}.get(item["status"], "error")}
                      for item in self.feeds.status()},
            "suricata": self._tool("suricata", bool(self.config.suricata_eve_path)),
            "zeek": self._tool("zeek", bool(self.config.zeek_log_dir)),
            "yara": self.yara.status(), "sigma": self.sigma.status(),
            "optional_tools": {name: self._tool(name) for name in ("nmap", "rkhunter", "fail2ban", "ufw")},
            "misp": {"status": "disabled"}, "opencti": {"status": "disabled"},
            "external_apis": {"status": "disabled" if not self.config.external_enrichment else "degraded"},
        }
        if include_external:
            result["misp"], result["opencti"] = await asyncio.gather(self.misp.health(), self.opencti.health())
        return result

    async def doctor(self) -> Dict[str, Any]:
        snapshot = await self.snapshot(include_external=False)
        checks = {
            "TI service": ("REQUIRED", "AVAILABLE" if self.config.enabled else "UNAVAILABLE"),
            "gateway authentication": ("REQUIRED", "AVAILABLE" if self.config.service_token else "DEGRADED"),
            "database": ("REQUIRED", "AVAILABLE" if snapshot["database"]["status"] == "connected" else "UNAVAILABLE"),
            "transport": ("REQUIRED", "AVAILABLE" if snapshot["bus"]["status"] == "connected" else "DEGRADED"),
            "STIX 2.1": ("REQUIRED", "AVAILABLE"), "MITRE ATT&CK": ("REQUIRED", "AVAILABLE" if self.config.feeds["mitre_attack"]["enabled"] else "DEGRADED"),
            "CISA KEV": ("REQUIRED", "AVAILABLE" if self.config.feeds["cisa_kev"]["enabled"] else "DEGRADED"),
            "Suricata": ("OPTIONAL", snapshot["suricata"].get("availability", snapshot["suricata"]["status"]).upper()),
            "Zeek": ("OPTIONAL", snapshot["zeek"].get("availability", snapshot["zeek"]["status"]).upper()),
            "YARA": ("OPTIONAL", snapshot["yara"]["status"].upper()), "Sigma": ("OPTIONAL", snapshot["sigma"]["status"].upper()),
            "MISP": ("OPTIONAL", "AVAILABLE" if self.misp.enabled else "DISABLED"),
            "OpenCTI": ("OPTIONAL", "AVAILABLE" if self.opencti.enabled else "DISABLED"),
            "external APIs": ("OPTIONAL", "AVAILABLE" if self.config.external_enrichment else "DISABLED"),
            "systemd": ("OPTIONAL", "AVAILABLE" if shutil.which("systemctl") else "UNAVAILABLE"),
        }
        for name, state in snapshot["optional_tools"].items():
            checks[name] = ("OPTIONAL", state.get("availability", state["status"]).upper())
        required_ok = all(state == "AVAILABLE" for requirement, state in checks.values() if requirement == "REQUIRED")
        return {"status": "healthy" if required_ok else "degraded", "checks": {name: {"requirement": req, "state": state} for name, (req, state) in checks.items()},
                "detail": snapshot}
