"""Infrastructure AI — observes authorized infrastructure and emits telemetry.

Responsibilities (observation and reporting only, no offensive capability):

* CPU / RAM / disk usage (real ``/proc`` data on Linux, clearly labeled)
* Local listening sockets (reuses the existing ``core.local_sensors`` module)
* Process inventory summary
* Authentication events parsed from the SIEM log database

Every emitted event carries a ``provenance.mode`` of REAL when measured from
the live host, and synthetic events are always labeled SIMULATED with a
``SIMULATION`` marker — never presented as real telemetry.
"""
from __future__ import annotations

import os
import platform
import re
import socket
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .event_bus import EventBus
from .observability import BaseAgent
from .schemas import EntityRef, EventMode, Provenance, SecurityEvent, utc_now_iso

_HOSTNAME = socket.gethostname()


class InfrastructureAI(BaseAgent):
    name = "InfrastructureAI"
    kind = "sensor"
    capabilities = ["telemetry", "cpu", "memory", "disk", "processes", "listeners", "auth_events"]

    # ------------------------------------------------------------------
    # Real collectors (observation only)
    # ------------------------------------------------------------------
    def _read_cpu(self) -> Optional[Dict[str, float]]:
        try:
            with open("/proc/stat", encoding="utf-8") as f:
                parts = f.readline().split()[1:]
            values = list(map(int, parts))
            idle = values[3] + (values[4] if len(values) > 4 else 0)
            total = sum(values)
            # Second sample a short moment later for a usage delta.
            import time

            time.sleep(0.05)
            with open("/proc/stat", encoding="utf-8") as f:
                parts2 = f.readline().split()[1:]
            v2 = list(map(int, parts2))
            idle2 = v2[3] + (v2[4] if len(v2) > 4 else 0)
            total2 = sum(v2)
            d_total, d_idle = total2 - total, idle2 - idle
            usage = 100.0 * (1 - (d_idle / d_total)) if d_total > 0 else 0.0
            return {"cpu_usage_percent": round(max(0.0, min(100.0, usage)), 2), "cores": os.cpu_count()}
        except (OSError, ValueError, IndexError):
            return None

    def _read_memory(self) -> Optional[Dict[str, float]]:
        try:
            info: Dict[str, int] = {}
            with open("/proc/meminfo", encoding="utf-8") as f:
                for line in f:
                    key, _, rest = line.partition(":")
                    info[key.strip()] = int(rest.strip().split()[0])
            total = info.get("MemTotal", 0)
            available = info.get("MemAvailable", info.get("MemFree", 0))
            if not total:
                return None
            return {
                "memory_total_mb": round(total / 1024, 1),
                "memory_available_mb": round(available / 1024, 1),
                "memory_usage_percent": round(100.0 * (1 - available / total), 2),
            }
        except (OSError, ValueError, IndexError):
            return None

    def _read_disk(self) -> Optional[Dict[str, Any]]:
        try:
            usage = os.statvfs("/")
            total = usage.f_blocks * usage.f_frsize
            free = usage.f_bavail * usage.f_frsize
            if not total:
                return None
            return {
                "disk_total_gb": round(total / 1e9, 1),
                "disk_free_gb": round(free / 1e9, 1),
                "disk_usage_percent": round(100.0 * (1 - free / total), 2),
            }
        except (OSError, AttributeError):
            return None

    def _read_processes(self) -> Optional[Dict[str, int]]:
        try:
            count = 0
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    count += 1
            return {"process_count": count}
        except OSError:
            return None

    def _read_listeners(self) -> Optional[List[Dict[str, Any]]]:
        try:
            from vrin_SOC.core.local_sensors import local_listeners

            result = local_listeners()
            return result.get("listeners", [])[:100]
        except Exception:  # noqa: BLE001
            return None

    # ------------------------------------------------------------------
    # Telemetry events
    # ------------------------------------------------------------------
    def collect_telemetry(self, host: Optional[str] = None) -> SecurityEvent:
        """Collect REAL system telemetry from the local host."""
        data: Dict[str, Any] = {
            "host": host or _HOSTNAME,
            "platform": platform.platform(),
            "pid": os.getpid(),
        }
        for key, collector in (
            ("cpu", self._read_cpu),
            ("memory", self._read_memory),
            ("disk", self._read_disk),
            ("processes", self._read_processes),
        ):
            measured = collector()
            if measured is not None:
                data[key] = measured
            else:
                data[key] = {"status": "unavailable"}

        listeners = self._read_listeners()
        if listeners is not None:
            data["listeners"] = listeners
        else:
            data["listeners"] = {"status": "unavailable"}

        mode = EventMode.REAL if any(
            isinstance(data.get(key), dict) and data.get(key, {}).get("status") != "unavailable"
            for key in ("cpu", "memory", "disk", "processes")
        ) else EventMode.FALLBACK

        return SecurityEvent(
            event_type="telemetry",
            source_agent=self.name,
            source_system=data["host"],
            entity=EntityRef(host=data["host"]),
            data=data,
            severity="low",
            provenance=Provenance(
                source="infrastructure",
                collection_method="proc_sensors" if mode == EventMode.REAL else "unavailable",
                source_agent=self.name,
                agent_version=self.agent_version,
                mode=mode,
            ),
        )

    def emit_telemetry(self, host: Optional[str] = None) -> Dict[str, Any]:
        """Collect and publish real telemetry to the event bus."""
        return self.run_guarded(self._emit_telemetry, host)

    def _emit_telemetry(self, host: Optional[str]) -> Dict[str, Any]:
        event = self.collect_telemetry(host)
        report = self.bus.publish(event)
        return {"status": "success", "event_id": event.event_id, "mode": event.provenance.mode.value,
                "data_sections": [k for k, v in event.data.items() if isinstance(v, dict) and v.get("status") != "unavailable"],
                "delivery": report["delivered_to"]}

    # ------------------------------------------------------------------
    # Authentication events from the SIEM database (parsed, not invented)
    # ------------------------------------------------------------------
    _AUTH_RE = re.compile(r"failed (?:login|password|auth)", re.IGNORECASE)

    def auth_events(self, limit: int = 50) -> Dict[str, Any]:
        """Parse authentication failures out of the SIEM log table."""
        return self.run_guarded(self._auth_events, limit)

    def _auth_events(self, limit: int) -> Dict[str, Any]:
        from vrin_SOC.database.db import get_logs

        rows = get_logs(max(1, min(limit, 200)))
        hits: List[Dict[str, Any]] = []
        for row in rows:
            command = str(row.get("command", ""))
            result = str(row.get("result", ""))
            text = f"{command} {result}"
            if self._AUTH_RE.search(text):
                ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text)
                hits.append({
                    "timestamp": row.get("timestamp"),
                    "command": command[:200],
                    "risk_level": row.get("risk_level", "Low"),
                    "source_ip": ip_match.group(1) if ip_match else None,
                })
        return {
            "status": "success",
            "mode": EventMode.REAL.value,
            "source": "siem_database",
            "count": len(hits),
            "events": hits,
            "note": "Parsed from existing SIEM logs; no records invented."
            if hits else "No authentication failures found in recent SIEM logs.",
        }

    # ------------------------------------------------------------------
    # Offline-first synthetic telemetry (always labeled SIMULATION)
    # ------------------------------------------------------------------
    def synthetic_event(
        self,
        event_type: str,
        data: Dict[str, Any],
        host: str = "sim-host-01",
        ip: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        severity: str = "medium",
    ) -> SecurityEvent:
        """Build a clearly labeled simulated event for offline dev/testing/demo."""
        ts = (timestamp or datetime.now(timezone.utc)).isoformat()
        event = SecurityEvent(
            event_type=event_type,
            source_agent=self.name,
            source_system=host,
            entity=EntityRef(host=host, ip=ip),
            data={"SIMULATION": True, **data},
            severity=severity,
            timestamp=ts,
            provenance=Provenance(
                source="synthetic_generator",
                collection_method="simulation",
                source_agent=self.name,
                agent_version=self.agent_version,
                mode=EventMode.SIMULATED,
            ),
        )
        return event


infrastructure_ai = InfrastructureAI()

__all__ = ["InfrastructureAI", "infrastructure_ai", "utc_now_iso", "timedelta"]
