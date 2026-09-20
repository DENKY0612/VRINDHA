"""
Threat Intelligence Availability Enforcer — Phase 3.

Ensures the "TI unavailable ≠ clean" philosophy is enforced in code, not just docs.
Every TI call must go through this layer which:
1. Validates the TI service is reachable
2. Returns proper ThreatIntelStatus enum
3. Marks events with TI_AVAILABLE metadata when TI is down
4. Never lets code paths assume TI returns data
"""

from __future__ import annotations

import time
import os
from enum import Enum
from typing import Any, Dict, Optional

from vrin_SOC.coordination.schemas import ThreatIntelStatus


class TIAvailability(Enum):
    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class TIEnforcer:
    """
    Singleton enforcer for TI availability checks.
    
    Usage:
        enforcer = TIEnforcer()
        status = enforcer.check()
        if status != TIAvailability.AVAILABLE:
            event.metadata["TI_AVAILABLE"] = False
            event.metadata["TI_STATUS"] = status.value
    """

    _instance: Optional["TIEnforcer"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._last_status = TIAvailability.UNKNOWN
        self._last_check_time = 0
        self._cached_gateway = None

    def check(self) -> TIAvailability:
        """Check if TI service is available. Caches result for 30 seconds."""
        if hasattr(self, "_last_check_time") and time.time() - self._last_check_time < 30:
            return self._last_status

        self._last_check_time = time.time()
        
        # Try to reach the TI gateway
        try:
            from vrin_SOC.core.intelligence_bus import intelligence_gateway
            # Quick health check - try a lightweight call
            result = intelligence_gateway.health()
            if result.get("status") == "success":
                self._last_status = TIAvailability.AVAILABLE
            else:
                self._last_status = TIAvailability.DEGRADED
        except Exception:
            self._last_status = TIAvailability.UNAVAILABLE

        return self._last_status

    def get_status_enum(self) -> ThreatIntelStatus:
        """Map to the formal ThreatIntelStatus enum used in events."""
        status = self.check()
        mapping = {
            TIAvailability.AVAILABLE: ThreatIntelStatus.AVAILABLE,
            TIAvailability.DEGRADED: ThreatIntelStatus.DEGRADED,
            TIAvailability.UNAVAILABLE: ThreatIntelStatus.UNAVAILABLE,
            TIAvailability.UNKNOWN: ThreatIntelStatus.UNKNOWN,
        }
        return mapping.get(status, ThreatIntelStatus.UNKNOWN)

    def enrich_event_metadata(self, event_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Add TI availability metadata to an event's metadata dict."""
        status = self.check()
        event_metadata["TI_AVAILABLE"] = status == TIAvailability.AVAILABLE
        event_metadata["TI_STATUS"] = status.value
        return event_metadata

    def validate_ti_call(self, ti_result: Any, default: Any = None) -> Any:
        """
        Validate a TI call result. If TI is unavailable, return default
        and log a warning. Never let code assume TI data is present.
        """
        status = self.check()
        if status != TIAvailability.AVAILABLE:
            # TI is not available - don't trust any positive result
            import logging
            logging.warning(f"TI call made but TI status is {status.value} - treating as unavailable")
            return default
        return ti_result


# Module-level singleton
ti_enforcer = TIEnforcer()


def get_ti_enforcer() -> TIEnforcer:
    return ti_enforcer