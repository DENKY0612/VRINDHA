"""Vrindha Threat Intelligence (Vrin_TI).

An independently runnable, defensive threat-intelligence subsystem.  The SOC
integrates through the authenticated intelligence gateway; TI never invokes
SOC response actions directly.
"""

__version__ = "1.0.0"

from .models import IntelligenceEvent, ThreatIndicator

__all__ = ["IntelligenceEvent", "ThreatIndicator", "__version__"]
