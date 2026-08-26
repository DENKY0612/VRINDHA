"""Hive coordinator — unified entry point for the swarm layer.

The ``HiveCoordinator`` owns the agent registry and swarm dispatcher,
auto-registers the built-in Vrindha agents at startup, and exposes a
high-level API consumed by the Brain and the REST API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
import logging

from .models import AgentState, HiveSnapshot, TaskPriority
from .registry import AgentRegistry
from .swarm import SwarmDispatcher

logger = logging.getLogger(__name__)


# Built-in agent definitions: (name, kind, capabilities)
_BUILTIN_AGENTS = [
    ("SIEMAgent", "blue", ["siem", "log_correlation", "event_detection"]),
    ("ReconAgent", "red", ["nmap", "whois", "recon", "subdomain_enum"]),
    ("VulnAgent", "red", ["nikto", "gobuster", "dirb", "vuln_scan"]),
    ("ThreatAgent", "blue", ["threat_detection", "ioc_lookup", "correlation"]),
    ("NetworkAgent", "blue", ["tcpdump", "wireshark", "ids", "snort"]),
    ("EndpointAgent", "blue", ["rootkit_scan", "endpoint_security", "file_integrity"]),
    ("FirewallAgent", "blue", ["firewall", "block_ip", "ids_monitor"]),
    ("AnomalyDetector", "ml", ["anomaly_detection", "risk_scoring", "prediction"]),
    ("ExploitAssistant", "red", ["hashcat", "exploit_assist", "metasploit"]),
    ("IntelligenceBus", "sensor", ["ti_lookup", "feed_sync", "intelligence"]),
]


class HiveCoordinator:
    """Top-level coordinator for the Vrindha agent hive."""

    def __init__(self, auto_register: bool = True) -> None:
        self.registry = AgentRegistry()
        self.dispatcher = SwarmDispatcher(self.registry)
        self._started_at = datetime.now().isoformat()

        if auto_register:
            self._register_builtins()

        logger.info(
            "[Hive] Coordinator initialized with %d built-in agents",
            len(_BUILTIN_AGENTS),
        )

    # ------------------------------------------------------------------
    # Bootstrap
    # ------------------------------------------------------------------
    def _register_builtins(self) -> None:
        for name, kind, capabilities in _BUILTIN_AGENTS:
            self.registry.register(name, kind, capabilities)

    # ------------------------------------------------------------------
    # Agent management
    # ------------------------------------------------------------------
    def register_agent(
        self,
        name: str,
        kind: str,
        capabilities: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        record = self.registry.register(name, kind, capabilities, metadata)
        return {"status": "success", "agent": record.to_dict()}

    def deregister_agent(self, name: str) -> Dict[str, Any]:
        removed = self.registry.deregister(name)
        return {
            "status": "success" if removed else "not_found",
            "name": name,
            "removed": removed,
        }

    def heartbeat_agent(self, name: str) -> Dict[str, Any]:
        record = self.registry.heartbeat(name)
        if record is None:
            return {"status": "not_found", "name": name}
        return {"status": "success", "agent": record.to_dict()}

    def list_agents(self, kind: Optional[str] = None) -> Dict[str, Any]:
        if kind:
            agents = self.registry.by_kind(kind)
        else:
            agents = list(self.registry.all_agents().values())
        return {
            "status": "success",
            "count": len(agents),
            "agents": [a.to_dict() for a in agents],
        }

    def agent_status(self, name: str) -> Dict[str, Any]:
        record = self.registry.get(name)
        if record is None:
            return {"status": "not_found", "name": name}
        return {"status": "success", "agent": record.to_dict()}

    # ------------------------------------------------------------------
    # Swarm dispatch
    # ------------------------------------------------------------------
    def dispatch(
        self,
        command: str,
        priority: str = "normal",
        capabilities: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create and immediately dispatch a task to matching agents."""
        prio = TaskPriority(priority) if priority in TaskPriority.__members__.values() else TaskPriority.NORMAL
        task = self.dispatcher.create_task(command, prio, capabilities)

        if task.status == "pending":
            return {
                "status": "no_agents",
                "message": "No active agents matched the required capabilities",
                "task": task.to_dict(),
            }

        result = self.dispatcher.dispatch_task(task.task_id)
        return result

    def create_task(
        self,
        command: str,
        priority: str = "normal",
        capabilities: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create a task without immediately dispatching it."""
        prio = TaskPriority(priority) if priority in TaskPriority.__members__.values() else TaskPriority.NORMAL
        task = self.dispatcher.create_task(command, prio, capabilities)
        return {"status": "created", "task": task.to_dict()}

    def execute_task(self, task_id: int) -> Dict[str, Any]:
        return self.dispatcher.dispatch_task(task_id)

    def list_tasks(self, status: Optional[str] = None) -> Dict[str, Any]:
        tasks = self.dispatcher.list_tasks(status)
        return {
            "status": "success",
            "count": len(tasks),
            "tasks": [t.to_dict() for t in tasks],
        }

    # ------------------------------------------------------------------
    # Intelligence sharing
    # ------------------------------------------------------------------
    def share_intelligence(
        self,
        source_agent: str,
        indicator: str,
        indicator_type: str = "auto",
        confidence: float = 0.5,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Broadcast an intelligence sighting from one agent to all others.

        This is a lightweight, in-process fan-out. For durable TI exchange
        with the external Vrin_TI service, use the IntelligenceBus directly.
        """
        record = self.registry.get(source_agent)
        if record is None:
            return {"status": "error", "message": f"Source agent '{source_agent}' not registered"}

        # Fan out to all active agents except the source
        recipients: List[str] = []
        for agent in self.registry.active_agents():
            if agent.name != source_agent:
                recipients.append(agent.name)

        sighting = {
            "source": source_agent,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "confidence": confidence,
            "context": context or {},
            "timestamp": datetime.now().isoformat(),
            "recipients": recipients,
        }

        logger.info(
            "[Hive] Intelligence shared: %s (%s) from %s → %d agents",
            indicator,
            indicator_type,
            source_agent,
            len(recipients),
        )

        return {
            "status": "success",
            "sighting": sighting,
            "recipient_count": len(recipients),
        }

    # ------------------------------------------------------------------
    # Health & snapshot
    # ------------------------------------------------------------------
    def reap_stale(self) -> Dict[str, Any]:
        reaped = self.registry.reap_stale()
        return {
            "status": "success",
            "reaped": reaped,
            "count": len(reaped),
        }

    def snapshot(self) -> Dict[str, Any]:
        """Return a full point-in-time snapshot of the hive."""
        self.registry.reap_stale()
        snap = HiveSnapshot(
            agents=self.registry.all_agents(),
            active_tasks=len(self.dispatcher.list_tasks("dispatched")),
            completed_tasks=len(self.dispatcher.list_tasks("completed")),
            failed_tasks=len(self.dispatcher.list_tasks("failed")),
        )
        return snap.to_dict()

    def health(self) -> Dict[str, Any]:
        """Lightweight health check for the hive layer."""
        self.registry.reap_stale()
        agents = self.registry.all_agents()
        active = sum(
            1 for a in agents.values() if a.state in (AgentState.ACTIVE, AgentState.BUSY)
        )
        total = len(agents)
        return {
            "status": "healthy" if active > 0 else "degraded",
            "agents_total": total,
            "agents_active": active,
            "agents_offline": total - active,
            "dispatcher": self.dispatcher.stats(),
            "started_at": self._started_at,
            "timestamp": datetime.now().isoformat(),
        }


# Module-level singleton — imported by the Brain and API layers.
hive = HiveCoordinator()
