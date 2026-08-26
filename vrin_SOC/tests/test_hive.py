"""Tests for the Hive coordination layer."""
from __future__ import annotations

import importlib


def test_hive_package_importable():
    hive_pkg = importlib.import_module("vrin_SOC.hive")
    assert hive_pkg is not None


def test_hive_coordinator_singleton():
    from vrin_SOC.hive.coordinator import hive, HiveCoordinator
    assert isinstance(hive, HiveCoordinator)


def test_hive_health():
    from vrin_SOC.hive.coordinator import hive
    health = hive.health()
    assert health["status"] in ("healthy", "degraded")
    assert "agents_total" in health
    assert "agents_active" in health
    assert health["agents_total"] > 0  # built-in agents are auto-registered


def test_hive_snapshot():
    from vrin_SOC.hive.coordinator import hive
    snap = hive.snapshot()
    assert "agents" in snap
    assert "timestamp" in snap
    assert len(snap["agents"]) > 0


def test_hive_list_agents():
    from vrin_SOC.hive.coordinator import hive
    result = hive.list_agents()
    assert result["status"] == "success"
    assert result["count"] > 0
    names = [a["name"] for a in result["agents"]]
    assert "SIEMAgent" in names
    assert "ReconAgent" in names


def test_hive_register_and_deregister():
    from vrin_SOC.hive.coordinator import hive
    reg = hive.register_agent("TestAgent", "blue", ["test_cap"])
    assert reg["status"] == "success"
    assert reg["agent"]["name"] == "TestAgent"

    status = hive.agent_status("TestAgent")
    assert status["status"] == "success"

    dereg = hive.deregister_agent("TestAgent")
    assert dereg["status"] == "success"
    assert dereg["removed"] is True

    gone = hive.agent_status("TestAgent")
    assert gone["status"] == "not_found"


def test_hive_heartbeat():
    from vrin_SOC.hive.coordinator import hive
    hive.register_agent("HeartbeatAgent", "blue", ["ping"])
    result = hive.heartbeat_agent("HeartbeatAgent")
    assert result["status"] == "success"
    assert result["agent"]["last_heartbeat"] is not None
    hive.deregister_agent("HeartbeatAgent")


def test_hive_dispatch_no_matching_capability():
    from vrin_SOC.hive.coordinator import hive
    result = hive.dispatch("test command", capabilities=["nonexistent_capability_xyz"])
    assert result["status"] == "no_agents"


def test_hive_dispatch_with_capability():
    from vrin_SOC.hive.coordinator import hive
    result = hive.dispatch("test scan", capabilities=["nmap"])
    assert result["status"] in ("completed", "failed")
    assert "results" in result


def test_hive_share_intelligence():
    from vrin_SOC.hive.coordinator import hive
    result = hive.share_intelligence(
        source_agent="SIEMAgent",
        indicator="192.168.1.100",
        indicator_type="ipv4",
        confidence=0.8,
    )
    assert result["status"] == "success"
    assert result["recipient_count"] > 0


def test_hive_list_tasks():
    from vrin_SOC.hive.coordinator import hive
    result = hive.list_tasks()
    assert result["status"] == "success"
    assert "tasks" in result


def test_hive_reap_stale():
    from vrin_SOC.hive.coordinator import hive
    result = hive.reap_stale()
    assert result["status"] == "success"
    assert "reaped" in result
