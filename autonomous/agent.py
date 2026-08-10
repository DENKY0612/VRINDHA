"""Autonomous Agent runtime for Phase 2/3: heartbeat, agent state, emergency stop."""

from datetime import datetime
from typing import Dict

from .state_manager import state_manager

class AutonomousAgent:
    def __init__(self):
        state = state_manager.get_state()
        self.active = state.get("active", False)
        self.last_heartbeat = state.get("last_heartbeat")
        self.emergency_stopped = state.get("emergency_stopped", False)
        self.current_mode = state.get("current_mode", "defensive")

    def _persist(self):
        return state_manager.update_state(
            active=self.active,
            emergency_stopped=self.emergency_stopped,
            last_heartbeat=self.last_heartbeat,
            current_mode=self.current_mode,
        )

    def start(self, mode: str = "autonomous") -> Dict[str, object]:
        if self.emergency_stopped:
            return {"status": "denied", "message": "Cannot start while emergency stop is active."}
        if mode not in ["autonomous", "defensive"]:
            return {"status": "error", "message": "Unknown mode. Choose 'autonomous' or 'defensive'."}
        self.active = True
        self.current_mode = mode
        self.last_heartbeat = datetime.now().isoformat()
        state = self._persist()
        return {
            "status": "success",
            "active": self.active,
            "current_mode": self.current_mode,
            "message": f"Autonomous agent started in {self.current_mode} mode.",
            "heartbeat": self.last_heartbeat,
            "state": state,
        }

    def stop(self) -> Dict[str, object]:
        self.active = False
        self.current_mode = "defensive"
        self.last_heartbeat = datetime.now().isoformat()
        state = self._persist()
        return {"status": "success", "active": self.active, "current_mode": self.current_mode, "message": "Autonomous agent stopped.", "state": state}

    def heartbeat(self) -> Dict[str, object]:
        if not self.active:
            return {"status": "inactive", "message": "Autonomous agent is not running."}
        self.last_heartbeat = datetime.now().isoformat()
        state = self._persist()
        return {"status": "success", "message": "Heartbeat received.", "heartbeat": self.last_heartbeat, "state": state}

    def emergency_stop(self) -> Dict[str, object]:
        self.active = False
        self.emergency_stopped = True
        self.last_heartbeat = datetime.now().isoformat()
        state = self._persist()
        return {"status": "success", "message": "Emergency stop engaged. Autonomous operations halted.", "active": self.active, "state": state}

    def reset_emergency(self) -> Dict[str, object]:
        self.emergency_stopped = False
        state = self._persist()
        return {"status": "success", "message": "Emergency stop reset. Start the autonomous agent to resume operations.", "state": state}

    def set_mode(self, mode: str) -> Dict[str, object]:
        if mode not in ["autonomous", "defensive"]:
            return {"status": "error", "message": "Mode must be 'autonomous' or 'defensive'."}
        self.current_mode = mode
        state = self._persist()
        return {"status": "success", "current_mode": self.current_mode, "message": f"Autonomous mode set to {self.current_mode}.", "state": state}

    def status(self) -> Dict[str, object]:
        state = self._persist()
        return {
            "active": self.active,
            "emergency_stopped": self.emergency_stopped,
            "last_heartbeat": self.last_heartbeat,
            "current_mode": self.current_mode,
            "message": "Autonomous agent status returned." if self.active else "Autonomous agent is not currently running.",
            "state": state,
        }


autonomous_agent = AutonomousAgent()
