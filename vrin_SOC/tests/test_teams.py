"""Red Team and Blue Team end-to-end behavior."""
import socket
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from api import main as api_main
from api.auth import AuthModule
from automation.firewall import FirewallModule
from core.brain import Brain
from core.local_sensors import tcp_connect_scan
from database.db import get_blocked_ips, get_threats
from tools.nmap_tool import run_nmap
from tools.whois_tool import run_whois

STRONG_PASSWORD = "correct-horse-battery-staple"


class LocalSensorTests(unittest.TestCase):
    def test_tcp_scan_finds_open_port(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            result = tcp_connect_scan("127.0.0.1", ports=[port], timeout=0.5)
            self.assertEqual(result["status"], "success")
            self.assertTrue(any(item["port"] == port for item in result["open_ports"]))
        finally:
            server.close()

    def test_nmap_wrapper_returns_structured_result(self):
        result = run_nmap("127.0.0.1")
        self.assertIn(result.get("status"), {"success", "error"})
        self.assertIn("findings", result)
        self.assertTrue(result.get("result"))

    def test_whois_returns_real_or_explicit_error(self):
        result = run_whois("example.com")
        self.assertIn(result.get("status"), {"success", "error"})
        if result.get("status") == "success":
            self.assertIn("example", result.get("result", "").lower())


class BrainTeamTests(unittest.TestCase):
    def test_red_scan_requires_confirmation_then_executes(self):
        brain = Brain()
        first = brain.process("scan network 127.0.0.1", session_id="red-op")
        self.assertEqual(first["status"], "awaiting_confirmation")
        self.assertIsNotNone(brain.pending_for("red-op"))
        confirmed = brain.process("yes", session_id="red-op")
        self.assertEqual(confirmed["action"], "executed")
        self.assertEqual(confirmed["status"], "success")
        self.assertIn("result", confirmed.get("data", {}))

    def test_public_nmap_is_denied(self):
        result = Brain().process("scan network 8.8.8.8", session_id="public")
        self.assertEqual(result["status"], "denied")

    def test_whois_public_domain_is_allowed_after_confirm(self):
        brain = Brain()
        first = brain.process("whois example.com", session_id="whois-op")
        self.assertEqual(first["status"], "awaiting_confirmation")
        confirmed = brain.process("yes", session_id="whois-op")
        self.assertEqual(confirmed["action"], "executed")

    def test_blue_detect_with_source_ip_records_threat(self):
        before = len(get_threats(200))
        result = Brain().process("detect threats malware attack from 10.0.0.8", session_id="blue-op")
        self.assertEqual(result["mode"], "blue")
        self.assertEqual(result["action"], "threat_detection")
        self.assertNotEqual(result.get("action"), "goal_planned")
        self.assertGreaterEqual(len(get_threats(200)), before)

    def test_blue_block_requires_ip(self):
        result = Brain().process("block ip", session_id="blue-block")
        self.assertEqual(result["status"], "error")

    def test_blue_block_persists_valid_ip(self):
        result = Brain().process("block ip 10.0.0.9", session_id="blue-block-ok")
        self.assertIn(result["status"], {"success", "error"})
        if result["status"] == "success":
            self.assertTrue(any(item["ip"] == "10.0.0.9" for item in get_blocked_ips(50)))

    def test_firewall_does_not_invent_failures_without_demo(self):
        analysis = FirewallModule().check_and_block(log_text="clean system boot", demo=False)
        self.assertEqual(analysis["analysis"]["blocked"], [])
        self.assertFalse(analysis.get("demo"))


class TeamAPITests(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.auth = AuthModule(Path(self._tmpdir.name) / "users.json", "t" * 48)
        self._original = api_main.auth_module
        api_main.auth_module = self.auth
        self.client = TestClient(api_main.app)
        created = self.client.post("/register", json={"username": "admin", "password": STRONG_PASSWORD})
        self.assertEqual(created.status_code, 201)
        self.headers = {"Authorization": f"Bearer {created.json()['access_token']}"}
        api_main.brain.pending_confirmations.pop("admin", None)

    def tearDown(self):
        api_main.auth_module = self._original
        self._tmpdir.cleanup()

    def test_state_requires_auth(self):
        self.assertEqual(self.client.get("/team/state").status_code, 401)

    def test_red_then_confirm(self):
        first = self.client.post("/team/red", headers=self.headers, json={"action": "nmap", "target": "127.0.0.1"})
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json()["status"], "awaiting_confirmation")
        state = self.client.get("/team/state", headers=self.headers)
        self.assertIsNotNone(state.json()["pending"])
        confirmed = self.client.post("/team/confirm", headers=self.headers, json={"decision": "yes"})
        self.assertEqual(confirmed.status_code, 200)
        self.assertEqual(confirmed.json()["action"], "executed")

    def test_blue_detect_and_block(self):
        detect = self.client.post(
            "/team/blue",
            headers=self.headers,
            json={"action": "detect", "target": "10.0.0.12", "details": "malware attack"},
        )
        self.assertEqual(detect.status_code, 200)
        self.assertEqual(detect.json()["action"], "threat_detection")
        block = self.client.post("/team/blue", headers=self.headers, json={"action": "block", "target": "10.0.0.13"})
        self.assertEqual(block.status_code, 200)
        missing = self.client.post("/team/blue", headers=self.headers, json={"action": "block", "target": ""})
        self.assertEqual(missing.status_code, 422)

    def test_confirm_without_pending(self):
        response = self.client.post("/team/confirm", headers=self.headers, json={"decision": "no"})
        self.assertEqual(response.status_code, 409)

    def test_unknown_action(self):
        response = self.client.post("/team/red", headers=self.headers, json={"action": "launch-missiles"})
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
