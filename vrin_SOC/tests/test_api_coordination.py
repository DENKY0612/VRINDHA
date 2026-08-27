"""API tests for the coordination layer endpoints (auth, data-science,
ethics/Gita, commander, coordinator dashboard, demo).

Follows the existing registration-test pattern: an isolated user store is
swapped into both api.main and api.deps so tests never touch the real
users.json.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from vrin_SOC import api as api_main_module
from vrin_SOC.api import coordination_routes
from vrin_SOC.api import deps as api_deps
from vrin_SOC.api import main as api_main
from vrin_SOC.api.auth import AuthModule

STRONG_PASSWORD = "correct-horse-battery-staple-42"


class CoordinationAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(api_main.app)

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.users_file = Path(self._tmpdir.name) / "users.json"
        self.auth = AuthModule(self.users_file, "t" * 48)
        self._original_deps_auth = api_deps.auth_module
        self._original_main_auth = api_main.auth_module
        api_deps.auth_module = self.auth
        api_main.auth_module = self.auth
        self.admin_token = None
        self.user_token = None

    def tearDown(self):
        api_deps.auth_module = self._original_deps_auth
        api_main.auth_module = self._original_main_auth
        self._tmpdir.cleanup()

    # ------------------------------------------------------------------
    def _bootstrap_admin(self) -> str:
        response = self.client.post("/register", json={"username": "admin", "password": STRONG_PASSWORD})
        self.assertEqual(response.status_code, 201)
        return response.json()["access_token"]

    def _create_user(self, username: str, admin_token: str) -> str:
        response = self.client.post(
            "/register",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"username": username, "password": STRONG_PASSWORD, "role": "user"},
        )
        self.assertEqual(response.status_code, 201)
        login = self.client.post("/login", json={"username": username, "password": STRONG_PASSWORD})
        self.assertEqual(login.status_code, 200)
        return login.json()["access_token"]

    def _headers(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}"}

    # ------------------------------------------------------------------
    # Authentication is required on every coordination endpoint
    # ------------------------------------------------------------------
    def test_endpoints_require_authentication(self):
        for endpoint in ("/agents/health", "/data-science/health", "/commander/incidents",
                         "/coordinator/dashboard", "/ethics/audit", "/knowledge/lessons"):
            response = self.client.get(endpoint)
            self.assertEqual(response.status_code, 401, f"{endpoint} must require auth")

    def test_demo_requires_admin(self):
        token = self._create_user("analyst-hive", self._bootstrap_admin())
        response = self.client.post("/coordinator/demo", headers=self._headers(token),
                                    json={"approver": "analyst"})
        self.assertEqual(response.status_code, 403)

    # ------------------------------------------------------------------
    # Data Science endpoints
    # ------------------------------------------------------------------
    def test_data_science_health_and_models(self):
        token = self._bootstrap_admin()
        health = self.client.get("/data-science/health", headers=self._headers(token))
        self.assertEqual(health.status_code, 200)
        body = health.json()
        self.assertEqual(body["agent"], "DataScienceAI")
        self.assertEqual(body["status"], "healthy")

        models = self.client.get("/data-science/models", headers=self._headers(token))
        self.assertEqual(models.status_code, 200)
        names = {m["model_name"] for m in models.json()["models"]}
        self.assertIn("anomaly", names)
        self.assertIn("risk", names)

    def test_data_science_ingest_rejects_bad_payload_with_reason(self):
        token = self._bootstrap_admin()
        response = self.client.post(
            "/data-science/events",
            headers=self._headers(token),
            json={"event": {"event_type": "security_event", "entity": {"ip": "999.1.1.1"}}},
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "rejected")
        self.assertTrue(body["data_quality"]["rejected_records"])

    def test_data_science_anomaly_and_risk_endpoints(self):
        token = self._bootstrap_admin()
        anomaly = self.client.post(
            "/data-science/anomaly",
            headers=self._headers(token),
            json={"event_type": "security_event", "entity": {"host": "api-host"},
                  "data": {"authentication": {"failed_login_count": 12}}, "severity": "critical"},
        )
        self.assertEqual(anomaly.status_code, 200)
        self.assertIn("anomaly_score", anomaly.json())

        risk = self.client.post(
            "/data-science/risk",
            headers=self._headers(token),
            json={"event_type": "security_event", "entity": {"host": "api-host-2"},
                  "data": {"authentication": {"failed_login_count": 8}}, "severity": "high"},
        )
        self.assertEqual(risk.status_code, 200)
        self.assertIn("factors", risk.json())

    # ------------------------------------------------------------------
    # Ethics + Gita endpoints
    # ------------------------------------------------------------------
    def test_ethics_evaluate_denies_harmful_action(self):
        token = self._bootstrap_admin()
        response = self.client.post(
            "/ethics/evaluate",
            headers=self._headers(token),
            json={"action": "steal the customer data and exfiltrate it",
                  "authorization_status": "missing"},
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["decision"], "deny")
        self.assertEqual(body["classification"], "high_risk_adharma")
        self.assertIn("ASTEYA", body["principles"])

    def test_gita_verse_verified_and_404_when_absent(self):
        token = self._bootstrap_admin()
        verse = self.client.get("/ethics/gita/2/47", headers=self._headers(token))
        self.assertEqual(verse.status_code, 200)
        body = verse.json()
        self.assertTrue(body["verified"])
        self.assertEqual(body["chapter"], 2)
        self.assertEqual(body["verse"], 47)
        self.assertTrue(body["sanskrit"])

        # Out-of-range chapter/verse is a client error…
        out_of_range = self.client.get("/ethics/gita/18/999", headers=self._headers(token))
        self.assertEqual(out_of_range.status_code, 422)
        # …and a valid range without a stored verse is a clean 404 (never fabricated).
        missing = self.client.get("/ethics/gita/2/73", headers=self._headers(token))
        self.assertEqual(missing.status_code, 404)

    def test_gita_chapters_index_lists_18(self):
        token = self._bootstrap_admin()
        response = self.client.get("/ethics/gita/chapters", headers=self._headers(token))
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(len(body["chapters"]), 18)
        self.assertGreaterEqual(body["verse_count"], 700)

    def test_ethics_teach_endpoint(self):
        token = self._bootstrap_admin()
        response = self.client.post(
            "/ethics/teach",
            headers=self._headers(token),
            json={"topic": "why is unauthorized access adharma"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "success")

    # ------------------------------------------------------------------
    # Commander + coordinator
    # ------------------------------------------------------------------
    def test_commander_incidents_endpoint(self):
        token = self._bootstrap_admin()
        response = self.client.get("/commander/incidents", headers=self._headers(token))
        self.assertEqual(response.status_code, 200)
        self.assertIn("incidents", response.json())

    def test_coordinator_dashboard_shape(self):
        token = self._bootstrap_admin()
        response = self.client.get("/coordinator/dashboard", headers=self._headers(token))
        self.assertEqual(response.status_code, 200)
        body = response.json()
        for key in ("agents", "bus", "totals", "incidents", "risk_timeline",
                    "anomaly_timeline", "top_risk_factors", "data_quality", "models"):
            self.assertIn(key, body)
        self.assertEqual(len(body["agents"]), 7)

    def test_demo_endpoint_runs_labeled_simulation(self):
        token = self._bootstrap_admin()
        response = self.client.post("/coordinator/demo", headers=self._headers(token),
                                    json={"approver": "api-e2e-human"})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "success")
        self.assertTrue(body["SIMULATION"])
        self.assertIn("human_approval", [s["stage"] for s in body["stages"]])
        self.assertIsNotNone(body["final_incident"])

    def test_infrastructure_telemetry_endpoint(self):
        token = self._bootstrap_admin()
        response = self.client.get("/infrastructure/telemetry", headers=self._headers(token))
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["event_type"], "telemetry")
        self.assertIn(body["provenance"]["mode"], {"real", "fallback"})


if __name__ == "__main__":
    unittest.main()
