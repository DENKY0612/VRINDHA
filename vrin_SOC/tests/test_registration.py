"""Tests for secure user registration and Bearer authentication.

Covers the AuthModule user-management methods and the FastAPI /register,
/login, and protected endpoints via TestClient against an isolated user store.
"""
import json
import tempfile
import threading
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from vrin_SOC.api import main as api_main
from vrin_SOC.api.auth import (
    AuthModule,
    BootstrapClosedError,
    DuplicateUserError,
    InvalidPasswordError,
    InvalidRoleError,
    InvalidUsernameError,
)

STRONG_PASSWORD = "correct-horse-battery-staple"
OTHER_PASSWORD = "another-secure-password"


class AuthModuleUnitTests(unittest.TestCase):
    def _auth(self, directory: str) -> AuthModule:
        return AuthModule(Path(directory) / "users.json", "s" * 48)

    def test_username_normalization_and_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            auth = self._auth(directory)
            self.assertEqual(auth.normalize_username("  Analyst-1 "), "analyst-1")
            user = auth.create_user("Test_User.1", STRONG_PASSWORD)
            self.assertEqual(user["username"], "test_user.1")
            for bad in ["ab", "a" * 65, "1 bad", "-lead", "has space", "x!y", ".hidden"]:
                with self.assertRaises(InvalidUsernameError):
                    auth.create_user(bad, STRONG_PASSWORD)

    def test_password_minimum_and_role_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            auth = self._auth(directory)
            with self.assertRaises(InvalidPasswordError):
                auth.create_user("analyst1", "short")
            with self.assertRaises(InvalidRoleError):
                auth.create_user("analyst1", STRONG_PASSWORD, role="root")

    def test_duplicate_rejected_and_hash_never_returned(self):
        with tempfile.TemporaryDirectory() as directory:
            auth = self._auth(directory)
            user = auth.create_user("analyst1", STRONG_PASSWORD)
            self.assertNotIn("password_hash", user)
            # The hash IS stored on disk for authentication.
            self.assertIn("password_hash", auth.load_users()["analyst1"])
            self.assertIs(user.get("active"), True)
            # Case-insensitive duplicates are rejected.
            with self.assertRaises(DuplicateUserError):
                auth.create_user("ANALYST1", OTHER_PASSWORD)
            self.assertTrue(auth.has_users())

    def test_first_user_bootstrap_is_atomic_and_forced_admin(self):
        with tempfile.TemporaryDirectory() as directory:
            auth = self._auth(directory)
            created = []

            def attempt(name):
                try:
                    auth.create_user(name, STRONG_PASSWORD, role="user", require_empty=True)
                    created.append(name)
                except BootstrapClosedError:
                    pass

            threads = [threading.Thread(target=attempt, args=(f"user{i}",)) for i in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(len(created), 1)
            stored = auth.load_users()
            self.assertEqual(stored[created[0]]["role"], "admin")
            # Bootstrap is closed once a user exists.
            with self.assertRaises(BootstrapClosedError):
                auth.create_user("latecomer", STRONG_PASSWORD, require_empty=True)

    def test_disabled_user_cannot_authenticate(self):
        with tempfile.TemporaryDirectory() as directory:
            auth = self._auth(directory)
            auth.create_user("analyst1", STRONG_PASSWORD)
            self.assertIsNotNone(auth.authenticate_user("analyst1", STRONG_PASSWORD))
            users = auth.load_users()
            users["analyst1"]["active"] = False
            auth._write_users(users)
            self.assertIsNone(auth.authenticate_user("analyst1", STRONG_PASSWORD))

    def test_users_file_written_atomically_with_0600(self):
        with tempfile.TemporaryDirectory() as directory:
            auth = self._auth(directory)
            auth.create_user("analyst1", STRONG_PASSWORD)
            mode = auth.users_file.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)
            self.assertEqual(json.loads(auth.users_file.read_text(encoding="utf-8"))["analyst1"]["username"], "analyst1")
            # No leftover temp files next to the store.
            leftovers = [p.name for p in auth.users_file.parent.iterdir() if p.name != "users.json"]
            self.assertEqual(leftovers, [])


class RegistrationAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(api_main.app)

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.users_file = Path(self._tmpdir.name) / "users.json"
        self.auth = AuthModule(self.users_file, "t" * 48)
        self._original_auth_module = api_main.auth_module
        api_main.auth_module = self.auth

    def tearDown(self):
        api_main.auth_module = self._original_auth_module
        self._tmpdir.cleanup()

    def _bootstrap(self) -> str:
        """Register the first administrator and return its access token."""
        response = self.client.post("/register", json={"username": "admin", "password": STRONG_PASSWORD})
        self.assertEqual(response.status_code, 201)
        return response.json()["access_token"]

    def test_first_user_forced_admin_and_returns_jwt(self):
        response = self.client.post("/register", json={"username": "admin", "password": STRONG_PASSWORD})
        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertEqual(body["status"], "success")
        self.assertEqual(body["message"], "First administrator registered")
        self.assertEqual(body["user"]["role"], "admin")
        self.assertEqual(body["user"]["active"], True)
        self.assertIn("created", body["user"])
        self.assertNotIn("password_hash", body["user"])
        self.assertEqual(body["token_type"], "bearer")
        payload = self.auth.verify_token(body["access_token"])
        self.assertEqual(payload["sub"], "admin")
        self.assertEqual(payload["role"], "admin")
        # The stored record really is an administrator.
        self.assertEqual(self.auth.load_users()["admin"]["role"], "admin")

    def test_public_registration_closes_after_first_user(self):
        self._bootstrap()
        response = self.client.post("/register", json={"username": "analyst1", "password": OTHER_PASSWORD})
        self.assertEqual(response.status_code, 401)

    def test_administrator_can_create_user(self):
        token = self._bootstrap()
        response = self.client.post(
            "/register",
            headers={"Authorization": f"Bearer {token}"},
            json={"username": "analyst1", "password": OTHER_PASSWORD, "role": "user"},
        )
        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertEqual(body["user"]["username"], "analyst1")
        self.assertEqual(body["user"]["role"], "user")
        self.assertNotIn("password_hash", body["user"])

    def test_regular_user_cannot_create_users(self):
        token = self._bootstrap()
        self.client.post(
            "/register",
            headers={"Authorization": f"Bearer {token}"},
            json={"username": "analyst1", "password": OTHER_PASSWORD, "role": "user"},
        )
        login = self.client.post("/login", json={"username": "analyst1", "password": OTHER_PASSWORD})
        self.assertEqual(login.status_code, 200)
        user_token = login.json()["access_token"]
        response = self.client.post(
            "/register",
            headers={"Authorization": f"Bearer {user_token}"},
            json={"username": "analyst2", "password": OTHER_PASSWORD},
        )
        self.assertEqual(response.status_code, 403)

    def test_missing_or_bad_token_returns_401(self):
        self._bootstrap()
        # Anonymous registration after bootstrap.
        response = self.client.post("/register", json={"username": "analyst1", "password": OTHER_PASSWORD})
        self.assertEqual(response.status_code, 401)
        # Garbage bearer token.
        response = self.client.post(
            "/register",
            headers={"Authorization": "Bearer not.a.jwt"},
            json={"username": "analyst1", "password": OTHER_PASSWORD},
        )
        self.assertEqual(response.status_code, 401)
        # No Authorization header on protected endpoints.
        for method, path, payload in [
            ("get", "/logs", None),
            ("get", "/dashboard-data", None),
            ("get", "/ml/predict", None),
            ("get", "/ml/pipeline", None),
            ("get", "/tools/verify", None),
            ("post", "/command", {"command": "status"}),
            ("post", "/ml/anomaly", {"command": "test"}),
            ("post", "/ml/risk", {"ip": "127.0.0.1"}),
            ("get", "/team/state", None),
            ("post", "/team/red", {"action": "nmap", "target": "127.0.0.1"}),
            ("post", "/team/blue", {"action": "detect", "details": "malware"}),
            ("post", "/team/confirm", {"decision": "no"}),
        ]:
            request = getattr(self.client, method)
            result = request(path, json=payload) if payload else request(path)
            self.assertEqual(result.status_code, 401, (method, path))

    def test_duplicate_username_returns_409(self):
        token = self._bootstrap()
        first = self.client.post(
            "/register",
            headers={"Authorization": f"Bearer {token}"},
            json={"username": "analyst1", "password": OTHER_PASSWORD},
        )
        self.assertEqual(first.status_code, 201)
        duplicate = self.client.post(
            "/register",
            headers={"Authorization": f"Bearer {token}"},
            json={"username": "Analyst1", "password": OTHER_PASSWORD},
        )
        self.assertEqual(duplicate.status_code, 409)

    def test_invalid_input_returns_422(self):
        token = self._bootstrap()
        cases = [
            {"username": "a", "password": STRONG_PASSWORD},
            {"username": "bad name!", "password": STRONG_PASSWORD},
            {"username": "-leading", "password": STRONG_PASSWORD},
            {"username": "analyst1", "password": "short"},
            {"username": "analyst1", "password": STRONG_PASSWORD, "role": "superuser"},
            {"username": "", "password": STRONG_PASSWORD},
        ]
        for payload in cases:
            response = self.client.post(
                "/register",
                headers={"Authorization": f"Bearer {token}"},
                json=payload,
            )
            self.assertEqual(response.status_code, 422, payload)

    def test_usernames_normalized_to_lowercase(self):
        token = self._bootstrap()
        response = self.client.post(
            "/register",
            headers={"Authorization": f"Bearer {token}"},
            json={"username": "Analyst-1", "password": OTHER_PASSWORD},
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["user"]["username"], "analyst-1")
        self.assertIn("analyst-1", self.auth.load_users())
        # Login is case-insensitive too.
        login = self.client.post("/login", json={"username": "ANALYST-1", "password": OTHER_PASSWORD})
        self.assertEqual(login.status_code, 200)

    def test_disabled_user_cannot_log_in(self):
        token = self._bootstrap()
        self.client.post(
            "/register",
            headers={"Authorization": f"Bearer {token}"},
            json={"username": "analyst1", "password": OTHER_PASSWORD},
        )
        users = self.auth.load_users()
        users["analyst1"]["active"] = False
        self.auth._write_users(users)
        login = self.client.post("/login", json={"username": "analyst1", "password": OTHER_PASSWORD})
        self.assertEqual(login.status_code, 401)

    def test_jwt_authentication_works_on_protected_endpoints(self):
        token = self._bootstrap()
        headers = {"Authorization": f"Bearer {token}"}
        self.assertEqual(self.client.get("/logs", headers=headers).status_code, 200)
        self.assertEqual(self.client.post("/command", headers=headers, json={"command": "status"}).status_code, 200)
        self.assertEqual(self.client.get("/dashboard-data", headers=headers).status_code, 200)
        self.assertEqual(self.client.get("/tools/verify", headers=headers).status_code, 200)

    def test_openapi_contains_bearer_auth(self):
        spec = self.client.get("/openapi.json").json()
        schemes = spec["components"]["securitySchemes"]
        self.assertIn("BearerAuth", schemes)
        self.assertEqual(schemes["BearerAuth"]["type"], "http")
        self.assertEqual(schemes["BearerAuth"]["scheme"], "bearer")

    def test_protected_endpoints_declare_bearer_security(self):
        spec = self.client.get("/openapi.json").json()
        protected = [
            ("/command", "post"),
            ("/logs", "get"),
            ("/dashboard-data", "get"),
            ("/ml/anomaly", "post"),
            ("/ml/risk", "post"),
            ("/ml/predict", "get"),
            ("/ml/pipeline", "get"),
            ("/tools/verify", "get"),
            ("/team/state", "get"),
            ("/team/red", "post"),
            ("/team/blue", "post"),
            ("/team/confirm", "post"),
        ]
        for path, method in protected:
            security = spec["paths"][path][method].get("security")
            self.assertTrue(security and any("BearerAuth" in item for item in security), (path, method))
        public = [("/", "get"), ("/status", "get"), ("/login", "post"), ("/gita/random", "get")]
        for path, method in public:
            self.assertNotIn("security", spec["paths"][path][method], (path, method))


if __name__ == "__main__":
    unittest.main()
