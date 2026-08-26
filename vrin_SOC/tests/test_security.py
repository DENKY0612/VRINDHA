import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from vrin_SOC.api.auth import AuthModule
from vrin_SOC.automation.actions import automation_actions
from vrin_SOC.core.authorization import AuthorizationLayer
from vrin_SOC.core.brain import Brain


class SecurityTests(unittest.TestCase):
    def test_auth_password_and_expiring_token(self):
        with tempfile.TemporaryDirectory() as directory:
            auth = AuthModule(Path(directory) / "users.json", "x" * 48)
            hashed = auth.hash_password("correct horse battery staple")
            self.assertTrue(auth.verify_password("correct horse battery staple", hashed))
            self.assertFalse(auth.verify_password("wrong", hashed))
            token = auth.create_access_token({"sub": "tester", "role": "admin"})
            self.assertEqual(auth.verify_token(token)["sub"], "tester")
            self.assertIsNone(auth.verify_token("invalid"))

    def test_public_active_targets_denied(self):
        policy = AuthorizationLayer()
        self.assertFalse(policy.is_target_allowed("8.8.8.8", "nmap")[0])
        self.assertFalse(policy.is_target_allowed("example.com", "scan")[0])
        self.assertTrue(policy.is_target_allowed("example.com", "whois")[0])
        self.assertTrue(policy.is_target_allowed("127.0.0.1", "nmap")[0])

    def test_invalid_firewall_address_rejected(self):
        self.assertEqual(automation_actions.block_ip("999.999.999.999")["status"], "error")

    def test_red_confirmations_are_isolated_and_not_auto_confirmed(self):
        brain = Brain()
        first = brain.process("scan network 127.0.0.1", auto_confirm=True, session_id="alice")
        self.assertEqual(first["status"], "awaiting_confirmation")
        unrelated = brain.process("yes", session_id="bob")
        self.assertNotEqual(unrelated["action"], "executed")
        confirmed = brain.process("yes", session_id="alice")
        self.assertEqual(confirmed["action"], "executed")

        brain.process("scan network 127.0.0.1", session_id="expired")
        brain.pending_confirmations["expired"]["timestamp"] = (datetime.now() - timedelta(minutes=6)).isoformat()
        expired = brain.process("yes", session_id="expired")
        self.assertEqual(expired["action"], "confirmation_expired")

    def test_harmful_intent_is_denied(self):
        result = Brain().process("hack government.gov", session_id="attacker")
        self.assertEqual(result["status"], "denied")


if __name__ == "__main__":
    unittest.main()
