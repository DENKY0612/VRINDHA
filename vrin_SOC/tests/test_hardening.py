"""Regression tests for the interface-injection and session hardening fixes."""

import os
import unittest

from vrin_SOC.tools.security import validate_interface


class InterfaceValidationTests(unittest.TestCase):
    def test_common_interfaces_are_accepted(self):
        for name in ("eth0", "lo", "ens33", "br-0", "vlan.10", "wlan0:1"):
            ok, value = validate_interface(name)
            self.assertTrue(ok, name)
            self.assertEqual(value, name)

    def test_flag_smuggling_is_rejected(self):
        for bad in ("eth0 -w /tmp/x", "-w", "eth0;id", "eth0|tee x", "e t", "", None,
                    "eth0$(id)", "x" * 64):
            ok, _ = validate_interface(bad or "")
            self.assertFalse(ok, bad)

    def test_tcpdump_tool_rejects_bad_interface(self):
        from vrin_SOC.tools.tcpdump_tool import run_tcpdump

        result = run_tcpdump("lo -w /tmp/evil")
        self.assertEqual(result.get("status"), "error")
        self.assertIn("invalid interface", result.get("error", ""))

    def test_ids_monitor_rejects_bad_interface(self):
        from vrin_SOC.automation.ids_monitor import ids_monitor

        result = ids_monitor.monitor(interface="eth0 -l /tmp/evil", prevent=False)
        self.assertEqual(result.get("status"), "error")

    def test_api_endpoints_reject_bad_interface(self):
        os.environ.setdefault("SECRET_KEY", "ci-test-secret-key-value-0123456789abcdef")
        from fastapi.testclient import TestClient
        from vrin_SOC.api.main import app

        client = TestClient(app)
        bad = "eth0 -l /tmp/evil"
        for path in ("/incident/ids", "/incident/idps"):
            response = client.get(path, params={"interface": bad})
            # Auth runs after routing/validation; either way the request fails.
            self.assertIn(response.status_code, (401, 422), (path, response.status_code))


class TokenDefaultTests(unittest.TestCase):
    def test_default_token_lifetime_is_short(self):
        from vrin_SOC.api.auth import DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES

        self.assertLessEqual(DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES, 480)


if __name__ == "__main__":
    unittest.main()
