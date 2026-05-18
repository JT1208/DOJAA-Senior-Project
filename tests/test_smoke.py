"""Smoke tests: routes return 200, key behaviours hold.

Run with `python -m pytest tests/` or `python -m unittest tests/test_smoke.py`.
"""

from __future__ import annotations

import os
import unittest

# Make sure we don't accidentally hit external APIs from the test run.
os.environ.setdefault("DOJAA_AUTH_DISABLED", "true")
os.environ.setdefault("SHODAN_API_KEY", "")
os.environ.setdefault("CENSYS_API_TOKEN", "")
os.environ.setdefault("NVD_API_KEY", "")

from dojaa import create_app  # noqa: E402
from dojaa.normalizer import normalize_data  # noqa: E402
from dojaa.risk_engine import calculate_risk  # noqa: E402
from dojaa.risk_tiers import risk_bucket, risk_tier_counts  # noqa: E402


class RouteSmokeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = create_app().test_client()

    def test_all_main_routes_render(self) -> None:
        for path in (
            "/dashboard",
            "/hosts",
            "/ports",
            "/risk",
            "/cves",
            "/ssl-tls",
            "/graph",
            "/tools/dns",
            "/tools/headers",
        ):
            with self.subTest(path=path):
                resp = self.client.get(path)
                self.assertEqual(resp.status_code, 200, f"{path} returned {resp.status_code}")

    def test_root_redirects_when_auth_enabled(self) -> None:
        # Re-create with auth on for this test.
        os.environ["DOJAA_AUTH_DISABLED"] = "false"
        try:
            app = create_app()
            resp = app.test_client().get("/dashboard", follow_redirects=False)
            self.assertEqual(resp.status_code, 302)
        finally:
            os.environ["DOJAA_AUTH_DISABLED"] = "true"


class RiskBucketTests(unittest.TestCase):
    def test_buckets(self) -> None:
        self.assertEqual(risk_bucket(0), "low")
        self.assertEqual(risk_bucket(19), "low")
        self.assertEqual(risk_bucket(20), "medium")
        self.assertEqual(risk_bucket(49), "medium")
        self.assertEqual(risk_bucket(50), "high")
        self.assertEqual(risk_bucket(100), "high")
        self.assertEqual(risk_bucket(None), "unknown")
        self.assertEqual(risk_bucket("nope"), "unknown")

    def test_tier_counts(self) -> None:
        low, mid, high = risk_tier_counts(
            [{"risk_score": 10}, {"risk_score": 30}],
            [{"risk_score": 80}, {"risk_score": 51}, {"risk_score": "bad"}],
        )
        self.assertEqual((low, mid, high), (1, 1, 2))


class RiskEngineTests(unittest.TestCase):
    def test_shadow_ssh_no_https_scores_high(self) -> None:
        asset = {
            "ssh_exposed": True,
            "http_exposed": True,
            "https_exposed": False,
            "port": 22,
            "known": False,
            "banner": "SSH-2.0-OpenSSH_7.4",
            "banner_version": "7.4",
        }
        out = calculate_risk(asset)
        self.assertGreaterEqual(out["risk_score"], 50)
        self.assertEqual(out["severity"], "High")
        self.assertIn("Shadow asset detected", out["issues"])

    def test_port_as_string_is_handled(self) -> None:
        asset = {"port": "3389", "known": True, "https_exposed": True}
        out = calculate_risk(asset)
        self.assertIn("Sensitive service port exposed", out["issues"])


class NormalizerTests(unittest.TestCase):
    def test_shodan_row_normalises(self) -> None:
        rows = normalize_data([
            {"ip": "1.2.3.4", "port": 443, "service": "nginx", "banner": "Server: nginx"}
        ])
        self.assertEqual(rows[0]["ip"], "1.2.3.4")
        self.assertEqual(rows[0]["port"], 443)
        self.assertEqual(rows[0]["service"], "nginx")

    def test_string_port_coerces_to_int(self) -> None:
        rows = normalize_data([{"ip": "1.1.1.1", "port": "22"}])
        self.assertEqual(rows[0]["port"], 22)


if __name__ == "__main__":
    unittest.main()
