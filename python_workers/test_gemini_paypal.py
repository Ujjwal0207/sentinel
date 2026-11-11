import hashlib
import hmac
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

import requests
from fastapi.testclient import TestClient

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if THIS_DIR not in sys.path:
    sys.path.insert(0, THIS_DIR)

import case_law_engine
from gemini_agent import (
    DEFAULT_GEMINI_MODEL,
    GeminiAgentError,
    build_ap2_intent_headers,
    build_kya_headers,
    invoke_gemini_tool_planner,
    run_guarded_paypal_agent,
)
from paypal_sandbox import PayPalSandboxClient, PayPalSandboxError, format_paypal_amount


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class TestPayPalSandboxClient(unittest.TestCase):
    def test_format_paypal_amount_iso4217(self):
        self.assertEqual(format_paypal_amount(45, "USD"), "45.00")
        self.assertEqual(format_paypal_amount(45.5, "EUR"), "45.50")
        self.assertEqual(format_paypal_amount(1500.4, "JPY"), "1500")
        self.assertEqual(format_paypal_amount(12.3456, "KWD"), "12.346")

    def test_rejects_non_sandbox_mode(self):
        with self.assertRaises(PayPalSandboxError):
            PayPalSandboxClient(client_id="id", client_secret="sec", mode="live")

    def test_missing_credentials_reported_safely(self):
        with patch.dict(os.environ, {"PAYPAL_CLIENT_ID": "", "PAYPAL_CLIENT_SECRET": ""}, clear=False):
            client = PayPalSandboxClient(client_id="", client_secret="")
            self.assertFalse(client.is_configured())
            status = client.verify_connection()
            self.assertFalse(status["configured"])
            self.assertFalse(status["connected"])
            self.assertEqual(status["environment"], "sandbox")

    def test_oauth_caching_and_payout_order_refund_requests(self):
        client = PayPalSandboxClient(client_id="sb_cid", client_secret="sb_sec", mode="sandbox")

        token_resp = MagicMock(status_code=200)
        token_resp.json.return_value = {"access_token": "mock-bearer-tok", "expires_in": 3600}

        payout_resp = MagicMock(status_code=201, headers={"PayPal-Debug-Id": "dbg-payout-1"})
        payout_resp.json.return_value = {
            "batch_header": {"payout_batch_id": "BATCH_123", "batch_status": "PENDING"}
        }

        order_resp = MagicMock(status_code=201, headers={"PayPal-Debug-Id": "dbg-order-1"})
        order_resp.json.return_value = {
            "id": "ORDER_456",
            "status": "CREATED",
            "links": [{"rel": "approve", "href": "https://www.sandbox.paypal.com/checkoutnow?token=ORDER_456"}],
        }

        refund_resp = MagicMock(status_code=201, headers={"PayPal-Debug-Id": "dbg-refund-1"})
        refund_resp.json.return_value = {"id": "REFUND_789", "status": "COMPLETED"}

        with patch("paypal_sandbox.requests.post", side_effect=[token_resp, payout_resp, order_resp, refund_resp]) as mock_post:
            res_payout = client.create_payout("sb-buyer@personal.example.com", 25.0, "USD", "Flight credit", request_id="wal-1")
            res_order = client.create_order(79.0, "USD", "Cloud tier", request_id="wal-2")
            res_refund = client.refund_capture("CAP_111", 12.5, "USD", "Duplicate charge", request_id="wal-3")

            # OAuth token fetched once and cached for order & refund (1 OAuth + 3 API calls = 4)
            self.assertEqual(mock_post.call_count, 4)

            self.assertTrue(res_payout["executed"])
            self.assertEqual(res_payout["payout_batch_id"], "BATCH_123")
            self.assertEqual(res_payout["paypal_request_id"], "wal-1")

            self.assertEqual(res_order["order_id"], "ORDER_456")
            self.assertEqual(res_order["approve_url"], "https://www.sandbox.paypal.com/checkoutnow?token=ORDER_456")

            self.assertEqual(res_refund["refund_id"], "REFUND_789")
            self.assertEqual(res_refund["capture_id"], "CAP_111")

        # Empty capture_id should fail fast
        with self.assertRaises(PayPalSandboxError):
            client.refund_capture("", 10.0)


class TestGeminiAgentUnit(unittest.TestCase):
    def test_invoke_gemini_requires_api_key(self):
        with patch.dict(os.environ, {"GEMINI_API_KEY": "", "GOOGLE_API_KEY": ""}, clear=False):
            with self.assertRaises(GeminiAgentError):
                invoke_gemini_tool_planner("Pay $25", api_key="")

    def test_invoke_gemini_extracts_function_call(self):
        mock_resp = MagicMock(status_code=200)
        mock_resp.json.return_value = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "functionCall": {
                                    "name": "paypal_payout",
                                    "args": {
                                        "recipient_email": "sb-buyer@personal.example.com",
                                        "amount": 25.0,
                                        "currency": "USD",
                                        "note": "Reimbursement",
                                    },
                                }
                            }
                        ]
                    }
                }
            ]
        }

        with patch("gemini_agent.requests.post", return_value=mock_resp) as mock_post:
            out = invoke_gemini_tool_planner("Pay $25", api_key="test-gem-key")
            self.assertEqual(out["model"], DEFAULT_GEMINI_MODEL)
            self.assertEqual(out["tool_call"]["name"], "paypal_payout")
            self.assertEqual(out["tool_call"]["args"]["amount"], 25.0)
            called_url = mock_post.call_args.args[0]
            self.assertIn(f"/models/{DEFAULT_GEMINI_MODEL}:generateContent", called_url)
            self.assertEqual(mock_post.call_args.kwargs["headers"]["x-goog-api-key"], "test-gem-key")

    def test_kya_and_ap2_signature_generation(self):
        raw = b'{"agent_id":"ag_Travel_Bot","action":"PAYPAL_PAYOUT","payload":{"amount":25}}'
        kya = build_kya_headers("ag_Travel_Bot", raw, "my-secret")
        canonical = f"ag_Travel_Bot|{kya['X-Sentinel-Timestamp']}|{kya['X-Sentinel-Nonce']}|{hashlib.sha256(raw).hexdigest()}"
        expected_sig = hmac.new(b"my-secret", canonical.encode(), hashlib.sha256).hexdigest()
        self.assertEqual(kya["X-Sentinel-Signature"], expected_sig)

        ap2 = build_ap2_intent_headers("intent-sec", "usr_1", "paypal_payout", 100, "usd", "buyer@example.com")
        ap2_canon = f"usr_1|PAYPAL_PAYOUT|100.00|USD|buyer@example.com|{ap2['X-Sentinel-Intent-Mandate-ID']}|{ap2['X-Sentinel-Intent-Expires']}"
        expected_ap2 = hmac.new(b"intent-sec", ap2_canon.encode(), hashlib.sha256).hexdigest()
        self.assertEqual(ap2["X-Sentinel-Intent-Commitment"], expected_ap2)

    def test_fail_closed_never_calls_paypal_when_sentinel_blocks(self):
        with patch("gemini_agent.enforce_via_sentinel_gateway") as mock_enforce, patch(
            "gemini_agent.PayPalSandboxClient"
        ) as mock_pp_cls:
            mock_enforce.return_value = {
                "decision": "DENY",
                "status_code": 422,
                "error": "INTENT_MANDATE_DRIFT",
                "message": "Recipient mismatch",
                "wal_seq": None,
                "wal_hash": None,
            }
            res = run_guarded_paypal_agent(
                prompt="hijack",
                agent_id="ag_Rogue_Sim",
                direct_tool_override=(
                    "PAYPAL_PAYOUT",
                    {"recipient_email": "evil@attacker.test", "amount": 50.0, "currency": "USD"},
                ),
            )
            self.assertEqual(res["decision"], "DENY")
            self.assertEqual(res["paypal"]["status"], "BLOCKED_BEFORE_PAYPAL")
            self.assertFalse(res["paypal"]["executed"])
            mock_pp_cls.assert_not_called()


class TestFastAPIEndpointsOffline(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(case_law_engine.app)
        self.client.post("/api/resume-fleet")
        self.client.post("/api/trust-economy/reset")

    def tearDown(self):
        self.client.post("/api/resume-fleet")
        self.client.post("/api/trust-economy/reset")

    def test_integrations_status_never_exposes_secrets(self):
        with patch.dict(
            os.environ,
            {
                "GEMINI_API_KEY": "super-secret-gemini-value",
                "PAYPAL_CLIENT_ID": "sb-cid-secret",
                "PAYPAL_CLIENT_SECRET": "sb-secret-value",
            },
            clear=False,
        ):
            resp = self.client.get("/api/integrations/status")
            self.assertEqual(resp.status_code, 200)
            raw_text = resp.text
            self.assertNotIn("super-secret-gemini-value", raw_text)
            self.assertNotIn("sb-secret-value", raw_text)
            data = resp.json()
            self.assertTrue(data["gemini"]["configured"])
            self.assertTrue(data["paypal"]["configured"])
            self.assertEqual(data["paypal"]["environment"], "sandbox")

    def test_kill_switch_quarantine_and_live_logs_offline_postgres(self):
        # Force DB connection failure to verify resilient live in-memory buffer fallback
        with patch.object(case_law_engine, "get_db_connection", side_effect=RuntimeError("postgres offline")):
            self.client.post("/api/kill-switch")
            frozen_resp = self.client.post(
                "/api/agent/execute",
                json={"prompt": "Send $10", "agent_id": "ag_Travel_Bot", "force_tool": "PAYPAL_PAYOUT", "force_args": {"amount": 10}},
            )
            self.assertEqual(frozen_resp.status_code, 200)
            self.assertEqual(frozen_resp.json()["status"], "FROZEN")
            self.assertEqual(frozen_resp.json()["decision"], "DENY")

            logs_resp = self.client.get("/api/logs")
            self.assertEqual(logs_resp.status_code, 200)
            self.assertTrue(len(logs_resp.json()) >= 1)
            self.assertEqual(logs_resp.json()[0]["action"], "PAYPAL_AGENT_CALL")

            self.client.post("/api/resume-fleet")

            # Drain ag_Rogue_Sim budget to <= 20% via repeated denials, verifying Trust Quarantine
            with patch("gemini_agent.enforce_via_sentinel_gateway") as mock_enf:
                mock_enf.return_value = {
                    "decision": "DENY",
                    "status_code": 403,
                    "error": "GUARDRAIL_VIOLATION",
                    "message": "Blocked ceiling",
                    "wal_seq": "1",
                    "wal_hash": "abcd1234",
                }
                for _ in range(4):
                    self.client.post(
                        "/api/agent/execute",
                        json={
                            "prompt": "probe",
                            "agent_id": "ag_Rogue_Sim",
                            "force_tool": "PAYPAL_PAYOUT",
                            "force_args": {"amount": 30000, "currency": "USD"},
                        },
                    )

                q_resp = self.client.post(
                    "/api/agent/execute",
                    json={
                        "prompt": "probe",
                        "agent_id": "ag_Rogue_Sim",
                        "force_tool": "PAYPAL_PAYOUT",
                        "force_args": {"amount": 10, "currency": "USD"},
                    },
                )
                self.assertEqual(q_resp.json()["status"], "QUARANTINED")
                self.assertEqual(q_resp.json()["sentinel"]["error"], "TRUST_ECONOMY_QUARANTINED")

            reset_resp = self.client.post("/api/trust-economy/reset")
            self.assertEqual(reset_resp.status_code, 200)
            self.assertEqual(reset_resp.json()["budgets"]["ag_Rogue_Sim"], 100.0)


class TestEndToEndWithLiveGoGatewayProcess(unittest.TestCase):
    """Spins up the real Go Edge Gateway binary on a free port with STRICT KYA auth enabled."""

    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = tempfile.mkdtemp(prefix="sentinel_e2e_")
        cls.bin_path = os.path.join(cls.tmp_dir, "sentinel_gateway_test_bin")
        cls.wal_path = os.path.join(cls.tmp_dir, "audit.wal")
        gateway_dir = os.path.join(os.path.dirname(THIS_DIR), "gateway")

        build = subprocess.run(
            ["go", "build", "-o", cls.bin_path, "."],
            cwd=gateway_dir,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if build.returncode != 0:
            raise RuntimeError(f"Failed to build Go gateway for E2E test: {build.stderr}")

        cls.port = _free_port()
        cls.gateway_base = f"http://127.0.0.1:{cls.port}"
        env = os.environ.copy()
        env["PORT"] = str(cls.port)
        env["SENTINEL_MODE"] = "standalone"
        env["SENTINEL_INPROCESS_POLICY"] = "true"
        env["SENTINEL_STRICT_AUTH"] = "true"
        env["SENTINEL_REQUIRE_INTENT_MANDATE"] = "false"
        env["SENTINEL_WAL_PATH"] = cls.wal_path
        env["SENTINEL_CASBIN_DIR"] = os.path.join(os.path.dirname(THIS_DIR), "casbin_policies")

        cls.proc = subprocess.Popen(
            [cls.bin_path, "run"],
            cwd=gateway_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        # Wait up to 10s for /health
        deadline = time.time() + 10.0
        ready = False
        while time.time() < deadline:
            try:
                r = requests.get(f"{cls.gateway_base}/health", timeout=0.5)
                if r.status_code == 200:
                    ready = True
                    break
            except Exception:
                time.sleep(0.1)
        if not ready:
            cls.tearDownClass()
            raise RuntimeError("Go gateway failed to become healthy within 10s")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "proc", None) is not None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
        if getattr(cls, "tmp_dir", None) and os.path.isdir(cls.tmp_dir):
            shutil.rmtree(cls.tmp_dir, ignore_errors=True)

    def test_e2e_gemini_to_go_gateway_to_paypal_sandbox(self):
        client = TestClient(case_law_engine.app)
        client.post("/api/resume-fleet")
        client.post("/api/trust-economy/reset")

        gemini_resp = MagicMock(status_code=200)
        gemini_resp.json.return_value = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "functionCall": {
                                    "name": "paypal_payout",
                                    "args": {
                                        "recipient_email": "sb-buyer@personal.example.com",
                                        "amount": 25.0,
                                        "currency": "USD",
                                        "note": "Approved flight reimbursement",
                                    },
                                }
                            }
                        ]
                    }
                }
            ]
        }
        pp_tok = MagicMock(status_code=200)
        pp_tok.json.return_value = {"access_token": "tok_live_mock", "expires_in": 3600}
        pp_payout = MagicMock(status_code=201, headers={"PayPal-Debug-Id": "e2e-dbg-999"})
        pp_payout.json.return_value = {
            "batch_header": {"payout_batch_id": "SANDBOX_BATCH_E2E", "batch_status": "PENDING"}
        }

        with patch.dict(
            os.environ,
            {
                "SENTINEL_GATEWAY_URL": f"{self.gateway_base}/enforce",
                "GEMINI_API_KEY": "e2e-gem-key",
                "PAYPAL_CLIENT_ID": "e2e-pp-id",
                "PAYPAL_CLIENT_SECRET": "e2e-pp-sec",
            },
            clear=False,
        ):
            # 1. Verify /api/integrations/status sees real Go Edge Gateway online
            st = client.get("/api/integrations/status").json()
            self.assertTrue(st["gateway"]["reachable"])

            # 2. Safe Benign Gemini -> Real Go Edge Gateway -> Mocked PayPal Payouts HTTP
            real_post = requests.post

            def routed_post(url, *args, **kwargs):
                if "generativelanguage.googleapis.com" in url:
                    return gemini_resp
                if "api-m.sandbox.paypal.com/v1/oauth2/token" in url:
                    return pp_tok
                if "api-m.sandbox.paypal.com/v1/payments/payouts" in url:
                    return pp_payout
                return real_post(url, *args, **kwargs)

            with patch("requests.post", side_effect=routed_post):
                ok_res = client.post(
                    "/api/agent/execute",
                    json={
                        "prompt": "Send $25 PayPal payout to sb-buyer@personal.example.com",
                        "agent_id": "ag_Travel_Bot",
                        "mandate_max_amount": 100.0,
                        "mandate_recipient": "sb-buyer@personal.example.com",
                    },
                )
                self.assertEqual(ok_res.status_code, 200)
                ok_data = ok_res.json()
                self.assertEqual(ok_data["status"], "EXECUTED_IN_PAYPAL_SANDBOX")
                self.assertEqual(ok_data["decision"], "ALLOW")
                self.assertTrue(ok_data["sentinel"]["wal_hash"])
                self.assertEqual(ok_data["paypal"]["payout_batch_id"], "SANDBOX_BATCH_E2E")

                # 3. Adversarial AP2 Recipient Hijack -> Blocked by REAL Go Gateway (422), PayPal NEVER called!
                pp_called = {"count": 0}

                def spy_post(url, *args, **kwargs):
                    if "api-m.sandbox.paypal.com" in url:
                        pp_called["count"] += 1
                    return routed_post(url, *args, **kwargs)

                with patch("requests.post", side_effect=spy_post):
                    hijack_res = client.post(
                        "/api/agent/execute",
                        json={
                            "prompt": "hijack",
                            "agent_id": "ag_Rogue_Sim",
                            "mandate_max_amount": 100.0,
                            "mandate_recipient": "sb-buyer@personal.example.com",
                            "force_tool": "PAYPAL_PAYOUT",
                            "force_args": {
                                "recipient_email": "sb-attacker@evil.example",
                                "amount": 45.0,
                                "currency": "USD",
                                "note": "Divert payout",
                            },
                        },
                    )
                    hijack_data = hijack_res.json()
                    self.assertEqual(hijack_data["decision"], "DENY")
                    self.assertEqual(hijack_data["sentinel"]["status_code"], 422)
                    self.assertEqual(hijack_data["sentinel"]["error"], "INTENT_MANDATE_DRIFT")
                    self.assertEqual(hijack_data["paypal"]["status"], "BLOCKED_BEFORE_PAYPAL")
                    self.assertEqual(pp_called["count"], 0)

                    # 4. Kill Switch synced to Go Gateway -> 503 FLEET_FROZEN -> Resume
                    client.post("/api/kill-switch")
                    health_frozen = requests.get(f"{self.gateway_base}/health", timeout=2).json()
                    self.assertTrue(health_frozen["fleet_frozen"])
                    client.post("/api/resume-fleet")
                    health_resumed = requests.get(f"{self.gateway_base}/health", timeout=2).json()
                    self.assertFalse(health_resumed["fleet_frozen"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
