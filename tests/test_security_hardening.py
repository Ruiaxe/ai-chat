"""
Unit and integration tests for security hardening (D1 - D7).
Tests DNS rebinding protection, origin validation, Content-Type enforcement,
ephemeral one-time auth code login, session invalidation, and loopback host policy.
"""
import subprocess
import sys
import unittest
from pathlib import Path
import tempfile
import shutil

from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from aichat.hub import ChatHub
from aichat.storage import ChatStorage
from aichat.web_app import create_app
from aichat.mcp_server import hub as global_hub


class TestSecurityHardening(unittest.TestCase):
    """Verifies D1-D5 hardening measures."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_hardening.db"
        self.logs_dir = Path(self.temp_dir) / "logs"
        self.storage = ChatStorage(db_path=self.db_path, logs_dir=self.logs_dir)
        self.orig_storage = global_hub.storage
        global_hub.storage = self.storage

        self.app = create_app()
        self.client = TestClient(self.app, base_url="http://testserver")

    def tearDown(self):
        global_hub.storage = self.orig_storage
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # D1: DNS Rebinding Protection (TrustedHostMiddleware)
    def test_dns_rebinding_trusted_host_blocks_unauthorized_host(self):
        """Host headers not in allowed_hosts (127.0.0.1, localhost, testserver) receive 400 Bad Request."""
        # Malicious external domain
        resp_evil = self.client.get("/", headers={"Host": "evil.attacker.com"})
        self.assertEqual(resp_evil.status_code, 400)

        # Legitimate loopback / testserver hosts
        resp_testserver = self.client.get("/", headers={"Host": "testserver"})
        self.assertEqual(resp_testserver.status_code, 200)

        resp_localhost = self.client.get("/", headers={"Host": "localhost"})
        self.assertEqual(resp_localhost.status_code, 200)

        resp_loopback = self.client.get("/", headers={"Host": "127.0.0.1"})
        self.assertEqual(resp_loopback.status_code, 200)

    # D2: Origin Validation (SecurityHardeningMiddleware)
    def test_cross_origin_mutating_requests_blocked_with_403(self):
        """State-modifying requests with external or different-origin Origin header return 403."""
        # Evil attacker origin
        resp_evil = self.client.post(
            "/api/rooms",
            json={"name": "test-hack"},
            headers={"Origin": "http://evil.com"},
        )
        self.assertEqual(resp_evil.status_code, 403)
        self.assertIn("Cross-origin request rejected", resp_evil.text)

        # Different local port (e.g., local dev server running on port 5173)
        resp_port = self.client.post(
            "/api/rooms",
            json={"name": "test-hack"},
            headers={"Origin": "http://testserver:5173"},
        )
        self.assertEqual(resp_port.status_code, 403)

        # Valid matching origin is accepted
        resp_ok = self.client.post(
            "/api/rooms",
            json={"name": "valid-room"},
            headers={"Origin": "http://testserver"},
        )
        self.assertIn(resp_ok.status_code, [200, 201])

    # D2: Content-Type Enforcement on /api/
    def test_content_type_enforcement_returns_415(self):
        """Mutating /api/ requests with non-JSON content-type return 415 Unsupported Media Type."""
        # text/plain
        resp_text = self.client.post(
            "/api/rooms",
            content=b'{"name": "test"}',
            headers={"Content-Type": "text/plain"},
        )
        self.assertEqual(resp_text.status_code, 415)
        self.assertIn("expected application/json", resp_text.text)

        # application/x-www-form-urlencoded
        resp_form = self.client.post(
            "/api/rooms",
            content=b"name=test",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(resp_form.status_code, 415)

    # D2: WebSocket Origin Validation
    def test_websocket_cross_origin_blocked(self):
        """WebSocket connection with untrusted origin is rejected."""
        global_hub.create_room(name="ws-sec-room")
        with self.assertRaises(WebSocketDisconnect) as cm:
            with self.client.websocket_connect("/ws/ws-sec-room", headers={"Origin": "http://evil.attacker.com"}):
                pass
        self.assertEqual(cm.exception.code, 4403)

        # Valid origin connects cleanly
        with self.client.websocket_connect("/ws/ws-sec-room", headers={"Origin": "http://testserver"}) as ws:
            ws.send_json({"type": "ping"})
            # Connected without disconnect

    # D5: Ephemeral Single-Use Auth Code & Session Management
    def test_one_time_auth_code_and_session_cookie(self):
        """Ephemeral code sets HttpOnly SameSite=Strict cookie, invalidates after one use, and logout terminates session."""
        code = global_hub.generate_one_time_auth_code(expiry_seconds=300)

        # First visit with code -> 303 redirect to / and sets human_session cookie
        resp = self.client.get(f"/?auth={code}", follow_redirects=False)
        self.assertEqual(resp.status_code, 303)
        self.assertEqual(resp.headers.get("location"), "/")

        set_cookie = resp.headers.get("set-cookie", "")
        self.assertIn("human_session=", set_cookie)
        self.assertIn("httponly", set_cookie.lower())
        self.assertIn("samesite=strict", set_cookie.lower())

        # Extract session_id from cookie
        session_id = None
        for part in set_cookie.split(";"):
            if part.strip().startswith("human_session="):
                session_id = part.strip().split("=")[1]
                break
        self.assertIsNotNone(session_id)

        # Attempting to reuse the one-time code must fail (single-use)
        reused = global_hub.consume_one_time_code(code)
        self.assertFalse(reused)

        # Authenticated using session cookie
        auth_status = self.client.get("/api/auth/status", cookies={"human_session": session_id})
        self.assertEqual(auth_status.status_code, 200)
        self.assertTrue(auth_status.json()["authenticated"])

        # Logout terminates the session
        logout_resp = self.client.post("/api/auth/logout", cookies={"human_session": session_id})
        self.assertEqual(logout_resp.status_code, 200)

        # Check status again -> now unauthenticated
        auth_status_after = self.client.get("/api/auth/status", cookies={"human_session": session_id})
        self.assertEqual(auth_status_after.status_code, 200)
        self.assertFalse(auth_status_after.json()["authenticated"])

    # D4: Loopback Enforcement in run_server.py
    def test_run_server_refuses_non_loopback_host(self):
        """run_server.py exits with error code 1 when attempting to bind to non-loopback host without --allow-remote."""
        cmd = [sys.executable, "run_server.py", "--host", "0.0.0.0", "--no-browser"]
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(Path(__file__).resolve().parent.parent))
        self.assertEqual(result.returncode, 1)
        self.assertIn("ERRO DE SEGURANÇA", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
