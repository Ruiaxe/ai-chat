"""
Security Regression Test Suite for AI Chat Room MCP Server (v2.4).
Verifies all findings from the independent QA audit report (C1-C5, A1-A4, M1-M5).
"""
import asyncio
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from starlette.testclient import TestClient

from aichat.hub import ChatHub
from aichat.storage import ChatStorage
from aichat.web_app import create_app, safe_int


class TestSecurityAuditVulnerabilities(unittest.IsolatedAsyncioTestCase):
    """Regression test cases verifying security fixes for the QA audit report."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_security.db"
        self.logs_dir = Path(self.temp_dir) / "logs"
        self.storage = ChatStorage(db_path=self.db_path, logs_dir=self.logs_dir)
        self.hub = ChatHub(storage=self.storage)

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # --- C1: Human token security and auth endpoints ---
    def test_c1_token_security_and_auth_endpoints(self):
        """Verifies GET / does not leak token, and /api/auth/ endpoints work with persistent cookie."""
        from aichat.mcp_server import hub as global_hub
        orig_storage = global_hub.storage
        global_hub.storage = self.storage
        try:
            app = create_app()
            client = TestClient(app)

            # 1. GET / must not contain human_token in response body (HTML leak prevention)
            resp = client.get("/")
            self.assertEqual(resp.status_code, 200)
            self.assertNotIn(global_hub.human_token, resp.text)
            self.assertNotIn("window.__HUMAN_AUTH_TOKEN__", resp.text)

            # 2. GET /api/auth/status initially unauthenticated
            status_unauth = client.get("/api/auth/status")
            self.assertEqual(status_unauth.status_code, 200)
            self.assertFalse(status_unauth.json()["authenticated"])

            # 3. POST /api/auth/login with invalid token -> 401
            login_fail = client.post("/api/auth/login", json={"token": "wrong-token"})
            self.assertEqual(login_fail.status_code, 401)

            # 4. POST /api/auth/login with valid token -> 200 and sets persistent cookie
            login_ok = client.post("/api/auth/login", json={"token": global_hub.human_token})
            self.assertEqual(login_ok.status_code, 200)
            cookie_header = login_ok.headers.get("set-cookie", "")
            self.assertIn("human_session", cookie_header)
            self.assertIn("Max-Age=", cookie_header)

            # 5. Subsequent GET /api/auth/status with session is authenticated
            status_auth = client.get("/api/auth/status", cookies={"human_session": global_hub.human_token})
            self.assertEqual(status_auth.status_code, 200)
            self.assertTrue(status_auth.json()["authenticated"])

            # 6. POST /api/auth/logout clears session
            logout_resp = client.post("/api/auth/logout")
            self.assertEqual(logout_resp.status_code, 200)
        finally:
            global_hub.storage = orig_storage

    # --- C2: Human decision resolve authentication ---
    async def test_c2_resolve_decision_requires_human_auth(self):
        """HTTP endpoint /api/decisions/{id}/resolve must reject unauthenticated requests."""
        # Setup Starlette app with our test storage
        from aichat.mcp_server import hub as global_hub
        orig_storage = global_hub.storage
        global_hub.storage = self.storage
        try:
            app = create_app()
            client = TestClient(app)
            self.storage.create_room("dec-room")
            msg = self.storage.add_message(
                "dec-room", "Agent1", "agent", "Should we launch?",
                message_type="decision_request",
                metadata={"status": "pending", "options": ["Yes", "No"]},
            )
            # Unauthenticated attempt -> 403 Forbidden
            res_fail = client.post(
                f"/api/decisions/{msg['id']}/resolve",
                json={"decision": "Yes", "decider": "Mallory"},
            )
            self.assertEqual(res_fail.status_code, 403)
            # Verify status remained pending
            unresolved = self.storage.get_message_by_id(msg["id"])
            self.assertEqual(unresolved["metadata"]["status"], "pending")

            # Authenticated attempt with X-Human-Token -> 200 OK
            res_ok = client.post(
                f"/api/decisions/{msg['id']}/resolve",
                json={"decision": "Yes", "decider": "Rui"},
                headers={"X-Human-Token": global_hub.human_token},
            )
            self.assertEqual(res_ok.status_code, 200)
            resolved = self.storage.get_message_by_id(msg["id"])
            self.assertEqual(resolved["metadata"]["status"], "resolved")
            self.assertEqual(resolved["metadata"]["decision"], "Yes")
        finally:
            global_hub.storage = orig_storage

    # --- C3: Poll closure authorization and double-close prevention ---
    async def test_c3_close_poll_authorization_and_double_close(self):
        """Poll closer must be creator with valid member_token or authenticated human."""
        self.hub.create_room("poll-test-room")
        # Alice registers and creates poll
        alice_join = self.hub.join_room("poll-test-room", "Alice", role="agent")
        alice_token = alice_join["member_token"]
        poll = await self.hub.create_poll("poll-test-room", "Alice", "Deploy?", ["Yes", "No"], member_token=alice_token)
        poll_id = poll["id"]

        # Mallory attempts to close Alice's poll without token -> PermissionError
        with self.assertRaises(PermissionError):
            await self.hub.close_poll(poll_id, closer="Mallory", is_human=False, member_token="")

        # Mallory attempts to close impersonating Alice without token -> PermissionError
        with self.assertRaises(PermissionError):
            await self.hub.close_poll(poll_id, closer="Alice", is_human=False, member_token="")

        # Mallory attempts with wrong token -> PermissionError
        with self.assertRaises(PermissionError):
            await self.hub.close_poll(poll_id, closer="Alice", is_human=False, member_token="fake-token")

        # Alice closes with valid member_token -> success
        closed = await self.hub.close_poll(poll_id, closer="Alice", is_human=False, member_token=alice_token)
        self.assertTrue(closed["is_closed"])

        # Second close attempt -> ValueError (already closed)
        with self.assertRaises(ValueError) as ctx:
            await self.hub.close_poll(poll_id, closer="Alice", is_human=False, member_token=alice_token)
        self.assertIn("já se encontra encerrada", str(ctx.exception))

    # --- C4: join_room token stealing prevention ---
    def test_c4_join_room_prevents_token_stealing(self):
        """Calling join_room for an existing member without token must not leak the token."""
        self.hub.create_room("secure-zone")
        # VictimAgent registers and obtains token
        join1 = self.hub.join_room("secure-zone", "VictimAgent", role="agent")
        victim_token = join1["member_token"]
        self.assertTrue(len(victim_token) > 0)

        # Mallory calls join_room for VictimAgent without providing token -> PermissionError
        with self.assertRaises(PermissionError) as ctx:
            self.hub.join_room("secure-zone", "VictimAgent", role="agent", member_token="")
        self.assertIn("já está registado", str(ctx.exception))

        # Mallory calls join_room with wrong token -> PermissionError
        with self.assertRaises(PermissionError) as ctx:
            self.hub.join_room("secure-zone", "VictimAgent", role="agent", member_token="bad-token")
        self.assertIn("outro token", str(ctx.exception))

        # Legitimate VictimAgent calls join_room with correct token -> succeeds and matches token
        join_valid = self.hub.join_room("secure-zone", "VictimAgent", role="agent", member_token=victim_token)
        self.assertEqual(join_valid["member_token"], victim_token)

    # --- A1: WebSocket password protection ---
    def test_a1_websocket_password_validation(self):
        """WebSocket connection to password-protected room must reject unauthorized connections."""
        from aichat.mcp_server import hub as global_hub
        orig_storage = global_hub.storage
        global_hub.storage = self.storage
        try:
            self.hub.create_room("secret-ws-room", password="SuperSecretPassword")
            app = create_app()
            client = TestClient(app)

            # Connecting without password -> closes with 4403
            with self.assertRaises(Exception):
                with client.websocket_connect("/ws/secret-ws-room") as ws:
                    ws.receive_text()

            # Connecting with wrong password -> closes with 4403
            with self.assertRaises(Exception):
                with client.websocket_connect("/ws/secret-ws-room?password=wrong") as ws:
                    ws.receive_text()

            # Connecting with correct password -> succeeds
            with client.websocket_connect("/ws/secret-ws-room?password=SuperSecretPassword") as ws:
                ws.send_text(json.dumps({"type": "ping"}))
                resp = ws.receive_json()
                self.assertEqual(resp.get("type"), "pong")
        finally:
            global_hub.storage = orig_storage

    # --- A2: Room log file collision prevention ---
    def test_a2_room_log_file_id_indexing(self):
        """Rooms with names that sanitize identically must have distinct log files."""
        room1 = self.storage.create_room("project-alpha", topic="Alpha 1")
        # Create second room with punctuation or spaces that would sanitize to same name
        room2 = self.storage.create_room("project!alpha", topic="Alpha 2")

        file1 = self.storage.get_room_log_file(room1["name"])
        file2 = self.storage.get_room_log_file(room2["name"])
        # Log filenames must include room ID, guaranteeing uniqueness
        self.assertNotEqual(file1.name, file2.name)
        self.assertIn(f"room_{room1['id']}_", file1.name)
        self.assertIn(f"room_{room2['id']}_", file2.name)

    # --- A3: Cross-room reaction prevention ---
    async def test_a3_cross_room_reaction_prevented(self):
        """Reactions must verify the message strictly belongs to the specified room."""
        self.hub.create_room("room-a")
        self.hub.create_room("room-b")

        msg_a = await self.hub.send_message("room-a", "AgentA", "Message in A", role="agent")
        msg_id_a = msg_a["id"]

        # Attempt to react to msg_id_a while targeting room-b -> PermissionError
        with self.assertRaises(PermissionError) as ctx:
            await self.hub.toggle_reaction(msg_id_a, "room-b", "AgentB", "👍")
        self.assertIn("pertence à sala", str(ctx.exception))

        # Reacting in room-a -> succeeds
        res_ok = await self.hub.toggle_reaction(msg_id_a, "room-a", "AgentA", "👍")
        self.assertEqual(res_ok["action"], "added")

    # --- A4: Safe integer conversion helper ---
    def test_a4_safe_int_helper(self):
        """safe_int must parse valid ints, apply bounds, and never crash on bad inputs."""
        self.assertEqual(safe_int("42"), 42)
        self.assertEqual(safe_int("invalid", default=10), 10)
        self.assertEqual(safe_int(-5, min_val=0), 0)
        self.assertEqual(safe_int(2000, max_val=500), 500)
        self.assertEqual(safe_int(None, default=5), 5)

    # --- M1: Multi-room wait no dropped messages ---
    async def test_m1_multi_room_wait_collects_all_messages(self):
        """wait_for_new_messages across subscribed rooms returns all simultaneous messages."""
        self.hub.create_room("sub-room-1")
        self.hub.create_room("sub-room-2")
        self.hub.join_room("sub-room-1", "Subscriber", role="agent")
        self.hub.join_room("sub-room-2", "Subscriber", role="agent")

        wait_task = asyncio.create_task(
            self.hub.wait_for_new_messages("subscribed", agent_name="Subscriber", timeout_seconds=2.0)
        )
        await asyncio.sleep(0.05)

        # Post messages to both rooms nearly simultaneously
        await self.hub.send_message("sub-room-1", "Sender1", "Message 1", role="agent")
        await self.hub.send_message("sub-room-2", "Sender2", "Message 2", role="agent")

        result = await asyncio.wait_for(wait_task, timeout=2.0)
        self.assertEqual(result["status"], "new_messages")
        self.assertGreaterEqual(len(result["messages"]), 2)
        contents = [m["content"] for m in result["messages"]]
        self.assertIn("Message 1", contents)
        self.assertIn("Message 2", contents)

    # --- M5: Role normalization and homoglyph defense ---
    async def test_m5_role_normalization_and_human_check(self):
        """Role parameter with uppercase, whitespace, or homoglyphs cannot bypass human protection."""
        self.hub.create_room("defense-room")

        # Uppercase "HUMAN" without token -> PermissionError
        with self.assertRaises(PermissionError):
            await self.hub.send_message("defense-room", "Hacker", "content", role="HUMAN")

        # Mixed case " Human " without token -> PermissionError
        with self.assertRaises(PermissionError):
            await self.hub.send_message("defense-room", "Hacker", "content", role="  Human  ")

        # Normalization with valid human token -> verified
        msg = await self.hub.send_message(
            "defense-room", "HumanUser", "valid", role=" HUMAN ", human_token=self.hub.human_token
        )
        self.assertTrue(msg["is_verified"])
        self.assertEqual(msg["role"], "human")


if __name__ == "__main__":
    unittest.main()
