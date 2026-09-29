"""
Acceptance Test Suite for AI Chat v3.0 Phase 1.

Validates the complete end-to-end migration and server lifecycle:
1. Migration from real v2 DB to v3 schema with full relational mapping.
2. FastMCP schema pruning (32 parameters removed from published tool schemas).
3. Agent authentication via Authorization: Bearer <aic_token>, room filtering, and message sending.
4. Human login via scrypt password, mandatory password change enforcement, and admin privileges.
5. Central authorization (authorize) across REST, MCP, and WebSockets.
6. Safeguards: archived room rejection, last admin deactivation protection, and IP brute-force lockout.
"""
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "migrations" / "v3"))

import migrate_v2_to_v3 as mig
from aichat.storage import ChatStorage
from aichat.web_app import create_app
from aichat.mcp_server import (
    hub,
    mcp,
    current_auth_token,
    current_principal,
    _authenticate,
    list_my_rooms as tool_list_my_rooms,
    read_messages as tool_read_messages,
    send_message as tool_send_message,
    create_room as tool_create_room,
)


class TestV3Phase1Acceptance(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.src_path = cls.tmp / "chat_v2.db"
        cls.logs_dir = cls.tmp / "logs"

        # 1. Build authentic v2 database using v2 ChatStorage
        v2_st = ChatStorage(db_path=cls.src_path, logs_dir=cls.logs_dir)
        v2_st.create_room("geral", topic="Sala aberta geral")
        v2_st.create_room(
            "privada",
            password_hash="pwd_hash_v2",
            salt="salt_v2",
            is_protected=True,
            clear_password="SecretPrivadaPassword123",
        )
        v2_st.create_room("arquivada", topic="Sala a ser arquivada")

        cls.v2_tokens = {}
        for name in ["Claude-Dev", "Worker-1", "Sentinel"]:
            is_sys = (name == "Sentinel")
            cls.v2_tokens[name] = v2_st.register_agent_admin(callsign=name, is_system=is_sys).get("token", "")

        # Membership: Claude-Dev has access to geral & privada; Worker-1 only to geral
        v2_st.add_or_update_member("geral", "Claude-Dev", "agent")
        v2_st.add_or_update_member("privada", "Claude-Dev", "agent")
        v2_st.add_or_update_member("geral", "Worker-1", "agent")

        # Add initial messages
        v2_st.add_message("geral", "Rui", "human", "Bem-vindos ao chat v2!", is_verified=True)
        v2_st.add_message("geral", "Claude-Dev", "agent", "Olá equipa!", is_verified=True)
        v2_st.add_message("privada", "Claude-Dev", "agent", "Conversa confidencial", is_verified=True)

        # Archive room
        v2_st.archive_room("arquivada")
        v2_st.close()

        # 2. Run non-destructive migration to v3
        cls.out_dir = cls.tmp / "migration_out"
        cls.dst_path = cls.tmp / "chat_v3.db"
        rc = mig.main([
            "--source", str(cls.src_path),
            "--target", str(cls.dst_path),
            "--admin-username", "Rui",
            "--out-dir", str(cls.out_dir),
        ])
        assert rc == 0, "Migration returned non-zero exit code"

        # Read generated credentials
        creds_file = next(cls.out_dir.glob("credentials_*.txt"))
        creds_text = creds_file.read_text(encoding="utf-8")
        cls.creds_text = creds_text

        # Extract admin password and agent tokens
        cls.admin_username = "Rui"
        cls.admin_init_pwd = None
        cls.agent_tokens = {}
        for line in creds_text.splitlines():
            line_s = line.strip()
            if line_s.startswith("Admin initial password:"):
                cls.admin_init_pwd = line_s.split("Admin initial password:")[1].split("(")[0].strip()
            elif line_s.startswith("Claude-Dev"):
                cls.agent_tokens["Claude-Dev"] = line_s.split()[-1].strip()
            elif line_s.startswith("Worker-1"):
                cls.agent_tokens["Worker-1"] = line_s.split()[-1].strip()
            elif line_s.startswith("Sentinel"):
                cls.agent_tokens["Sentinel"] = line_s.split()[-1].strip()

        assert cls.admin_init_pwd, "Initial admin password not found in credentials file"
        assert "Claude-Dev" in cls.agent_tokens, "Claude-Dev token not found"
        assert "Worker-1" in cls.agent_tokens, "Worker-1 token not found"

        # 3. Mount v3 storage into global hub and create Starlette app
        cls.orig_storage = hub.storage
        cls.test_storage = ChatStorage(db_path=cls.dst_path, logs_dir=cls.logs_dir)
        assert cls.test_storage.is_v3(), "ChatStorage must be in v3 mode for migrated database"
        hub.storage = cls.test_storage

        os.environ["AICHAT_TESTING"] = "1"
        cls.app = create_app()
        cls.client = TestClient(cls.app)

    @classmethod
    def tearDownClass(cls):
        hub.storage.close()
        hub.storage = cls.orig_storage
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_01_schema_v3_contract_and_integrity(self):
        """Verifies v3 schema contract: IDs, principals, and schema_version."""
        self.assertTrue(self.test_storage.is_v3())
        conn = sqlite3.connect(self.dst_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        ver = cur.execute("SELECT version FROM schema_version;").fetchone()
        self.assertEqual(ver["version"], 3)

        # Rui is admin
        rui = cur.execute("SELECT * FROM principals WHERE name = 'Rui';").fetchone()
        self.assertIsNotNone(rui)
        self.assertEqual(rui["kind"], "human")
        human_row = cur.execute("SELECT * FROM humans WHERE principal_id = ?;", (rui["id"],)).fetchone()
        self.assertEqual(human_row["access_role"], "admin")
        self.assertEqual(human_row["must_change_password"], 1)

        # Agents
        dev = cur.execute("SELECT * FROM principals WHERE name = 'Claude-Dev';").fetchone()
        self.assertIsNotNone(dev)
        self.assertEqual(dev["kind"], "agent")
        worker = cur.execute("SELECT * FROM principals WHERE name = 'Worker-1';").fetchone()
        self.assertIsNotNone(worker)
        self.assertEqual(worker["kind"], "agent")

        # Room access
        grants = cur.execute(
            """
            SELECT p.name AS p_name, r.name AS r_name
            FROM room_access ra
            JOIN principals p ON ra.principal_id = p.id
            JOIN rooms r ON ra.room_id = r.id;
            """
        ).fetchall()
        grant_pairs = {(g["p_name"], g["r_name"]) for g in grants}
        self.assertIn(("Claude-Dev", "geral"), grant_pairs)
        self.assertIn(("Claude-Dev", "privada"), grant_pairs)
        self.assertIn(("Worker-1", "geral"), grant_pairs)
        self.assertNotIn(("Worker-1", "privada"), grant_pairs)
        conn.close()

    def test_02_fastmcp_schema_pruning(self):
        """Verifies all 32 parameters (agent_token, sender_name, etc.) are pruned from MCP tool schemas."""
        pruned_keys = {"agent_token", "sender_name", "agent_name", "member_token"}
        tools = mcp._tool_manager.list_tools()
        for t in tools:
            props = t.parameters.get("properties", {})
            for key in pruned_keys:
                self.assertNotIn(
                    key,
                    props,
                    f"Tool '{t.name}' still exposes parameter '{key}' in its public schema",
                )

    def test_03_agent_bearer_token_and_room_filtering(self):
        """Verifies agents authenticate via Bearer token and see only permitted rooms."""
        # Unauthenticated request -> 401
        res_no_auth = self.client.get("/api/rooms")
        self.assertEqual(res_no_auth.status_code, 401)

        # Worker-1 only has access to 'geral'
        worker_tok = self.agent_tokens["Worker-1"]
        res_w1 = self.client.get("/api/rooms", headers={"Authorization": f"Bearer {worker_tok}"})
        self.assertEqual(res_w1.status_code, 200)
        w1_rooms = [r["name"] for r in res_w1.json()]
        self.assertIn("geral", w1_rooms)
        self.assertNotIn("privada", w1_rooms)

        # Claude-Dev has access to 'geral' and 'privada'
        dev_tok = self.agent_tokens["Claude-Dev"]
        res_dev = self.client.get("/api/rooms", headers={"Authorization": f"Bearer {dev_tok}"})
        self.assertEqual(res_dev.status_code, 200)
        dev_rooms = [r["name"] for r in res_dev.json()]
        self.assertIn("geral", dev_rooms)
        self.assertIn("privada", dev_rooms)

    def test_04_agent_message_post_and_authorization(self):
        """Verifies agent message posting permissions and identity attribution."""
        worker_tok = self.agent_tokens["Worker-1"]
        dev_tok = self.agent_tokens["Claude-Dev"]

        # Worker-1 posting to 'privada' (unauthorized) -> 403
        res_w1_priv = self.client.post(
            "/api/rooms/privada/messages",
            headers={"Authorization": f"Bearer {worker_tok}"},
            json={"content": "Tentativa não autorizada"},
        )
        self.assertEqual(res_w1_priv.status_code, 403)

        # Worker-1 posting to 'geral' (authorized) -> 201
        res_w1_geral = self.client.post(
            "/api/rooms/geral/messages",
            headers={"Authorization": f"Bearer {worker_tok}"},
            json={"content": "Mensagem válida do Worker-1"},
        )
        self.assertEqual(res_w1_geral.status_code, 201)
        data = res_w1_geral.json()
        self.assertEqual(data["sender"], "Worker-1")
        self.assertEqual(data["role"], "agent")
        self.assertTrue(data["is_verified"])

        # Agent posting to archived room -> 400
        res_archived = self.client.post(
            "/api/rooms/arquivada/messages",
            headers={"Authorization": f"Bearer {dev_tok}"},
            json={"content": "Tentativa de escrita em sala arquivada"},
        )
        self.assertEqual(res_archived.status_code, 400)
        self.assertIn("arquivada", res_archived.json()["error"].lower())

        # Agent cannot create rooms (admin only) -> 403
        res_create = self.client.post(
            "/api/rooms",
            headers={"Authorization": f"Bearer {dev_tok}"},
            json={"name": "sala-do-agente", "topic": "teste"},
        )
        self.assertEqual(res_create.status_code, 403)

    def test_05_human_login_and_mandatory_password_change_lifecycle(self):
        """Verifies human login, must_change_password enforcement, password change, and admin access."""
        # 1. Invalid credentials -> 401
        bad_login = self.client.post(
            "/api/auth/login",
            json={"username": "Rui", "password": "WrongPassword123!"},
        )
        self.assertEqual(bad_login.status_code, 401)
        self.assertEqual(bad_login.json()["error"], "Credenciais inválidas")

        # 2. Login with initial admin password -> 200, must_change_password: True
        client_human = TestClient(self.app)
        ok_login = client_human.post(
            "/api/auth/login",
            json={"username": "Rui", "password": self.admin_init_pwd},
        )
        self.assertEqual(ok_login.status_code, 200)
        self.assertTrue(ok_login.json()["must_change_password"])
        self.assertIn("human_session", ok_login.headers.get("set-cookie", ""))

        # 3. Attempting to access protected endpoint while must_change_password is active -> 403
        blocked = client_human.get("/api/rooms")
        self.assertEqual(blocked.status_code, 403)
        self.assertTrue(blocked.json().get("must_change_password"))

        # 4. Mandatory password change endpoint: invalid new password (< 8 chars) -> 400
        short_pwd = client_human.post(
            "/api/auth/change-password",
            json={"new_password": "short"},
        )
        self.assertEqual(short_pwd.status_code, 400)

        # 5. Successful password change
        new_pwd = "NewAdminPassword2026!#"
        change_ok = client_human.post(
            "/api/auth/change-password",
            json={"new_password": new_pwd},
        )
        self.assertEqual(change_ok.status_code, 200)
        self.assertTrue(change_ok.json()["success"])

        # 6. Now /api/rooms is fully accessible
        rooms_resp = client_human.get("/api/rooms")
        self.assertEqual(rooms_resp.status_code, 200)
        all_rooms = [r["name"] for r in rooms_resp.json()]
        self.assertIn("geral", all_rooms)
        self.assertIn("privada", all_rooms)

        # 7. Admin creates new room -> 201
        create_resp = client_human.post(
            "/api/rooms",
            json={"name": "sala-estrategia-v3", "topic": "Sala criada pelo admin"},
        )
        self.assertEqual(create_resp.status_code, 201)
        self.assertEqual(create_resp.json()["name"], "sala-estrategia-v3")

        # 8. Logout
        logout_resp = client_human.post("/api/auth/logout")
        self.assertEqual(logout_resp.status_code, 200)
        after_logout = client_human.get("/api/rooms")
        self.assertEqual(after_logout.status_code, 401)

        # 9. Login with new password
        login_new = client_human.post(
            "/api/auth/login",
            json={"username": "Rui", "password": new_pwd},
        )
        self.assertEqual(login_new.status_code, 200)
        self.assertFalse(login_new.json()["must_change_password"])

    async def test_06_fastmcp_central_auth_and_read_cursor(self):
        """Verifies FastMCP tools authenticate via context and update read cursors."""
        worker_tok = self.agent_tokens["Worker-1"]
        dev_tok = self.agent_tokens["Claude-Dev"]

        # Worker-1 tries to read 'privada' via MCP tool -> error
        t_work = current_auth_token.set(worker_tok)
        try:
            priv_read = json.loads(tool_read_messages("privada"))
            self.assertEqual(priv_read["status"], "error")
            self.assertIn("Access denied", priv_read["error"])

            # Worker-1 reads 'geral' -> success
            geral_read = json.loads(tool_read_messages("geral"))
            self.assertEqual(geral_read["status"], "success")
            self.assertGreater(len(geral_read["messages"]), 0)

            # Check cursor updated
            conn = self.test_storage.v3._get_connection()
            w1_p = self.test_storage.v3.get_principal_by_name("Worker-1")
            room_g = self.test_storage.v3.get_room("geral")
            cur_pos = self.test_storage.v3.get_read_cursor(w1_p["id"], "geral")
            self.assertIsNotNone(cur_pos)
            self.assertGreaterEqual(cur_pos, geral_read["messages"][-1]["id"])
        finally:
            current_auth_token.reset(t_work)

        # Claude-Dev sends message to 'privada' via MCP tool -> success
        t_dev = current_auth_token.set(dev_tok)
        try:
            send_res = json.loads(await tool_send_message("privada", content="Atualização confidencial"))
            self.assertEqual(send_res["status"], "success")
            self.assertTrue(send_res["is_verified"])
        finally:
            current_auth_token.reset(t_dev)

    def test_07_websocket_authorization_rules(self):
        """Verifies WebSocket endpoint validates token and room authorization."""
        worker_tok = self.agent_tokens["Worker-1"]
        dev_tok = self.agent_tokens["Claude-Dev"]

        # Unauthenticated WebSocket rejected -> 4401
        with self.assertRaises(WebSocketDisconnect) as cm_no_auth:
            with self.client.websocket_connect("/ws/geral"):
                pass
        self.assertEqual(cm_no_auth.exception.code, 4401)

        # Worker-1 unauthorized to connect to /ws/privada -> 4403
        with self.assertRaises(WebSocketDisconnect) as cm_unauth:
            with self.client.websocket_connect(
                "/ws/privada",
                headers={"Authorization": f"Bearer {worker_tok}"},
            ):
                pass
        self.assertEqual(cm_unauth.exception.code, 4403)

        # Worker-1 authorized to connect to /ws/geral -> 200
        with self.client.websocket_connect(
            "/ws/geral",
            headers={"Authorization": f"Bearer {worker_tok}"},
        ) as ws:
            ws.send_json({"type": "ping"})
            resp = {}
            for _ in range(5):
                msg = ws.receive_json()
                if msg.get("type") == "pong":
                    resp = msg
                    break
            self.assertEqual(resp.get("type"), "pong")

        # Claude-Dev authorized to connect to /ws/privada
        with self.client.websocket_connect(
            "/ws/privada",
            headers={"Authorization": f"Bearer {dev_tok}"},
        ) as ws_dev:
            ws_dev.send_json({"type": "ping"})
            resp_dev = {}
            for _ in range(5):
                msg = ws_dev.receive_json()
                if msg.get("type") == "pong":
                    resp_dev = msg
                    break
            self.assertEqual(resp_dev.get("type"), "pong")

    def test_08_core_safeguards(self):
        """Verifies last admin protection and IP brute-force lockout."""
        # 1. Last active admin cannot be deactivated or deleted
        rui_p = self.test_storage.v3.get_principal_by_name("Rui")
        with self.assertRaises(ValueError) as cm_admin:
            self.test_storage.v3.update_principal_status(rui_p["id"], "inactive")
        self.assertIn("administrador ativo", str(cm_admin.exception).lower())

        with self.assertRaises(ValueError) as cm_del:
            self.test_storage.v3.delete_principal(rui_p["id"])
        self.assertIn("administrador ativo", str(cm_del.exception).lower())

        # 2. IP rate limiting: 5 consecutive failed logins triggers lockout
        test_ip = "192.168.1.100"
        for i in range(4):
            res_bad = self.client.post(
                "/api/auth/login",
                headers={"X-Forwarded-For": test_ip},
                json={"username": "Rui", "password": f"wrong_{i}"},
            )
            self.assertEqual(res_bad.status_code, 401)

        # 5th attempt triggers lockout -> 429
        res_locked = self.client.post(
            "/api/auth/login",
            headers={"X-Forwarded-For": test_ip},
            json={"username": "Rui", "password": "wrong_5th"},
        )
        self.assertEqual(res_locked.status_code, 429)
        self.assertIn("temporariamente bloqueada", res_locked.json()["error"].lower())

    def test_09_server_env_token_isolation(self):
        """Verifies that AICHAT_AGENT_TOKEN on the server does NOT authenticate HTTP or MCP callers."""
        sentinel_tok = self.agent_tokens["Sentinel"]
        os.environ["AICHAT_AGENT_TOKEN"] = sentinel_tok

        try:
            # 1. Unauthenticated HTTP request to REST API must return 401
            res_rest = self.client.get("/api/rooms")
            self.assertEqual(res_rest.status_code, 401)

            # 2. Unauthenticated HTTP request to MCP /sse must return 401
            res_sse = self.client.get("/sse")
            self.assertEqual(res_sse.status_code, 401)

            # 3. Direct MCP _authenticate in HTTP context without contextvar must fail
            ident, err = _authenticate()
            self.assertIsNone(ident)
            self.assertIsNotNone(err)
            err_data = json.loads(err)
            self.assertEqual(err_data["status"], "error")
            self.assertIn("Missing Authorization header", err_data["error"])
        finally:
            os.environ.pop("AICHAT_AGENT_TOKEN", None)

    def test_10_rejection_of_deprecated_identity_arguments(self):
        """Verifies that passing identity arguments in MCP tool calls is strictly rejected in v3."""
        expected_msg = "No AI Chat v3, o envio de tokens ou nomes de identidade nos argumentos foi descontinuado. Configure o cabeçalho 'Authorization: Bearer <token>' na ligação MCP."

        # Passing agent_token
        ident, err = _authenticate(agent_token="some_token")
        self.assertIsNone(ident)
        self.assertIsNotNone(err)
        err_json = json.loads(err)
        self.assertEqual(err_json["error"], expected_msg)

        # Passing member_token
        ident, err = _authenticate(member_token="some_token")
        self.assertIsNone(ident)
        self.assertIsNotNone(err)
        err_json = json.loads(err)
        self.assertEqual(err_json["error"], expected_msg)

        # Passing expected_callsign
        ident, err = _authenticate(expected_callsign="Sentinel")
        self.assertIsNone(ident)
        self.assertIsNotNone(err)
        err_json = json.loads(err)
        self.assertEqual(err_json["error"], expected_msg)

    def test_11_rejection_of_url_query_param_tokens(self):
        """Verifies that query-string tokens are completely ignored and rejected in v3."""
        dev_tok = self.agent_tokens["Claude-Dev"]

        # 1. REST endpoints reject query tokens -> 401
        res1 = self.client.get(f"/api/rooms?agent_token={dev_tok}")
        self.assertEqual(res1.status_code, 401)

        res2 = self.client.get(f"/api/rooms?token={dev_tok}")
        self.assertEqual(res2.status_code, 401)

        res3 = self.client.get(f"/api/rooms?human_token={dev_tok}")
        self.assertEqual(res3.status_code, 401)

        # 2. WebSocket rejects query tokens -> 4401
        with self.assertRaises(WebSocketDisconnect) as cm_ws1:
            with self.client.websocket_connect(f"/ws/geral?agent_token={dev_tok}"):
                pass
        self.assertEqual(cm_ws1.exception.code, 4401)

        with self.assertRaises(WebSocketDisconnect) as cm_ws2:
            with self.client.websocket_connect(f"/ws/geral?token={dev_tok}"):
                pass
        self.assertEqual(cm_ws2.exception.code, 4401)

        # 3. But passing token in Authorization Bearer header succeeds -> 200
        res_ok = self.client.get("/api/rooms", headers={"Authorization": f"Bearer {dev_tok}"})
        self.assertEqual(res_ok.status_code, 200)


if __name__ == "__main__":
    unittest.main()
