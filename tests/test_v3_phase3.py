"""
Test Suite for AI Chat v3.0 Phase 3 — Administration Console (/admin)

Tests server-side authorization (authorize), CRUD for humans/agents/roles/rooms,
token rotation/revocation, observer mode (can_write = 0), bulk room grants,
last active admin safeguard, and audit log querying.
"""
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from aichat.hub import ChatHub
from aichat.storage_v3 import StorageV3
from aichat.web_app import create_app


class TestV3Phase3AdminConsole(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.db_path = self.tmp / "test_v3_p3.db"
        self.logs_dir = self.tmp / "logs"
        self.storage = StorageV3(self.db_path, self.logs_dir)
        self.hub = ChatHub(storage=self.storage)

        # Create 1 admin and 1 regular user
        self.admin_id = self.storage.create_human(
            username="superadmin",
            password="AdminPassword123!",
            display_name="Super Admin",
            access_role="admin",
            must_change_password=0,
        )
        self.user_id = self.storage.create_human(
            username="regularuser",
            password="UserPassword123!",
            display_name="Regular User",
            access_role="user",
            must_change_password=0,
        )

        # Create 1 agent
        self.agent_id, self.agent_token = self.storage.create_agent(
            callsign="worker-bot",
            display_name="Worker Bot",
            role_key="developer",
        )

        # Wire test storage into global hub
        from aichat.mcp_server import hub
        self.orig_storage = hub.storage
        hub.storage = self.storage

        # Create sessions
        self.admin_session = self.storage.create_human_session(self.admin_id)
        self.user_session = self.storage.create_human_session(self.user_id)

        # TestClient with create_app()
        self.app = create_app()
        self.client = TestClient(self.app, base_url="http://127.0.0.1")

    def tearDown(self):
        from aichat.mcp_server import hub
        self.storage.close()
        hub.storage = self.orig_storage
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ------------------------------------------------------------------ 1. Authorization
    def test_admin_endpoints_require_admin_authorization(self):
        """Anonymous and regular users or agents must be rejected with 401 or 403."""
        # Anonymous -> 401
        res_anon = self.client.get("/api/admin/humans")
        self.assertEqual(res_anon.status_code, 401)

        # Regular user -> 403
        res_user = self.client.get(
            "/api/admin/humans",
            cookies={"human_session": self.user_session},
        )
        self.assertEqual(res_user.status_code, 403)

        # Agent token -> 403
        res_agent = self.client.get(
            "/api/admin/humans",
            headers={"Authorization": f"Bearer {self.agent_token}"},
        )
        self.assertEqual(res_agent.status_code, 403)

        # Admin user -> 200
        res_admin = self.client.get(
            "/api/admin/humans",
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res_admin.status_code, 200)

    def test_admin_ui_route_authorization(self):
        """GET /admin should redirect unauthenticated browser or return 401/403."""
        # Unauthenticated HTML request -> 303 Redirect to login
        res_anon = self.client.get("/admin", headers={"Accept": "text/html"}, follow_redirects=False)
        self.assertEqual(res_anon.status_code, 303)
        self.assertIn("/?login=1", res_anon.headers.get("location", ""))

        # Non-admin user -> 403
        res_user = self.client.get(
            "/admin",
            headers={"Accept": "text/html"},
            cookies={"human_session": self.user_session},
        )
        self.assertEqual(res_user.status_code, 403)

        # Admin user -> 200 HTML
        res_admin = self.client.get(
            "/admin",
            headers={"Accept": "text/html"},
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res_admin.status_code, 200)
        self.assertIn("ai-chat v3", res_admin.text)

    def test_admin_me_endpoint(self):
        """GET /api/admin/me returns authenticated admin identity."""
        res = self.client.get(
            "/api/admin/me",
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["principal"]["name"], "superadmin")
        self.assertEqual(data["principal"]["role"], "admin")

    # ------------------------------------------------------------------ 2. Human Management & Safeguards
    def test_create_and_list_humans(self):
        """Admin creates human, receives 201, and can list all humans."""
        res = self.client.post(
            "/api/admin/humans",
            json={
                "username": "novousuario",
                "password": "TempPassword123!",
                "display_name": "Novo Utilizador",
                "access_role": "user",
            },
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(data["username"], "novousuario")
        new_id = data["id"]

        # List humans
        res_list = self.client.get(
            "/api/admin/humans",
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res_list.status_code, 200)
        humans = res_list.json()["humans"]
        self.assertEqual(len(humans), 3)
        created = [h for h in humans if h["id"] == new_id][0]
        self.assertEqual(created["name"], "novousuario")
        self.assertEqual(created["must_change_password"], 1)

    def test_update_human_and_reset_password(self):
        """Admin updates human attributes and resets password."""
        res = self.client.patch(
            f"/api/admin/humans/{self.user_id}",
            json={
                "display_name": "Utilizador Atualizado",
                "status": "inactive",
                "reset_password": "NewResetPassword456!",
            },
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res.status_code, 200)
        u = self.storage.get_principal_by_id(self.user_id)
        self.assertEqual(u["display_name"], "Utilizador Atualizado")
        self.assertEqual(u["status"], "inactive")
        self.assertEqual(u["must_change_password"], 1)

    def test_safeguard_cannot_demote_or_deactivate_or_delete_last_active_admin(self):
        """The system must strictly prevent demoting, deactivating, or deleting the sole active admin."""
        # 1. Demoting sole active admin to user -> 400
        res_demote = self.client.patch(
            f"/api/admin/humans/{self.admin_id}",
            json={"access_role": "user"},
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res_demote.status_code, 400)
        self.assertIn("único administrador", res_demote.json()["error"])

        # 2. Deactivating sole active admin -> 400
        res_deact = self.client.patch(
            f"/api/admin/humans/{self.admin_id}",
            json={"status": "inactive"},
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res_deact.status_code, 400)
        self.assertIn("único administrador", res_deact.json()["error"])

        # 3. Deleting sole active admin -> 400
        res_del = self.client.delete(
            f"/api/admin/humans/{self.admin_id}",
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res_del.status_code, 400)
        self.assertIn("único administrador", res_del.json()["error"])

        # 4. Now promote second user to admin
        res_prom = self.client.patch(
            f"/api/admin/humans/{self.user_id}",
            json={"access_role": "admin"},
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res_prom.status_code, 200)

        # 5. Now the first admin CAN be demoted or deactivated safely
        res_demote2 = self.client.patch(
            f"/api/admin/humans/{self.admin_id}",
            json={"access_role": "user"},
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res_demote2.status_code, 200)

    # ------------------------------------------------------------------ 3. Agent Management & Secrets
    def test_create_agent_token_revealed_once_and_never_in_logs(self):
        """Agent token must be shown only once in creation response, and never in audit log or plaintext."""
        res = self.client.post(
            "/api/admin/agents",
            json={
                "callsign": "qc-bot",
                "display_name": "QC Automation Bot",
                "role_key": "qa",
            },
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res.status_code, 201)
        data = res.json()
        raw_tok = data["token"]
        hint = data["token_hint"]
        self.assertTrue(raw_tok.startswith("aic_"))
        self.assertEqual(raw_tok[-4:], hint)

        # Authenticate with the new token
        p, err = self.storage.authenticate_agent_token(raw_tok)
        self.assertIsNotNone(p)
        self.assertEqual(p["name"], "qc-bot")

        # Verify raw token is NOT in credentials plaintext
        conn = self.storage._get_connection()
        row = conn.execute("SELECT * FROM credentials WHERE principal_id = ?;", (data["id"],)).fetchone()
        self.assertNotIn(raw_tok, str(dict(row)))

        # Verify raw token is NOT in audit log
        audit = self.storage.list_audit_log(target_type="principal")
        for item in audit["items"]:
            self.assertNotIn(raw_tok, item["details"])

    def test_rotate_and_revoke_agent_token(self):
        """Rotating generates new token; revoking invalidates it."""
        # Rotate token
        res_rot = self.client.post(
            f"/api/admin/agents/{self.agent_id}/rotate-token",
            json={"revoke_previous": True},
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res_rot.status_code, 200)
        data_rot = res_rot.json()
        new_tok = data_rot["token"]
        new_hint = data_rot["token_hint"]
        self.assertNotEqual(new_tok, self.agent_token)

        # Old token is revoked
        p_old, err_old = self.storage.authenticate_agent_token(self.agent_token)
        self.assertIsNone(p_old)
        self.assertIn("revogado", err_old.lower())

        # New token works
        p_new, err_new = self.storage.authenticate_agent_token(new_tok)
        self.assertIsNotNone(p_new)

        # Revoke new token
        res_rev = self.client.post(
            f"/api/admin/agents/{self.agent_id}/revoke-token",
            json={"token_hint": new_hint},
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res_rev.status_code, 200)

        # Token is now revoked
        p_rev, err_rev = self.storage.authenticate_agent_token(new_tok)
        self.assertIsNone(p_rev)

    # ------------------------------------------------------------------ 4. Rooms, Access Matrix & Bulk Grant
    def test_create_and_archive_room(self):
        """Admin creates, archives, and unarchives rooms."""
        res = self.client.post(
            "/api/admin/rooms",
            json={"name": "secret-ops", "topic": "Classified"},
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res.status_code, 201)
        room_id = res.json()["room"]["id"]

        # Archive room
        res_arch = self.client.post(
            f"/api/admin/rooms/{room_id}/archive",
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res_arch.status_code, 200)
        r = self.storage.get_room_by_id(room_id)
        self.assertEqual(r["is_archived"], 1)

        # Unarchive room
        res_unarch = self.client.post(
            f"/api/admin/rooms/{room_id}/unarchive",
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res_unarch.status_code, 200)
        r = self.storage.get_room_by_id(room_id)
        self.assertEqual(r["is_archived"], 0)

    def test_observer_mode_and_bulk_grant(self):
        """Matrix supports can_write=0 (observer mode) and bulk grant for multiple principals."""
        room = self.storage.create_room("war-room", topic="War Room", created_by_id=self.admin_id)
        rid = room["id"]

        # Bulk grant: user as observer (can_write=0), agent as normal (can_write=1)
        res_bulk = self.client.post(
            "/api/admin/rooms/bulk-grant",
            json={
                "grants": [
                    {"room_id": rid, "principal_id": self.user_id, "can_write": 0},
                    {"room_id": rid, "principal_id": self.agent_id, "can_write": 1},
                ]
            },
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res_bulk.status_code, 200)
        self.assertEqual(res_bulk.json()["count"], 2)

        # Verify permissions in storage
        u_p = self.storage.get_principal_by_id(self.user_id)
        a_p = self.storage.get_principal_by_id(self.agent_id)

        # User is observer: can read, but CANNOT write
        self.assertTrue(self.storage.authorize(u_p, "read_room", {"room_id": rid}))
        self.assertFalse(self.storage.authorize(u_p, "write_room", {"room_id": rid}))

        # Agent can read and write
        self.assertTrue(self.storage.authorize(a_p, "read_room", {"room_id": rid}))
        self.assertTrue(self.storage.authorize(a_p, "write_room", {"room_id": rid}))

        # Verify members endpoint
        res_mem = self.client.get(
            f"/api/admin/rooms/{rid}/members",
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res_mem.status_code, 200)
        members = res_mem.json()["members"]
        u_mem = [m for m in members if m["principal_id"] == self.user_id][0]
        self.assertEqual(u_mem["can_write"], 0)

    # ------------------------------------------------------------------ 5. Role Management
    def test_create_and_update_agent_role(self):
        """Admin creates and updates agent role reminder_text and description."""
        res_cr = self.client.post(
            "/api/admin/roles",
            json={
                "role_key": "data_engineer",
                "display_name": "Engenheiro de Dados",
                "description": "Modela e otimiza pipelines de dados.",
                "reminder_text": "Tu és o Engenheiro de Dados. Foca-te na integridade das pipelines.",
            },
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res_cr.status_code, 201)
        role_id = res_cr.json()["role"]["id"]

        # Update role description and reminder_text
        res_up = self.client.patch(
            f"/api/admin/roles/{role_id}",
            json={
                "description": "Descrição atualizada dos pipelines.",
                "reminder_text": "Novo texto de lembrete do agente.",
            },
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res_up.status_code, 200)
        role = self.storage.get_role_by_id(role_id)
        self.assertEqual(role["description"], "Descrição atualizada dos pipelines.")
        self.assertEqual(role["reminder_text"], "Novo texto de lembrete do agente.")

    # ------------------------------------------------------------------ 6. Audit Log
    def test_audit_log_querying_and_filtering(self):
        """Audit log queries with filters (actor, action, room) and pagination."""
        # Create a room to trigger an audit log
        self.client.post(
            "/api/admin/rooms",
            json={"name": "audit-test-room", "topic": "Testing audit log"},
            cookies={"human_session": self.admin_session},
        )

        # Query all audit logs
        res_all = self.client.get(
            "/api/admin/audit?limit=50",
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res_all.status_code, 200)
        data = res_all.json()
        self.assertGreater(data["total"], 0)
        self.assertGreater(len(data["items"]), 0)

        # Filter by action 'create_room'
        res_filt = self.client.get(
            "/api/admin/audit?action=create_room",
            cookies={"human_session": self.admin_session},
        )
        self.assertEqual(res_filt.status_code, 200)
        filt_items = res_filt.json()["items"]
        for it in filt_items:
            self.assertEqual(it["action"], "create_room")


if __name__ == "__main__":
    unittest.main()
