import os
os.environ["AICHAT_TESTING"] = "1"
import json
from pathlib import Path
import tempfile
import unittest
from starlette.testclient import TestClient

from aichat.storage import ChatStorage
from aichat.web_app import create_app
from aichat.mcp_server import hub


class TestV3Phase3Roles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.db_path = Path(cls.tmp) / "chat_v3.db"
        cls.logs_dir = Path(cls.tmp) / "logs"
        cls.test_storage = ChatStorage(db_path=cls.db_path, logs_dir=cls.logs_dir, schema_version=3)
        cls.orig_storage = hub.storage
        hub.storage = cls.test_storage

        # Admin and regular user
        cls.admin_id = hub.storage.v3.create_human(
            "admin_boss", "Admin123Pass!", display_name="Admin Boss", access_role="admin", must_change_password=0
        )
        cls.admin_token = hub.storage.v3.create_human_session(cls.admin_id)

        cls.user_id = hub.storage.v3.create_human(
            "user_norm", "User123Pass!", display_name="User Norm", access_role="user", must_change_password=0
        )
        cls.user_token = hub.storage.v3.create_human_session(cls.user_id)

        cls.app = create_app()
        cls.client = TestClient(cls.app)

    @classmethod
    def tearDownClass(cls):
        hub.storage = cls.orig_storage
        cls.test_storage.close()

    def setUp(self):
        self.admin_headers = {"Cookie": f"human_session={self.admin_token}"}
        self.user_headers = {"Cookie": f"human_session={self.user_token}"}

    def test_01_role_usage_and_listing(self):
        # 1. Create custom roles
        role1 = hub.storage.v3.create_role(
            "custom_architect",
            "Arquiteto de Software",
            description="Desenha arquiteturas",
            reminder_text="Foca-te na modularidade e escalabilidade.",
        )
        role2 = hub.storage.v3.create_role(
            "custom_reviewer",
            "Revisor de Código",
            description="Revisa pull requests",
            reminder_text="Verifica testes e boas práticas.",
        )
        role_unused = hub.storage.v3.create_role(
            "standalone",
            "Papel Isolado",
            description="Ninguém usa",
            reminder_text="Sem uso.",
        )

        # 2. Create agent with role1 as default role
        agent1_id, _ = hub.storage.v3.create_agent(
            "agent_arch",
            "Agent Architect",
            default_role_id=role1["id"],
        )

        # 3. Create room and grant agent1 role2 in this room
        room = hub.storage.v3.create_room("project-alpha", topic="Alpha Project")
        hub.storage.v3.grant_room_access(
            room["id"],
            agent1_id,
            role_id=role2["id"],
        )

        # 4. Query list roles via admin endpoint
        res = self.client.get("/api/admin/roles", headers=self.admin_headers)
        self.assertEqual(res.status_code, 200)
        roles = res.json()["roles"]

        # Check role1 usage (default role)
        r1_entry = next(r for r in roles if r["id"] == role1["id"])
        self.assertTrue(r1_entry["usage"]["in_use"])
        self.assertEqual(len(r1_entry["usage"]["default_agents"]), 1)
        self.assertEqual(r1_entry["usage"]["default_agents"][0]["id"], agent1_id)

        # Check role2 usage (room role)
        r2_entry = next(r for r in roles if r["id"] == role2["id"])
        self.assertTrue(r2_entry["usage"]["in_use"])
        self.assertEqual(len(r2_entry["usage"]["room_agents"]), 1)
        self.assertEqual(r2_entry["usage"]["room_agents"][0]["principal_id"], agent1_id)
        self.assertEqual(r2_entry["usage"]["room_agents"][0]["room_name"], "project-alpha")

        # Check role_unused usage
        r_un_entry = next(r for r in roles if r["id"] == role_unused["id"])
        self.assertFalse(r_un_entry["usage"]["in_use"])
        self.assertEqual(r_un_entry["usage"]["total_uses"], 0)

    def test_02_role_usage_endpoint_authorization(self):
        role_tmp = hub.storage.v3.create_role("sec_role", "Segurança", "Audita segurança")

        # 1. Unauthenticated -> 401
        res = self.client.get(f"/api/admin/roles/{role_tmp['id']}/usage")
        self.assertEqual(res.status_code, 401)

        # 2. Non-admin user -> 403
        res = self.client.get(f"/api/admin/roles/{role_tmp['id']}/usage", headers=self.user_headers)
        self.assertEqual(res.status_code, 403)

        # 3. Admin on non-existent role -> 404
        res = self.client.get("/api/admin/roles/999999/usage", headers=self.admin_headers)
        self.assertEqual(res.status_code, 404)

        # 4. Admin on existing role -> 200
        res = self.client.get(f"/api/admin/roles/{role_tmp['id']}/usage", headers=self.admin_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["usage"]["role_id"], role_tmp["id"])

    def test_03_role_deletion_safeguards(self):
        # 1. System builtin role cannot be deleted
        qa_role = hub.storage.v3.get_role_by_key("qa")
        if qa_role:
            res = self.client.delete(f"/api/admin/roles/{qa_role['id']}", headers=self.admin_headers)
            self.assertEqual(res.status_code, 400)
            self.assertIn("sistema", res.json()["error"].lower())

        # 2. Role in use cannot be deleted without error specifying where it is used
        role_busy = hub.storage.v3.create_role("busy_role", "Busy Worker", "Busy role")
        agent_busy_id, _ = hub.storage.v3.create_agent("busy_agent", "Busy Agent", default_role_id=role_busy["id"])

        res = self.client.delete(f"/api/admin/roles/{role_busy['id']}", headers=self.admin_headers)
        self.assertEqual(res.status_code, 400)
        err = res.json()["error"]
        self.assertIn("está em uso", err)
        self.assertIn("papel por defeito de: Busy Agent", err)

        # 3. Change agent default role to another, then delete role_busy -> succeeds!
        developer_role = hub.storage.v3.get_role_by_key("developer")
        hub.storage.v3.update_agent(agent_busy_id, default_role_id=developer_role["id"] if developer_role else 0)

        res_del = self.client.delete(f"/api/admin/roles/{role_busy['id']}", headers=self.admin_headers)
        self.assertEqual(res_del.status_code, 200)
        self.assertEqual(res_del.json()["deleted_id"], role_busy["id"])

        # Verify audit log recorded deletion
        logs = hub.storage.v3.list_audit_log(action="delete_role")["items"]
        self.assertTrue(any(log["target_id"] == role_busy["id"] for log in logs))
