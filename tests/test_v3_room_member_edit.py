import os
os.environ["AICHAT_TESTING"] = "1"
import json
from pathlib import Path
import tempfile
import unittest
from starlette.testclient import TestClient

from aichat.storage import ChatStorage
from aichat.web_app import create_app, extract_client_ip
from aichat.mcp_server import hub

class TestV3RoomMemberEdit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.db_path = Path(cls.tmp) / "chat_v3.db"
        cls.logs_dir = Path(cls.tmp) / "logs"
        cls.test_storage = ChatStorage(db_path=cls.db_path, logs_dir=cls.logs_dir, schema_version=3)
        cls.orig_storage = hub.storage
        hub.storage = cls.test_storage

        # Setup roles
        cls.role_pm = hub.storage.v3.create_role("pm", "Project Manager", "Gerir o projeto")
        cls.role_dev = hub.storage.v3.create_role("dev", "Developer", "Escrever código")

        # Setup admin human
        cls.admin_human_id = hub.storage.v3.create_human("rui_admin", "Admin123Pass!", display_name="Rui Admin", access_role="admin", must_change_password=0)
        cls.admin_token = hub.storage.v3.create_human_session(cls.admin_human_id)

        # Setup regular human (non-admin)
        cls.user_human_id = hub.storage.v3.create_human("pedro_user", "User123Pass!", display_name="Pedro User", access_role="user", must_change_password=0)
        cls.user_token = hub.storage.v3.create_human_session(cls.user_human_id)

        # Setup agents
        cls.agent_ana_id, cls.agent_ana_token = hub.storage.v3.create_agent(
            "ana_agent",
            "Agente Ana",
            default_role_id=cls.role_pm["id"]
        )
        cls.agent_carlos_id, cls.agent_carlos_token = hub.storage.v3.create_agent(
            "carlos_agent",
            "Agente Carlos",
            default_role_id=cls.role_dev["id"]
        )
        cls.agent_pedro_id, _ = hub.storage.v3.create_agent("pedro_outsider", "Agente Outsider")

        # Setup room
        cls.room = hub.storage.v3.create_room("dev-room", topic="Sala de Dev")

        cls.app = create_app()
        cls.client = TestClient(cls.app)

    @classmethod
    def tearDownClass(cls):
        hub.storage = cls.orig_storage
        cls.test_storage.close()

    def setUp(self):
        self.admin_headers = {"Cookie": f"human_session={self.admin_token}"}
        self.user_headers = {"Cookie": f"human_session={self.user_token}"}

    def test_01_edit_role_preserves_permission(self):
        """Editing role without sending can_write preserves existing write permission."""
        # Grant initial access: role=None, can_write=1
        hub.storage.v3.grant_room_access(self.room["id"], self.agent_ana_id, role_id=None, can_write=1)

        # PATCH only role_id
        resp = self.client.patch(
            f"/api/admin/rooms/{self.room['id']}/access/{self.agent_ana_id}",
            json={"role_id": self.role_dev["id"]},
            headers=self.admin_headers,
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["role_id"], self.role_dev["id"])
        self.assertEqual(data["can_write"], 1)

        # Verify in list_room_members
        members = hub.storage.v3.list_room_members(self.room["id"])
        ana = next(m for m in members if m["principal_id"] == self.agent_ana_id)
        self.assertEqual(ana["role_id"], self.role_dev["id"])
        self.assertEqual(ana["can_write"], 1)

    def test_02_observer_edited_only_in_role_remains_observer(self):
        """An observer whose role is edited without sending can_write remains observer (can_write=0)."""
        # Grant initial access: Carlos as observer (can_write=0), role=pm
        hub.storage.v3.grant_room_access(self.room["id"], self.agent_carlos_id, role_id=self.role_pm["id"], can_write=0)

        # PATCH only role_id
        resp = self.client.patch(
            f"/api/admin/rooms/{self.room['id']}/access/{self.agent_carlos_id}",
            json={"role_id": self.role_dev["id"]},
            headers=self.admin_headers,
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["role_id"], self.role_dev["id"])
        self.assertEqual(data["can_write"], 0)

        # Verify still observer
        members = hub.storage.v3.list_room_members(self.room["id"])
        carlos = next(m for m in members if m["principal_id"] == self.agent_carlos_id)
        self.assertEqual(carlos["role_id"], self.role_dev["id"])
        self.assertEqual(carlos["can_write"], 0)

    def test_03_edit_permission_preserves_role(self):
        """Editing can_write without sending role_id preserves the existing role."""
        # Carlos has role_dev and can_write=0. Edit to can_write=1 without role_id
        resp = self.client.patch(
            f"/api/admin/rooms/{self.room['id']}/access/{self.agent_carlos_id}",
            json={"can_write": 1},
            headers=self.admin_headers,
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        data = resp.json()
        self.assertEqual(data["role_id"], self.role_dev["id"])
        self.assertEqual(data["can_write"], 1)

        members = hub.storage.v3.list_room_members(self.room["id"])
        carlos = next(m for m in members if m["principal_id"] == self.agent_carlos_id)
        self.assertEqual(carlos["role_id"], self.role_dev["id"])
        self.assertEqual(carlos["can_write"], 1)

    def test_04_role_id_null_clears_room_role_to_fallback(self):
        """Sending role_id: null explicitly unsets room-specific role back to agent default role."""
        # Ana has role_dev in room. PATCH with role_id: None
        resp = self.client.patch(
            f"/api/admin/rooms/{self.room['id']}/access/{self.agent_ana_id}",
            json={"role_id": None},
            headers=self.admin_headers,
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        data = resp.json()
        self.assertIsNone(data["role_id"])
        self.assertEqual(data["can_write"], 1)  # preserved

        members = hub.storage.v3.list_room_members(self.room["id"])
        ana = next(m for m in members if m["principal_id"] == self.agent_ana_id)
        self.assertIsNone(ana["role_id"])
        # Notice default role is still present on the agent:
        self.assertEqual(ana["default_role_id"], self.role_pm["id"])
        self.assertEqual(ana["default_role_key"], "pm")

    def test_05_field_omitted_vs_role_id_null(self):
        """Verify distinction: omitting role_id keeps existing role; role_id=None sets it to None."""
        # Set Ana to role_dev
        self.client.patch(
            f"/api/admin/rooms/{self.room['id']}/access/{self.agent_ana_id}",
            json={"role_id": self.role_dev["id"]},
            headers=self.admin_headers,
        )
        # 1. Omit role_id, send only can_write: 0 -> role_id must stay role_dev
        resp1 = self.client.patch(
            f"/api/admin/rooms/{self.room['id']}/access/{self.agent_ana_id}",
            json={"can_write": 0},
            headers=self.admin_headers,
        )
        self.assertEqual(resp1.json()["role_id"], self.role_dev["id"])
        self.assertEqual(resp1.json()["can_write"], 0)

        # 2. Send role_id: null -> role_id becomes None, can_write: 0 is preserved
        resp2 = self.client.patch(
            f"/api/admin/rooms/{self.room['id']}/access/{self.agent_ana_id}",
            json={"role_id": None},
            headers=self.admin_headers,
        )
        self.assertIsNone(resp2.json()["role_id"])
        self.assertEqual(resp2.json()["can_write"], 0)

    def test_06_patch_non_member_returns_404(self):
        """PATCH to a principal who is not a member of the room returns 404."""
        resp = self.client.patch(
            f"/api/admin/rooms/{self.room['id']}/access/{self.agent_pedro_id}",
            json={"can_write": 1},
            headers=self.admin_headers,
        )
        self.assertEqual(resp.status_code, 404)
        self.assertIn("não é membro", resp.json()["error"])

    def test_07_non_admin_returns_403(self):
        """Non-admin human user cannot PATCH room access."""
        resp = self.client.patch(
            f"/api/admin/rooms/{self.room['id']}/access/{self.agent_ana_id}",
            json={"can_write": 1},
            headers=self.user_headers,
        )
        self.assertEqual(resp.status_code, 403)

    def test_08_audit_log_records_before_and_after(self):
        """Audit log records before and after values for role and write permission changes."""
        # 1. Change role from None to dev
        hub.storage.v3.grant_room_access(self.room["id"], self.agent_ana_id, role_id=None, can_write=1)
        self.client.patch(
            f"/api/admin/rooms/{self.room['id']}/access/{self.agent_ana_id}",
            json={"role_id": self.role_dev["id"]},
            headers=self.admin_headers,
        )
        logs = hub.storage.v3.get_room_audit_log(self.room["id"])
        latest = logs[0]
        self.assertEqual(latest["action"], "update_room_access")
        self.assertIn("role: — → Developer", latest["details"])

        # 2. Change permission from 1 to 0
        self.client.patch(
            f"/api/admin/rooms/{self.room['id']}/access/{self.agent_ana_id}",
            json={"can_write": 0},
            headers=self.admin_headers,
        )
        logs = hub.storage.v3.get_room_audit_log(self.room["id"])
        latest = logs[0]
        self.assertEqual(latest["action"], "update_room_access")
        self.assertIn("permissão: leitura e escrita → observador", latest["details"])

        # 3. Change role back to None
        self.client.patch(
            f"/api/admin/rooms/{self.room['id']}/access/{self.agent_ana_id}",
            json={"role_id": None},
            headers=self.admin_headers,
        )
        logs = hub.storage.v3.get_room_audit_log(self.room["id"])
        latest = logs[0]
        self.assertEqual(latest["action"], "update_room_access")
        self.assertIn("role: Developer → —", latest["details"])

    def test_09_trust_proxy_handling(self):
        """extract_client_ip ignores X-Forwarded-For unless AICHAT_TRUST_PROXY is explicitly enabled."""
        from starlette.datastructures import Headers

        scope = {"type": "http", "client": ("192.168.1.50", 50000)}
        headers = Headers({"x-forwarded-for": "10.0.0.99, 10.0.0.1"})

        # Without AICHAT_TRUST_PROXY
        if "AICHAT_TRUST_PROXY" in os.environ:
            del os.environ["AICHAT_TRUST_PROXY"]
        ip = extract_client_ip(scope=scope, headers=headers)
        self.assertEqual(ip, "192.168.1.50")

        # With AICHAT_TRUST_PROXY=1
        os.environ["AICHAT_TRUST_PROXY"] = "1"
        try:
            ip_trusted = extract_client_ip(scope=scope, headers=headers)
            self.assertEqual(ip_trusted, "10.0.0.99")
        finally:
            del os.environ["AICHAT_TRUST_PROXY"]

if __name__ == "__main__":
    unittest.main()
