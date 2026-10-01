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

class TestV3Phase3AccessMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.db_path = Path(cls.tmp) / "chat_v3.db"
        cls.logs_dir = Path(cls.tmp) / "logs"
        cls.test_storage = ChatStorage(db_path=cls.db_path, logs_dir=cls.logs_dir, schema_version=3)
        cls.orig_storage = hub.storage
        hub.storage = cls.test_storage

        # Setup roles (dev and qa exist as builtins, or create custom if not)
        cls.role_qa = hub.storage.v3.get_role_by_key("qa")
        if not cls.role_qa:
            cls.role_qa = hub.storage.v3.create_role("custom_qa", "Quality Assurance", "Testar sistema")
        cls.role_dev = hub.storage.v3.get_role_by_key("dev")
        if not cls.role_dev:
            cls.role_dev = hub.storage.v3.create_role("custom_dev", "Developer", "Codificar funcionalidade")

        # Setup admin human
        cls.admin_human_id = hub.storage.v3.create_human("admin_user", "Admin123Pass!", display_name="Admin Boss", access_role="admin", must_change_password=0)
        cls.admin_token = hub.storage.v3.create_human_session(cls.admin_human_id)

        # Setup regular user human
        cls.user_human_id = hub.storage.v3.create_human("regular_user", "User123Pass!", display_name="Regular Bob", access_role="user", must_change_password=0)
        cls.user_token = hub.storage.v3.create_human_session(cls.user_human_id)

        # Setup agents
        cls.agent1_id, _ = hub.storage.v3.create_agent("agent_alpha", "Agent Alpha", default_role_id=cls.role_dev["id"])
        cls.agent2_id, _ = hub.storage.v3.create_agent("agent_beta", "Agent Beta", default_role_id=cls.role_qa["id"])

        # Setup rooms
        cls.room_active = hub.storage.v3.create_room("active-room", topic="Active Topics")
        cls.room_archived = hub.storage.v3.create_room("old-room", topic="Archived Topics")
        hub.storage.v3.archive_room(cls.room_archived["id"], actor_id=cls.admin_human_id, actor_name="admin")

        cls.app = create_app()
        cls.client = TestClient(cls.app)

    @classmethod
    def tearDownClass(cls):
        hub.storage = cls.orig_storage
        cls.test_storage.close()

    def setUp(self):
        self.admin_headers = {"Cookie": f"human_session={self.admin_token}"}
        self.user_headers = {"Cookie": f"human_session={self.user_token}"}

    def test_01_matrix_unauthenticated_and_forbidden(self):
        # 401 without auth
        resp = self.client.get("/api/admin/rooms/matrix")
        self.assertEqual(resp.status_code, 401)

        # 403 with non-admin user
        resp = self.client.get("/api/admin/rooms/matrix", headers=self.user_headers)
        self.assertEqual(resp.status_code, 403)

    def test_02_matrix_get_data_and_filtering(self):
        # Admin gets matrix without archived rooms by default
        resp = self.client.get("/api/admin/rooms/matrix?include_archived=0&include_humans=0", headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        
        # Verify rooms (only active)
        room_names = [r["name"] for r in data["rooms"]]
        self.assertIn("active-room", room_names)
        self.assertNotIn("old-room", room_names)

        # Verify principals (only agents)
        princ_kinds = set(p["kind"] for p in data["principals"])
        self.assertEqual(princ_kinds, {"agent"})
        agent_names = [p["name"] for p in data["principals"]]
        self.assertIn("agent_alpha", agent_names)
        self.assertIn("agent_beta", agent_names)

        # Now include archived rooms
        resp_arch = self.client.get("/api/admin/rooms/matrix?include_archived=1&include_humans=0", headers=self.admin_headers)
        self.assertEqual(resp_arch.status_code, 200)
        data_arch = resp_arch.json()
        room_names_arch = [r["name"] for r in data_arch["rooms"]]
        self.assertIn("active-room", room_names_arch)
        self.assertIn("old-room", room_names_arch)

        # Now include humans
        resp_hum = self.client.get("/api/admin/rooms/matrix?include_archived=0&include_humans=1", headers=self.admin_headers)
        self.assertEqual(resp_hum.status_code, 200)
        data_hum = resp_hum.json()
        princ_kinds_hum = set(p["kind"] for p in data_hum["principals"])
        self.assertIn("human", princ_kinds_hum)
        self.assertIn("agent", princ_kinds_hum)

    def test_03_matrix_grant_update_and_revoke_flow_with_audit(self):
        room_id = self.room_active["id"]
        agent_id = self.agent1_id

        # 1. Grant access
        grant_resp = self.client.post(
            f"/api/admin/rooms/{room_id}/access",
            headers=self.admin_headers,
            json={"principal_id": agent_id, "can_write": 1, "role_id": None}
        )
        self.assertEqual(grant_resp.status_code, 200)
        self.assertEqual(grant_resp.json()["status"], "success")

        # Verify access in matrix
        m_resp = self.client.get("/api/admin/rooms/matrix", headers=self.admin_headers)
        acc_entries = [a for a in m_resp.json()["access"] if a["room_id"] == room_id and a["principal_id"] == agent_id]
        self.assertEqual(len(acc_entries), 1)
        self.assertEqual(acc_entries[0]["can_write"], 1)
        self.assertIsNone(acc_entries[0]["role_id"])

        # 2. Update role (PATCH)
        patch_role_resp = self.client.patch(
            f"/api/admin/rooms/{room_id}/access/{agent_id}",
            headers=self.admin_headers,
            json={"role_id": self.role_qa["id"]}
        )
        self.assertEqual(patch_role_resp.status_code, 200)
        self.assertEqual(patch_role_resp.json()["role_id"], self.role_qa["id"])

        # 3. Toggle observer (can_write: 0)
        patch_obs_resp = self.client.patch(
            f"/api/admin/rooms/{room_id}/access/{agent_id}",
            headers=self.admin_headers,
            json={"can_write": 0}
        )
        self.assertEqual(patch_obs_resp.status_code, 200)
        self.assertEqual(patch_obs_resp.json()["can_write"], 0)

        # 4. Check audit log for grant and updates
        audit_resp = self.client.get("/api/admin/audit?limit=20", headers=self.admin_headers)
        self.assertEqual(audit_resp.status_code, 200)
        actions = [entry["action"] for entry in audit_resp.json()["items"]]
        self.assertIn("grant_room_access", actions)
        self.assertIn("update_room_access", actions)

        # 5. Revoke access (DELETE)
        revoke_resp = self.client.delete(
            f"/api/admin/rooms/{room_id}/access/{agent_id}",
            headers=self.admin_headers
        )
        self.assertEqual(revoke_resp.status_code, 200)
        self.assertEqual(revoke_resp.json()["status"], "success")

        # Verify access is removed from matrix
        m_after_resp = self.client.get("/api/admin/rooms/matrix", headers=self.admin_headers)
        acc_after = [a for a in m_after_resp.json()["access"] if a["room_id"] == room_id and a["principal_id"] == agent_id]
        self.assertEqual(len(acc_after), 0)

        # Check audit log for revoke
        audit_resp2 = self.client.get("/api/admin/audit?limit=20", headers=self.admin_headers)
        actions2 = [entry["action"] for entry in audit_resp2.json()["items"]]
        self.assertIn("revoke_room_access", actions2)
