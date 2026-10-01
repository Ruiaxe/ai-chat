import os
os.environ["AICHAT_TESTING"] = "1"
import json
from pathlib import Path
import tempfile
import unittest
from starlette.testclient import TestClient

from aichat.crypto import verify_password
from aichat.storage import ChatStorage
from aichat.web_app import create_app
from aichat.mcp_server import hub


class TestV3Phase3AdminResetAndSettings(unittest.TestCase):
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
            "admin_chief", "AdminChiefPass123!", display_name="Admin Chief", access_role="admin", must_change_password=0
        )
        cls.admin_token = hub.storage.v3.create_human_session(cls.admin_id)

        cls.user_id = hub.storage.v3.create_human(
            "target_user", "OldUserPass123!", display_name="Target User", access_role="user", must_change_password=0
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

    def test_01_reset_password_authorization(self):
        # 1. Unauthenticated -> 401
        res = self.client.post(f"/api/admin/humans/{self.user_id}/reset-password")
        self.assertEqual(res.status_code, 401)

        # 2. Non-admin -> 403
        res = self.client.post(f"/api/admin/humans/{self.user_id}/reset-password", headers=self.user_headers)
        self.assertEqual(res.status_code, 403)

        # 3. Non-existent principal -> 404
        res = self.client.post("/api/admin/humans/999999/reset-password", headers=self.admin_headers)
        self.assertEqual(res.status_code, 404)

    def test_02_reset_password_success_and_auditing(self):
        # Set artificial failed logins and lock on user
        conn = hub.storage.v3._get_connection()
        with conn:
            conn.execute(
                "UPDATE humans SET failed_logins = 5, locked_until = '2099-01-01T00:00:00Z' WHERE principal_id = ?;",
                (self.user_id,),
            )

        # Call reset-password endpoint
        res = self.client.post(f"/api/admin/humans/{self.user_id}/reset-password", headers=self.admin_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["principal_id"], self.user_id)
        temp_pwd = data["temporary_password"]
        self.assertTrue(len(temp_pwd) >= 12)

        # Verify DB state
        p = hub.storage.v3.get_principal_by_id(self.user_id)
        self.assertEqual(p["must_change_password"], 1)
        self.assertEqual(p["failed_logins"], 0)
        self.assertIsNone(p["locked_until"])

        # Verify password is valid hash and matches temporary password
        row = conn.execute("SELECT password_hash FROM humans WHERE principal_id = ?;", (self.user_id,)).fetchone()
        pwd_hash = row["password_hash"]
        self.assertNotEqual(pwd_hash, temp_pwd)
        self.assertTrue(verify_password(temp_pwd, pwd_hash))

        # Check audit log: must record action, without password!
        logs = hub.storage.v3.list_audit_log(action="reset_password", target_id=self.user_id)["items"]
        self.assertTrue(len(logs) > 0)
        log_entry = logs[0]
        self.assertIn("password reposta pelo admin admin_chief para o utilizador target_user", log_entry["details"])
        self.assertNotIn(temp_pwd, log_entry["details"])

        # Also verify alias /api/admin/users/{id}/reset-password works
        res_alias = self.client.post(f"/api/admin/users/{self.user_id}/reset-password", headers=self.admin_headers)
        self.assertEqual(res_alias.status_code, 200)
        temp_pwd2 = res_alias.json()["temporary_password"]
        self.assertTrue(len(temp_pwd2) >= 12)
        self.assertNotEqual(temp_pwd, temp_pwd2)

    def test_03_settings_in_minutes_validation_and_update(self):
        # 1. GET settings returns minutes
        res = self.client.get("/api/admin/settings", headers=self.admin_headers)
        self.assertEqual(res.status_code, 200)
        s = res.json()["settings"]
        self.assertIn("t_idle_minutes", s)
        self.assertIn("t_unread_minutes", s)
        self.assertIn("t_idle_seconds", s)
        self.assertIn("t_unread_seconds", s)

        # 2. Validation: out-of-range minutes (< 1 or > 240)
        res_low = self.client.patch("/api/admin/settings", json={"t_idle_minutes": 0}, headers=self.admin_headers)
        self.assertEqual(res_low.status_code, 400)
        self.assertIn("entre 1 e 240 minutos", res_low.json()["error"])

        res_high = self.client.patch("/api/admin/settings", json={"t_idle_minutes": 241}, headers=self.admin_headers)
        self.assertEqual(res_high.status_code, 400)
        self.assertIn("entre 1 e 240 minutos", res_high.json()["error"])

        res_unread_low = self.client.patch("/api/admin/settings", json={"t_unread_minutes": -1}, headers=self.admin_headers)
        self.assertEqual(res_unread_low.status_code, 400)
        self.assertIn("entre 1 e 240 minutos", res_unread_low.json()["error"])

        res_unread_high = self.client.patch("/api/admin/settings", json={"t_unread_minutes": 300}, headers=self.admin_headers)
        self.assertEqual(res_unread_high.status_code, 400)
        self.assertIn("entre 1 e 240 minutos", res_unread_high.json()["error"])

        # 3. Validation: out-of-range seconds (< 60 or > 14400)
        res_sec_low = self.client.patch("/api/admin/settings", json={"t_idle_seconds": 30}, headers=self.admin_headers)
        self.assertEqual(res_sec_low.status_code, 400)
        self.assertIn("entre 1 e 240 minutos", res_sec_low.json()["error"])

        res_sec_high = self.client.patch("/api/admin/settings", json={"t_unread_seconds": 20000}, headers=self.admin_headers)
        self.assertEqual(res_sec_high.status_code, 400)
        self.assertIn("entre 1 e 240 minutos", res_sec_high.json()["error"])

        # 4. Valid update in minutes: 5 min idle, 10 min unread
        res_ok = self.client.patch(
            "/api/admin/settings",
            json={"t_idle_minutes": 5, "t_unread_minutes": 10},
            headers=self.admin_headers,
        )
        self.assertEqual(res_ok.status_code, 200)
        new_s = res_ok.json()["settings"]
        self.assertEqual(new_s["t_idle_minutes"], 5)
        self.assertEqual(new_s["t_idle_seconds"], 300)
        self.assertEqual(new_s["t_unread_minutes"], 10)
        self.assertEqual(new_s["t_unread_seconds"], 600)

        # 5. Check audit log
        logs = hub.storage.v3.list_audit_log(action="update_settings")["items"]
        self.assertTrue(len(logs) > 0)
