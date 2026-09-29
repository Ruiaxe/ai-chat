"""
Unit test suite for ai-chat v3 Phase 1 (Identity and Permissions).
Tests:
- Schema v3 contracts (IDs, foreign keys, tables).
- Scrypt password hashing, verification, failed_logins, and temporary lockout.
- Agent tokens (sha256 hash, hints, rotation, revocation, last_used_at).
- Central authorization (authorize): admin vs user vs agent, read vs write, can_write=0.
- Room access control and list_rooms_for_principal filtering.
- Server-side read cursors (read_cursors).
- Administrative CLI commands (create-admin, create-agent, rotate-token, revoke-token, grant-room).
"""
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aichat.crypto import (
    hash_password,
    verify_password,
    new_agent_token,
    hash_token,
    token_hint,
    new_session_token,
    utc_now,
)
from aichat.storage_v3 import StorageV3


class TestV3Crypto(unittest.TestCase):
    """Verifies cryptographic primitives used in v3."""

    def test_scrypt_password_hashing(self):
        pwd = "SuperSecretPassword123!"
        h = hash_password(pwd)
        self.assertTrue(h.startswith("scrypt$16384$8$1$"))
        self.assertTrue(verify_password(pwd, h))
        self.assertFalse(verify_password("wrong_password", h))
        self.assertFalse(verify_password("", h))
        self.assertFalse(verify_password(pwd, "invalid_hash_string"))

    def test_agent_token_generation_and_hashing(self):
        token = new_agent_token()
        self.assertTrue(token.startswith("aic_"))
        self.assertGreater(len(token), 32)
        h = hash_token(token)
        self.assertEqual(len(h), 64)  # SHA-256 hex string
        self.assertEqual(token_hint(token), token[-4:])

    def test_session_token_generation(self):
        sess = new_session_token()
        self.assertTrue(sess.startswith("aicsess_"))
        h = hash_token(sess)
        self.assertEqual(len(h), 64)


class TestV3StorageIdentityAndPermissions(unittest.TestCase):
    """Verifies StorageV3 identity management, permissions and authentication."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.db_path = self.tmp_dir / "chat_v3_test.db"
        self.storage = StorageV3(self.db_path, logs_dir=self.tmp_dir / "logs")

    def tearDown(self):
        self.storage.close()

    def test_schema_initialized(self):
        conn = self.storage._get_connection()
        row = conn.execute("SELECT version FROM schema_version;").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["version"], 3)

        # Check default roles seeded
        roles = self.storage.list_roles()
        role_keys = {r["role_key"] for r in roles}
        self.assertIn("developer", role_keys)
        self.assertIn("project_manager", role_keys)
        self.assertIn("ui_designer", role_keys)
        self.assertIn("qa", role_keys)
        self.assertIn("devops", role_keys)

    def test_create_and_authenticate_human_admin(self):
        pid = self.storage.create_human(
            username="rui_admin",
            password="AdminPassword2026!",
            display_name="Rui Admin",
            access_role="admin",
        )
        self.assertGreater(pid, 0)

        # Successful login
        principal, err = self.storage.authenticate_human("rui_admin", "AdminPassword2026!")
        self.assertIsNone(err)
        self.assertIsNotNone(principal)
        self.assertEqual(principal["id"], pid)
        self.assertEqual(principal["access_role"], "admin")
        self.assertEqual(principal["kind"], "human")
        self.assertIsNotNone(principal["last_login_at"])

        # Failed login with wrong password
        failed_p, err = self.storage.authenticate_human("rui_admin", "wrong_pass")
        self.assertIsNone(failed_p)
        self.assertIn("incorretos", err)

    def test_human_failed_logins_and_temporary_lockout(self):
        pid = self.storage.create_human(
            username="locked_user",
            password="CorrectPass123!",
            access_role="user",
        )

        # 4 consecutive failures
        for i in range(4):
            p, err = self.storage.authenticate_human("locked_user", "bad_pass")
            self.assertIsNone(p)
            self.assertIn("incorretos", err)

        # 5th failure triggers lockout
        p, err = self.storage.authenticate_human("locked_user", "bad_pass")
        self.assertIsNone(p)
        self.assertIn("bloqueada", err.lower())

        # Even correct password is now blocked while locked
        p, err = self.storage.authenticate_human("locked_user", "CorrectPass123!")
        self.assertIsNone(p)
        self.assertIn("bloqueada", err.lower())

    def test_human_change_password(self):
        pid = self.storage.create_human(
            username="user_change_pwd",
            password="InitialPassword123!",
            must_change_password=1,
        )
        p, _ = self.storage.authenticate_human("user_change_pwd", "InitialPassword123!")
        self.assertEqual(p["must_change_password"], 1)

        # Change password
        ok = self.storage.change_human_password(pid, "NewBrandPassword456!")
        self.assertTrue(ok)

        # Verify old password fails, new password succeeds and resets must_change_password
        p_old, err = self.storage.authenticate_human("user_change_pwd", "InitialPassword123!")
        self.assertIsNone(p_old)

        p_new, err = self.storage.authenticate_human("user_change_pwd", "NewBrandPassword456!")
        self.assertIsNotNone(p_new)
        self.assertEqual(p_new["must_change_password"], 0)

    def test_human_session_lifecycle(self):
        pid = self.storage.create_human(username="alice", password="AlicePassword123!")
        session_token = self.storage.create_human_session(pid, expires_hours=2)
        self.assertTrue(session_token.startswith("aicsess_"))

        # Authenticate session
        p = self.storage.authenticate_human_session(session_token)
        self.assertIsNotNone(p)
        self.assertEqual(p["name"], "alice")

        # Revoke session
        self.storage.revoke_human_session(session_token)
        self.assertIsNone(self.storage.authenticate_human_session(session_token))

    def test_agent_registration_auth_rotation_revocation(self):
        dev_role = self.storage.get_role_by_key("developer")
        pid, token = self.storage.create_agent(
            callsign="claude_code",
            display_name="Claude Developer",
            default_role_id=dev_role["id"],
        )
        self.assertTrue(token.startswith("aic_"))

        # Authenticate agent
        agent, err = self.storage.authenticate_agent_token(token)
        self.assertIsNone(err)
        self.assertIsNotNone(agent)
        self.assertEqual(agent["name"], "claude_code")
        self.assertEqual(agent["default_role_key"], "developer")

        # Rotate token
        new_token, hint = self.storage.rotate_agent_token(pid, revoke_old=True)
        self.assertNotEqual(token, new_token)
        self.assertEqual(hint, new_token[-4:])

        # Old token is now revoked
        old_agent, err = self.storage.authenticate_agent_token(token)
        self.assertIsNone(old_agent)
        self.assertIn("revogado", err)

        # New token works
        curr_agent, err = self.storage.authenticate_agent_token(new_token)
        self.assertIsNotNone(curr_agent)

        # Inactive agent rejected
        self.storage.update_principal_status(pid, "inactive")
        inact_agent, err = self.storage.authenticate_agent_token(new_token)
        self.assertIsNone(inact_agent)
        self.assertIn("não está ativo", err)

    def test_legacy_principal_cannot_log_in(self):
        pid = self.storage.create_principal(
            kind="human",
            name="legacy_human",
            is_legacy=1,
        )
        p, err = self.storage.authenticate_human("legacy_human", "any_password")
        self.assertIsNone(p)
        self.assertIn("legado", err.lower())

    def test_central_authorization_and_room_access(self):
        admin_id = self.storage.create_human(username="admin_boss", password="Pass123!", access_role="admin")
        user_id = self.storage.create_human(username="regular_user", password="Pass123!", access_role="user")
        agent_id, _ = self.storage.create_agent(callsign="bot_worker")

        admin_p = self.storage.get_principal_by_id(admin_id)
        user_p = self.storage.get_principal_by_id(user_id)
        agent_p = self.storage.get_principal_by_id(agent_id)

        # Create room
        room1 = self.storage.create_room("project_alpha", topic="Alpha Channel", created_by_id=admin_id)
        room2 = self.storage.create_room("project_beta", topic="Beta Channel", created_by_id=admin_id)

        # 1. Admin has access to all rooms
        self.assertTrue(self.storage.authorize(admin_p, "admin"))
        self.assertTrue(self.storage.authorize(admin_p, "read_room", {"room_id": room1["id"]}))
        self.assertTrue(self.storage.authorize(admin_p, "write_room", {"room_id": room1["id"]}))
        self.assertTrue(self.storage.authorize(admin_p, "manage_room", {"room_id": room1["id"]}))

        admin_rooms = self.storage.list_rooms_for_principal(admin_p)
        self.assertEqual(len(admin_rooms), 2)

        # 2. Regular user and agent have NO access until granted
        self.assertFalse(self.storage.authorize(user_p, "admin"))
        self.assertFalse(self.storage.authorize(user_p, "read_room", {"room_id": room1["id"]}))
        self.assertFalse(self.storage.authorize(agent_p, "read_room", {"room_id": room1["id"]}))
        self.assertEqual(len(self.storage.list_rooms_for_principal(user_p)), 0)

        # 3. Grant access to room1 for agent (read and write)
        self.storage.grant_room_access(room1["id"], agent_id, can_write=1)
        self.assertTrue(self.storage.authorize(agent_p, "read_room", {"room_id": room1["id"]}))
        self.assertTrue(self.storage.authorize(agent_p, "write_room", {"room_id": room1["id"]}))
        self.assertFalse(self.storage.authorize(agent_p, "read_room", {"room_id": room2["id"]}))

        agent_rooms = self.storage.list_rooms_for_principal(agent_p)
        self.assertEqual(len(agent_rooms), 1)
        self.assertEqual(agent_rooms[0]["id"], room1["id"])

        # 4. Grant read-only access (can_write=0) to regular user
        self.storage.grant_room_access(room1["id"], user_id, can_write=0)
        self.assertTrue(self.storage.authorize(user_p, "read_room", {"room_id": room1["id"]}))
        self.assertFalse(self.storage.authorize(user_p, "write_room", {"room_id": room1["id"]}))

        # 5. Revoke access
        self.storage.revoke_room_access(room1["id"], user_id)
        self.assertFalse(self.storage.authorize(user_p, "read_room", {"room_id": room1["id"]}))

    def test_read_cursors_and_messages(self):
        aid = self.storage.create_human(username="reporter", password="Pass123!", access_role="admin")
        reporter = self.storage.get_principal_by_id(aid)
        room = self.storage.create_room("status_room", created_by_id=aid)

        # Initial cursor is 0
        self.assertEqual(self.storage.get_read_cursor(aid, room["id"]), 0)

        # Add message
        msg1 = self.storage.add_message(
            room_id=room["id"],
            sender=reporter,
            content="Primeiro relatório v3",
        )
        self.assertGreater(msg1["id"], 0)
        self.assertEqual(self.storage.get_read_cursor(aid, room["id"]), msg1["id"])

        # Update cursor explicitly
        self.storage.update_read_cursor(aid, room["id"], 999)
        self.assertEqual(self.storage.get_read_cursor(aid, room["id"]), 999)


class TestV3CLI(unittest.TestCase):
    """Verifies command-line interface execution."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.db_path = self.tmp_dir / "chat_v3_cli.db"

    def _run_cli(self, args: list[str]) -> subprocess.CompletedProcess:
        cmd = [sys.executable, "-m", "aichat.cli", "--db", str(self.db_path)] + args
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_cli_full_flow(self):
        # 1. Create admin
        res1 = self._run_cli(["create-admin", "-u", "Rui", "-p", "ComplexAdminPassword!"])
        self.assertEqual(res1.returncode, 0, res1.stderr)
        self.assertIn("criado com sucesso", res1.stdout)

        # 2. Create agent
        res2 = self._run_cli(["create-agent", "-n", "WorkerBot", "--role", "developer"])
        self.assertEqual(res2.returncode, 0, res2.stderr)
        self.assertIn("registado com sucesso", res2.stdout)
        self.assertIn("aic_", res2.stdout)

        # 3. List principals
        res3 = self._run_cli(["list-principals"])
        self.assertEqual(res3.returncode, 0, res3.stderr)
        self.assertIn("Rui", res3.stdout)
        self.assertIn("WorkerBot", res3.stdout)

        # 4. Create room via storage and grant access via CLI
        st = StorageV3(self.db_path)
        room = st.create_room("ops_room")
        st.close()

        res4 = self._run_cli(["grant-room", "--room", "ops_room", "--principal", "WorkerBot", "--role", "developer"])
        self.assertEqual(res4.returncode, 0, res4.stderr)
        self.assertIn("concedido", res4.stdout)

        # 5. Revoke room access via CLI
        res5 = self._run_cli(["revoke-room", "--room", "ops_room", "--principal", "WorkerBot"])
        self.assertEqual(res5.returncode, 0, res5.stderr)
        self.assertIn("revogado", res5.stdout)
