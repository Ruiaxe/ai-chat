"""
Test Suite for AI Chat v3.1 Camada 1:
Universal wake-up on server, liveliness tracking, reliable delivery (ACK),
stalled agent alerts & recovery, MCP tool cleanup & deprecations, and admin controls.

All tests run in isolated temporary directories and clean up after themselves.
"""
import contextlib
import io
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

from starlette.testclient import TestClient

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
    wait_for_work as tool_wait_for_work,
    wait_for_new_messages as tool_wait_for_new_messages,
    team_status as tool_team_status,
    register_agent as tool_register_agent,
    send_message as tool_send_message,
    read_messages as tool_read_messages,
    join_room as tool_join_room,
    leave_room as tool_leave_room,
    create_room as tool_create_room,
    rotate_member_token as tool_rotate_member_token,
    change_room_password as tool_change_room_password,
    kick_member as tool_kick_member,
    archive_room as tool_archive_room,
    wake_up_call as tool_wake_up_call,
    get_room_audit_log as tool_get_room_audit_log,
    get_room_transcript as tool_get_room_transcript,
    check_new_messages as tool_check_new_messages,
    who_is_listening as tool_who_is_listening,
)


class TestV3WakeLayer1(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="v31_wake_l1_"))
        cls.src_path = cls.tmp / "chat_v2.db"
        cls.logs_dir = cls.tmp / "logs"

        # 1. Build authentic v2 database
        v2_st = ChatStorage(db_path=cls.src_path, logs_dir=cls.logs_dir)
        v2_st.create_room("geral", topic="Sala Geral")
        v2_st.create_room("dev", topic="Sala Dev")
        v2_st.close()

        # 2. Run migration to v3
        cls.out_dir = cls.tmp / "migration_out"
        cls.dst_path = cls.tmp / "chat_v3.db"
        rc = mig.main([
            "--source", str(cls.src_path),
            "--target", str(cls.dst_path),
            "--admin-username", "Rui",
            "--out-dir", str(cls.out_dir),
        ])
        assert rc == 0, "Migration returned non-zero exit code"

        creds_file = next(cls.out_dir.glob("credentials_*.txt"))
        creds_text = creds_file.read_text(encoding="utf-8")
        admin_pass = None
        for line in creds_text.splitlines():
            if line.strip().startswith("Admin initial password:"):
                admin_pass = line.strip().split("Admin initial password:")[1].split("(")[0].strip()
                break
        assert admin_pass, f"Admin password not found in {creds_text}"

        # 3. Mount v3 storage into global hub and create Starlette app
        cls.orig_storage = hub.storage
        cls.test_storage = ChatStorage(db_path=cls.dst_path, logs_dir=cls.logs_dir)
        assert cls.test_storage.is_v3(), "ChatStorage must be in v3 mode for migrated database"
        hub.storage = cls.test_storage

        os.environ["AICHAT_TESTING"] = "1"
        cls.app = create_app()
        cls.client = TestClient(cls.app)

        # Login as admin to get session cookie
        login_res = cls.client.post("/api/auth/login", json={
            "username": "Rui",
            "password": admin_pass,
        })
        assert login_res.status_code == 200, login_res.text
        # Change password to satisfy mandatory change
        pwd_res = cls.client.post("/api/auth/change-password", json={
            "old_password": admin_pass,
            "new_password": "AdminSecurePassword456!",
        })
        assert pwd_res.status_code == 200, pwd_res.text

        # Create active test agent "ana" via storage
        pid, raw_token = hub.storage.v3.create_agent(
            callsign="ana",
            display_name="Ana Researcher",
            status="active",
        )
        cls.ana_id = pid
        cls.ana_token = raw_token

        # Create active test agent "carlos" via storage
        pid_c, raw_token_c = hub.storage.v3.create_agent(
            callsign="carlos",
            display_name="Carlos Dev",
            status="active",
        )
        cls.carlos_id = pid_c
        cls.carlos_token = raw_token_c

        # Grant access to "geral" room for ana and carlos
        geral = hub.storage.v3.get_room("geral")
        hub.storage.v3.grant_room_access(geral["id"], cls.ana_id, can_write=1)
        hub.storage.v3.grant_room_access(geral["id"], cls.carlos_id, can_write=1)

    @classmethod
    def tearDownClass(cls):
        hub.storage.close()
        hub.storage = cls.orig_storage
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_01_mcp_docstrings_and_schema_cleanliness(self):
        """Verifies zero 'token' (as requirement), zero 'Rui', and zero leaked credentials."""
        # 1. Zero occurrences of "token" or "Rui" in all tool descriptions
        fails = []
        for name, tool in mcp._tool_manager._tools.items():
            desc = tool.description or ""
            # Zero "Rui" anywhere
            if re.search(r'\bRui\b', desc):
                fails.append(f"{name}: contains 'Rui'")
            # Zero "token" as auth requirement
            if re.search(r'\btoken\b', desc, re.I):
                fails.append(f"{name}: contains 'token' in description")

        self.assertEqual(fails, [], f"Docstring violations: {fails}")

        # 2. Check pruned parameters
        forbidden_params = {"agent_token", "member_token", "password", "requester_token", "sender_name", "agent_name"}
        leaked = []
        for name, tool in mcp._tool_manager._tools.items():
            if hasattr(tool, "parameters") and isinstance(tool.parameters, dict):
                props = set(tool.parameters.get("properties", {}).keys())
                bad = props.intersection(forbidden_params)
                if bad:
                    leaked.append(f"{name}: exposes {bad}")
        self.assertEqual(leaked, [], f"Leaked parameters in tool schemas: {leaked}")

    def test_02_agent_pending_registration_and_admin_approval(self):
        """Self-registration creates pending agent without token; admin approval issues token once."""
        # 1. MCP register_agent creates pending agent
        res = tool_register_agent(callsign="pedro", display_name="Pedro QA")
        parsed = json.loads(res) if isinstance(res, str) else res
        self.assertEqual(parsed.get("status"), "pending")
        self.assertNotIn("token", parsed)
        self.assertIn("aprovação", parsed.get("message", "").lower())

        # Verify in DB
        agent = hub.storage.v3.get_principal_by_name("pedro")
        self.assertIsNotNone(agent)
        self.assertEqual(agent["status"], "pending")

        # 2. Admin approves agent
        approve_res = self.client.post(f"/api/admin/agents/{agent['id']}/approve")
        self.assertEqual(approve_res.status_code, 200, approve_res.text)
        approve_data = approve_res.json()
        self.assertIn(approve_data.get("status"), ("success", "active"))
        issued_token = approve_data.get("token")
        self.assertTrue(issued_token and (issued_token.startswith("aic_") or issued_token.startswith("act_")))

        # Agent should now be active
        agent_after = hub.storage.v3.get_principal_by_name("pedro")
        self.assertEqual(agent_after["status"], "active")

        # Verify issued token can authenticate
        ident = hub.authenticate_agent(issued_token)
        self.assertEqual(ident["callsign"], "pedro")

    def test_03_agent_liveliness_transitions(self):
        """Verifies transitions across the 5 liveliness states."""
        # Carlos starts offline (no activity yet)
        liv = hub.storage.v3.get_agent_liveliness(self.carlos_id)
        self.assertEqual(liv["state"], "offline")
        self.assertIn("offline", liv["state_badge"])

        # 1. Listening transition: set listening_now = 1
        hub.storage.v3.set_agent_listening(self.carlos_id, True)
        liv = hub.storage.v3.get_agent_liveliness(self.carlos_id)
        self.assertEqual(liv["state"], "listening")
        self.assertEqual(liv["state_badge"], "🟢 a escutar")

        # Stop listening
        hub.storage.v3.set_agent_listening(self.carlos_id, False)

        # 2. Working transition: record recent activity
        hub.storage.v3.record_agent_activity(self.carlos_id)
        liv = hub.storage.v3.get_agent_liveliness(self.carlos_id)
        self.assertEqual(liv["state"], "working")
        self.assertEqual(liv["state_badge"], "🔵 a trabalhar")

        # 3. Idle transition: simulate past activity > T_idle (180s)
        conn = hub.storage.v3._get_connection()
        past_dt = (datetime.now(timezone.utc) - timedelta(seconds=250)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with conn:
            conn.execute("UPDATE agents SET last_activity_at = ? WHERE principal_id = ?;", (past_dt, self.carlos_id))

        liv = hub.storage.v3.get_agent_liveliness(self.carlos_id)
        self.assertEqual(liv["state"], "idle")
        self.assertEqual(liv["state_badge"], "💤 sem trabalho")

        # 4. Stalled transition: send unread message directed to carlos older than T_unread (120s)
        geral = hub.storage.v3.get_room("geral")
        msg = hub.storage.v3.add_message(
            room_name_or_id=geral["id"],
            sender="ana",
            content="@carlos precisamos de rever o PR de testes.",
            to=["@carlos"],
        )
        msg_past_dt = (datetime.now(timezone.utc) - timedelta(seconds=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with conn:
            conn.execute("UPDATE messages SET created_at = ? WHERE id = ?;", (msg_past_dt, msg["id"]))

        liv = hub.storage.v3.get_agent_liveliness(self.carlos_id)
        self.assertEqual(liv["state"], "stalled")
        self.assertEqual(liv["state_badge"], "🔴 parado")

    async def test_04_stalled_agent_alert_to_humans_and_backoff(self):
        """Tests stalled alert emission to room humans only, with backoff delays."""
        # Ensure carlos is stalled with old activity and old directed message
        conn = hub.storage.v3._get_connection()
        past_act = (datetime.now(timezone.utc) - timedelta(seconds=250)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with conn:
            conn.execute("UPDATE agents SET last_activity_at = ?, listening_now = 0, stalled_alert_count = 0, last_stalled_alert_at = NULL WHERE principal_id = ?;", (past_act, self.carlos_id))

        geral = hub.storage.v3.get_room("geral")
        msg = hub.storage.v3.add_message(
            room_name_or_id=geral["id"],
            sender="ana",
            content="@carlos atenção!",
            to=["@carlos"],
        )
        msg_past = (datetime.now(timezone.utc) - timedelta(seconds=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        with conn:
            conn.execute("UPDATE messages SET created_at = ? WHERE id = ?;", (msg_past, msg["id"]))

        # Check stalled candidates
        candidates = hub.storage.v3.list_stalled_agents_to_alert(t_idle=180, t_unread=120)
        stalled_carlos = [c for c in candidates if c["principal_id"] == self.carlos_id]
        self.assertTrue(len(stalled_carlos) > 0)

        # Trigger alert loop check
        await hub.check_and_alert_stalled_agents()

        # Verify alert message was created
        messages = hub.storage.v3.get_messages(geral["id"], limit=5)
        alert_msgs = [m for m in messages if "não está a escutar" in m["content"]]
        self.assertTrue(len(alert_msgs) > 0, "Stalled alert message was not found in room")

        # Verify recipient: sent only to humans
        alert_msg = alert_msgs[-1]
        for recip in alert_msg.get("recipients", []):
            if recip.get("target_kind") == "principal":
                p = hub.storage.v3.get_principal_by_id(recip["target_id"])
                if p:
                    self.assertEqual(p["kind"], "human", f"Alert sent to non-human: {p}")

        # Check backoff counter incremented
        agent_row = hub.storage.v3.get_principal_by_id(self.carlos_id)
        self.assertEqual(agent_row.get("stalled_alert_count"), 1)

        # Immediate second run: should NOT alert due to backoff
        await hub.check_and_alert_stalled_agents()
        agent_row2 = hub.storage.v3.get_principal_by_id(self.carlos_id)
        self.assertEqual(agent_row2.get("stalled_alert_count"), 1)

        # Simulate 11 minutes elapsed: should alert second time
        past_alert_dt = (datetime.now(timezone.utc) - timedelta(seconds=650)).strftime("%Y-%m-%dT%H:%M:%SZ")
        conn = hub.storage.v3._get_connection()
        with conn:
            conn.execute("UPDATE agents SET last_stalled_alert_at = ? WHERE principal_id = ?;", (past_alert_dt, self.carlos_id))

        await hub.check_and_alert_stalled_agents()
        agent_row3 = hub.storage.v3.get_principal_by_id(self.carlos_id)
        self.assertEqual(agent_row3.get("stalled_alert_count"), 2)

    async def test_05_recovery_alert_when_agent_resumes(self):
        """When an alerted stalled agent resumes listening or activity, recovery alert is emitted."""
        # Ensure agent had an active stalled alert
        hub.storage.v3.record_stalled_alert(self.carlos_id)

        # Carlos resumes by sending a message
        geral = hub.storage.v3.get_room("geral")
        await hub.send_message(
            room_name="geral",
            sender="carlos",
            content="Estou de volta e a trabalhar no PR.",
            member_token=self.carlos_token,
        )

        # Verify recovery alert in room
        messages = hub.storage.v3.get_messages(geral["id"], limit=5)
        recovery_msgs = [m for m in messages if "✅ @carlos voltou a" in m["content"]]
        self.assertTrue(len(recovery_msgs) > 0, "Recovery message was not found")

        # Stalled alert counter should be reset to 0
        agent_row = hub.storage.v3.get_principal_by_id(self.carlos_id)
        self.assertEqual(agent_row.get("stalled_alert_count", 0), 0)

    async def test_06_reliable_delivery_ack_and_redelivery(self):
        """Verifies unconfirmed batch redelivery when ack is missing or 0."""
        geral = hub.storage.v3.get_room("geral")

        # Ana sends a message directed to Carlos
        res_m = await hub.send_message(
            room_name="geral",
            sender="ana",
            content="@carlos tarefa urgente para entrega fiável.",
            member_token=self.ana_token,
        )
        msg_id = res_m["id"]

        # Carlos calls wait_for_work with timeout 0 to inspect immediate work
        work1 = await hub.wait_for_work(
            room_name="geral",
            agent_name="carlos",
            timeout_seconds=0,
            ack=0,
        )
        self.assertIn(work1.get("status"), ("new_work", "new_messages"))
        self.assertFalse(work1.get("redelivered", False))
        delivered_ids = [m["id"] for m in work1.get("messages", [])]
        self.assertIn(msg_id, delivered_ids)

        # Batch is unconfirmed in DB
        agent_row = hub.storage.v3.get_principal_by_id(self.carlos_id)
        self.assertTrue(agent_row.get("unconfirmed_batch_ids"))

        # Carlos calls again without ACK -> redelivered = True
        work2 = await hub.wait_for_work(
            room_name="geral",
            agent_name="carlos",
            timeout_seconds=0,
            ack=0,
        )
        self.assertIn(work2.get("status"), ("new_work", "new_messages"))
        self.assertTrue(work2.get("redelivered"))

        # Carlos confirms with ACK = msg_id
        work3 = await hub.wait_for_work(
            room_name="geral",
            agent_name="carlos",
            timeout_seconds=0,
            ack=msg_id,
        )
        # Batch should now be confirmed and cleared
        agent_row_ack = hub.storage.v3.get_principal_by_id(self.carlos_id)
        self.assertFalse(agent_row_ack.get("unconfirmed_batch_ids"))

    def test_07_team_status_and_read_receipts(self):
        """Verifies team_status tool and read receipts (✓ / ✓✓)."""
        # MCP team_status authenticated as ana
        tok = current_auth_token.set(self.ana_token)
        pr = current_principal.set(hub.storage.v3.get_principal_by_id(self.ana_id))
        try:
            status_raw = tool_team_status(room_name="geral")
        finally:
            current_auth_token.reset(tok)
            current_principal.reset(pr)

        status = json.loads(status_raw) if isinstance(status_raw, str) else status_raw
        self.assertEqual(status.get("status"), "success")
        self.assertEqual(status.get("room"), "geral")
        members = status.get("members", [])
        self.assertTrue(len(members) >= 2)
        ana_member = next((m for m in members if m["name"] == "ana"), None)
        self.assertIsNotNone(ana_member)
        self.assertIn("state_badge", ana_member)

        # REST endpoint team-status
        rest_res = self.client.get("/api/rooms/geral/team-status")
        self.assertEqual(rest_res.status_code, 200)
        rest_data = rest_res.json()
        self.assertEqual(rest_data.get("status"), "success")
        self.assertTrue(len(rest_data.get("team", [])) >= 2)

        # Read receipts verification
        geral = hub.storage.v3.get_room("geral")
        messages = hub.storage.v3.get_messages(geral["id"], limit=5)
        for m in messages:
            self.assertIn("read_receipt", m)
            self.assertIn(m["read_receipt"], ("✓", "✓✓"))
            self.assertIn("read_status", m)

    async def test_08_deprecated_tools_raise_and_log_audit(self):
        """Verifies 12 deprecated tools return explicit deprecation notices and log to audit."""
        tok = current_auth_token.set(self.ana_token)
        pr = current_principal.set(hub.storage.v3.get_principal_by_id(self.ana_id))
        try:
            dep_tools = [
                ("join_room", tool_join_room, {"room_name": "geral"}),
                ("leave_room", tool_leave_room, {"room_name": "geral"}),
                ("create_room", tool_create_room, {"room_name": "teste_nova"}),
                ("rotate_member_token", tool_rotate_member_token, {"room_name": "geral", "member_name": "ana"}),
                ("change_room_password", tool_change_room_password, {"room_name": "geral", "new_password": "p"}),
                ("kick_member", tool_kick_member, {"room_name": "geral", "member_to_kick": "carlos"}),
                ("archive_room", tool_archive_room, {"room_name": "geral"}),
                ("wake_up_call", tool_wake_up_call, {"room_name": "geral"}),
                ("get_room_audit_log", tool_get_room_audit_log, {"room_name": "geral"}),
                ("get_room_transcript", tool_get_room_transcript, {"room_name": "geral"}),
                ("check_new_messages", tool_check_new_messages, {"room_name": "geral"}),
                ("who_is_listening", tool_who_is_listening, {"room_name": "geral"}),
            ]

            for tool_name, func, kwargs in dep_tools:
                res = func(**kwargs)
                if hasattr(res, "__await__"):
                    res = await res
                parsed = json.loads(res) if isinstance(res, str) else res
                self.assertIn(parsed.get("status"), ("error", "deprecated"))
                self.assertIn("descontinuada", parsed.get("error", "").lower())

            # Verify audit log entries
            audit_entries = hub.storage.v3.list_audit_log(limit=50)
            dep_audits = [e for e in audit_entries["items"] if e.get("action") == "mcp_deprecated_call"]
            self.assertTrue(len(dep_audits) >= 12, f"Expected at least 12 mcp_deprecated_call audit logs, got {len(dep_audits)}")
        finally:
            current_auth_token.reset(tok)
            current_principal.reset(pr)

    def test_09_wake_profile_and_admin_settings_api(self):
        """Tests PATCH /api/admin/agents/{id}/wake-profile and GET/PATCH /api/admin/settings."""
        # 1. Update wake profile
        patch_wp = self.client.patch(
            f"/api/admin/agents/{self.ana_id}/wake-profile",
            json={"harness": "claude-code", "wake_mode": "hook"},
        )
        self.assertEqual(patch_wp.status_code, 200, patch_wp.text)
        ana_row = hub.storage.v3.get_principal_by_id(self.ana_id)
        self.assertEqual(ana_row["harness"], "claude-code")
        self.assertEqual(ana_row["wake_mode"], "hook")

        # 2. Get admin settings
        get_sett = self.client.get("/api/admin/settings")
        self.assertEqual(get_sett.status_code, 200)
        sett = get_sett.json()["settings"]
        self.assertIn("t_idle_seconds", sett)
        self.assertIn("t_unread_seconds", sett)
        self.assertIn("max_wake_timeout", sett)

        # 3. Patch admin settings
        patch_sett = self.client.patch(
            "/api/admin/settings",
            json={"t_idle_seconds": 240, "t_unread_seconds": 150, "max_wake_timeout": 900},
        )
        self.assertEqual(patch_sett.status_code, 200)
        updated_sett = patch_sett.json()["settings"]
        self.assertEqual(updated_sett["t_idle_seconds"], 240)
        self.assertEqual(updated_sett["t_unread_seconds"], 150)
        self.assertEqual(updated_sett["max_wake_timeout"], 900)


if __name__ == "__main__":
    unittest.main()
