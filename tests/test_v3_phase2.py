"""
Comprehensive test suite for ai-chat v3 Phase 2 (Addressing and Wake-Up).

Objectives tested:
1. Structured Addressing (`to` / `recipients`):
   - Maps 'all', '@role_key', '@callsign', and comma/list to `message_recipients`.
   - Populates `msg['recipients']` and `msg['to']` in get_message_by_id and get_messages.
   - Rejects unknown recipients.
2. Server-Side Read Cursors in Wake-up (`read_cursors`):
   - Replaces client-managed since_id with read_cursors(principal_id, room_id, last_message_id).
   - Resolves multi-room message loss in 'subscribed' mode.
3. Observers & Selective Wake-up:
   - Observers (`can_write = 0` in `room_access`) never wake up on 'all'; only when explicitly targeted.
   - Targeted messages only wake matching principals or matching roles.
   - Senders never wake up on their own messages.
4. Role Reminders on Wake-up:
   - Returns agent's room-specific `agent_roles.reminder_text` once per wake-up.
5. Agent Cycle Protection:
   - Detects and breaks runaway consecutive agent loops without human intervention.
   - Resets strictly upon human intervention.
"""
import asyncio
import os
from pathlib import Path
import tempfile
import unittest

from aichat.crypto import new_agent_token, hash_password
from aichat.storage import ChatStorage
from aichat.storage_v3 import StorageV3
from aichat.hub import ChatHub


class TestV3StructuredAddressing(unittest.TestCase):
    """Verifies structured addressing mapping, persistence, and queries."""

    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.storage = StorageV3(self.tmp_dir / "test_v3.db", logs_dir=self.tmp_dir / "logs")

        # Setup test principals
        self.admin_id = self.storage.create_principal(kind="human", name="RuiAdmin")
        self.dev_id = self.storage.create_principal(kind="agent", name="DevAgent")
        self.qa_id = self.storage.create_principal(kind="agent", name="QAAgent")

        # Link dev to 'developer' role and qa to 'qa' role
        dev_role = self.storage.get_role_by_key("developer")
        qa_role = self.storage.get_role_by_key("qa")
        conn = self.storage._get_connection()
        with conn:
            conn.execute("INSERT INTO agents (principal_id, default_role_id) VALUES (?, ?);", (self.dev_id, dev_role["id"]))
            conn.execute("INSERT INTO agents (principal_id, default_role_id) VALUES (?, ?);", (self.qa_id, qa_role["id"]))

        # Create room
        self.room_id = self.storage.create_room("project-alpha", created_by=self.admin_id)["id"]
        self.storage.grant_room_access(self.room_id, self.dev_id, role_id=dev_role["id"])
        self.storage.grant_room_access(self.room_id, self.qa_id, role_id=qa_role["id"])

    def tearDown(self):
        self.storage.close()

    def test_resolve_recipients_all(self):
        r1 = self.storage.resolve_recipients(None)
        self.assertEqual(r1, [{"target_kind": "all", "target_id": None, "target_name": "all"}])

        r2 = self.storage.resolve_recipients("all")
        self.assertEqual(r2, [{"target_kind": "all", "target_id": None, "target_name": "all"}])

        r3 = self.storage.resolve_recipients(["all"])
        self.assertEqual(r3, [{"target_kind": "all", "target_id": None, "target_name": "all"}])

    def test_resolve_recipients_roles(self):
        dev_role = self.storage.get_role_by_key("developer")
        r = self.storage.resolve_recipients("@developer")
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["target_kind"], "role")
        self.assertEqual(r[0]["target_id"], dev_role["id"])
        self.assertEqual(r[0]["target_name"], "developer")

    def test_resolve_recipients_principals(self):
        r = self.storage.resolve_recipients("@DevAgent")
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["target_kind"], "principal")
        self.assertEqual(r[0]["target_id"], self.dev_id)
        self.assertEqual(r[0]["target_name"], "DevAgent")

    def test_resolve_recipients_multiple_and_deduplication(self):
        dev_role = self.storage.get_role_by_key("developer")
        r = self.storage.resolve_recipients("@developer, DevAgent, @developer")
        self.assertEqual(len(r), 2)
        kinds = {(item["target_kind"], item["target_id"]) for item in r}
        self.assertIn(("role", dev_role["id"]), kinds)
        self.assertIn(("principal", self.dev_id), kinds)

    def test_resolve_recipients_unknown_raises_error(self):
        with self.assertRaises(ValueError) as ctx:
            self.storage.resolve_recipients("@NonExistentBot")
        self.assertIn("não encontrado", str(ctx.exception))

    def test_add_and_retrieve_message_with_recipients(self):
        msg = self.storage.add_message(
            room_name_or_id=self.room_id,
            sender="RuiAdmin",
            content="Task for dev team",
            role="human",
            to="@developer, QAAgent",
        )
        self.assertEqual(msg["sender"], "RuiAdmin")
        self.assertIn("@developer", msg["to"])
        self.assertIn("@QAAgent", msg["to"])

        # Fetch by ID
        fetched = self.storage.get_message_by_id(msg["id"])
        self.assertIsNotNone(fetched)
        self.assertEqual(len(fetched["recipients"]), 2)
        self.assertIn("@developer", fetched["to"])
        self.assertIn("@QAAgent", fetched["to"])

        # Fetch in list
        msgs = self.storage.get_messages(self.room_id)
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0]["to"], fetched["to"])


class TestV3ReadCursorsAndWakeup(unittest.IsolatedAsyncioTestCase):
    """Verifies server-side read_cursors in wait_for_new_messages and multi-room handling."""

    async def asyncSetUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.db_path = self.tmp_dir / "test_v3.db"
        self.storage_v3 = StorageV3(self.db_path, logs_dir=self.tmp_dir / "logs")

        # ChatStorage wrapper for ChatHub
        self.chat_storage = ChatStorage(self.db_path)
        self.chat_storage.v3 = self.storage_v3
        self.chat_storage._is_v3 = True

        self.hub = ChatHub(storage=self.chat_storage)

        # Setup principals and tokens
        self.admin_id = self.storage_v3.create_principal(kind="human", name="Rui")
        self.agent1_id = self.storage_v3.create_principal(kind="agent", name="Agent1")
        self.agent2_id = self.storage_v3.create_principal(kind="agent", name="Agent2")

        self.tok1, _ = self.storage_v3.rotate_agent_token(self.agent1_id)
        self.tok2, _ = self.storage_v3.rotate_agent_token(self.agent2_id)

        # Create two rooms
        self.room_a_id = self.storage_v3.create_room("room-a")["id"]
        self.room_b_id = self.storage_v3.create_room("room-b")["id"]

        # Grant access to Agent2
        self.storage_v3.grant_room_access(self.room_a_id, self.agent2_id, can_write=1)
        self.storage_v3.grant_room_access(self.room_b_id, self.agent2_id, can_write=1)

    async def asyncTearDown(self):
        self.storage_v3.close()

    async def test_read_cursor_advances_and_prevents_re_reading_past(self):
        """When since_id=0, read_cursor is initialized to max_id, and updates on delivery."""
        # 1. Past message sent before Agent1 was granted access to room-a
        await self.hub.send_message("room-a", "Agent2", "Old message", role="agent", member_token=self.tok2)

        # Grant access to Agent1 (sets cursor to max_id = 1)
        self.storage_v3.grant_room_access(self.room_a_id, self.agent1_id, can_write=1)

        # Agent1 starts waiting with since_id=0 -> should NOT receive 'Old message'
        wait_task = asyncio.create_task(
            self.hub.wait_for_new_messages(
                room_name="room-a",
                agent_name="Agent1",
                since_id=0,
                timeout_seconds=2.0,
            )
        )
        await asyncio.sleep(0.05)
        self.assertFalse(wait_task.done())

        # Agent2 sends new message
        await self.hub.send_message("room-a", "Agent2", "New message 1", role="agent", member_token=self.tok2)
        res = await asyncio.wait_for(wait_task, timeout=2.0)

        self.assertEqual(res["status"], "new_messages")
        self.assertEqual(len(res["messages"]), 1)
        self.assertEqual(res["messages"][0]["content"], "New message 1")

        # Verify cursor in DB advanced to message 2
        cursor_in_db = self.storage_v3.get_read_cursor(self.agent1_id, self.room_a_id)
        self.assertEqual(cursor_in_db, res["messages"][0]["id"])

        # 2. While Agent1 is offline / processing, Agent2 sends another message
        msg3 = await self.hub.send_message("room-a", "Agent2", "New message 2", role="agent", member_token=self.tok2)

        # Agent1 calls wait_for_new_messages again with since_id=0 -> receives message 2 immediately!
        res2 = await self.hub.wait_for_new_messages(
            room_name="room-a",
            agent_name="Agent1",
            since_id=0,
            timeout_seconds=2.0,
        )
        self.assertEqual(res2["status"], "new_messages")
        self.assertEqual(len(res2["messages"]), 1)
        self.assertEqual(res2["messages"][0]["content"], "New message 2")
        self.assertEqual(res2["messages"][0]["id"], msg3["id"])

    async def test_subscribed_multi_room_no_message_loss(self):
        """In subscribed mode across multiple rooms, server-side cursors eliminate message loss."""
        # Agent1 has access to both rooms
        self.storage_v3.grant_room_access(self.room_a_id, self.agent1_id, can_write=1)
        self.storage_v3.grant_room_access(self.room_b_id, self.agent1_id, can_write=1)

        # Agent1 initializes listening on subscribed rooms
        wait_task = asyncio.create_task(
            self.hub.wait_for_new_messages(
                room_name="subscribed",
                agent_name="Agent1",
                since_id=0,
                timeout_seconds=2.0,
            )
        )
        await asyncio.sleep(0.05)

        # Message in room-a
        await self.hub.send_message("room-a", "Agent2", "Message in A", role="agent", member_token=self.tok2)
        res_a = await asyncio.wait_for(wait_task, timeout=2.0)
        self.assertEqual(res_a["status"], "new_messages")
        self.assertEqual(res_a["messages"][0]["content"], "Message in A")

        # Now while Agent1 is offline, a message arrives in room-b
        msg_b = await self.hub.send_message("room-b", "Agent2", "Message in B", role="agent", member_token=self.tok2)

        # Agent1 resumes listening on subscribed: immediately receives message from room-b without loss!
        res_b = await self.hub.wait_for_new_messages(
            room_name="subscribed",
            agent_name="Agent1",
            since_id=0,
            timeout_seconds=2.0,
        )
        self.assertEqual(res_b["status"], "new_messages")
        self.assertEqual(len(res_b["messages"]), 1)
        self.assertEqual(res_b["messages"][0]["content"], "Message in B")
        self.assertEqual(res_b["messages"][0]["room_name"], "room-b")


class TestV3ObserversAndSelectiveWakeup(unittest.IsolatedAsyncioTestCase):
    """Verifies that observers (can_write=0) do not wake on 'all', only on explicit targeting."""

    async def asyncSetUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.db_path = self.tmp_dir / "test_v3.db"
        self.storage_v3 = StorageV3(self.db_path, logs_dir=self.tmp_dir / "logs")

        self.chat_storage = ChatStorage(self.db_path)
        self.chat_storage.v3 = self.storage_v3
        self.chat_storage._is_v3 = True

        self.hub = ChatHub(storage=self.chat_storage)

        self.admin_id = self.storage_v3.create_principal(kind="human", name="Rui")
        self.writer_id = self.storage_v3.create_principal(kind="agent", name="WriterAgent")
        self.observer_id = self.storage_v3.create_principal(kind="agent", name="ObserverAgent")

        self.tok_writer, _ = self.storage_v3.rotate_agent_token(self.writer_id)
        self.tok_observer, _ = self.storage_v3.rotate_agent_token(self.observer_id)

        qa_role = self.storage_v3.get_role_by_key("qa")
        conn = self.storage_v3._get_connection()
        with conn:
            conn.execute("INSERT INTO agents (principal_id, default_role_id) VALUES (?, ?);", (self.observer_id, qa_role["id"]))

        self.room_id = self.storage_v3.create_room("collab-room")["id"]
        # Writer: can_write = 1
        self.storage_v3.grant_room_access(self.room_id, self.writer_id, can_write=1)
        # Observer: can_write = 0
        self.storage_v3.grant_room_access(self.room_id, self.observer_id, role_id=qa_role["id"], can_write=0)

    async def asyncTearDown(self):
        self.storage_v3.close()

    async def test_observer_ignores_broadcast_all(self):
        """An observer with can_write=0 must NOT wake up on messages addressed to 'all'."""
        observer_wait = asyncio.create_task(
            self.hub.wait_for_new_messages(
                room_name="collab-room",
                agent_name="ObserverAgent",
                since_id=0,
                timeout_seconds=0.6,
            )
        )
        await asyncio.sleep(0.05)

        # Writer posts broadcast to "all"
        await self.hub.send_message(
            "collab-room",
            "WriterAgent",
            "Broadcast for all active workers",
            role="agent",
            member_token=self.tok_writer,
            to="all",
        )

        # Observer should timeout and receive 0 messages
        res = await observer_wait
        self.assertEqual(res["status"], "timeout")
        self.assertEqual(res["count"], 0)

    async def test_observer_wakes_on_explicit_principal_target(self):
        """An observer DOES wake up when explicitly targeted by its callsign / principal."""
        observer_wait = asyncio.create_task(
            self.hub.wait_for_new_messages(
                room_name="collab-room",
                agent_name="ObserverAgent",
                since_id=0,
                timeout_seconds=2.0,
            )
        )
        await asyncio.sleep(0.05)

        # Writer targets @ObserverAgent directly
        await self.hub.send_message(
            "collab-room",
            "WriterAgent",
            "Review needed, please check this output.",
            role="agent",
            member_token=self.tok_writer,
            to="@ObserverAgent",
        )

        res = await asyncio.wait_for(observer_wait, timeout=1.5)
        self.assertEqual(res["status"], "new_messages")
        self.assertEqual(len(res["messages"]), 1)
        self.assertEqual(res["messages"][0]["content"], "Review needed, please check this output.")

    async def test_observer_wakes_on_explicit_role_target(self):
        """An observer DOES wake up when targeted by its assigned role."""
        observer_wait = asyncio.create_task(
            self.hub.wait_for_new_messages(
                room_name="collab-room",
                agent_name="ObserverAgent",
                since_id=0,
                timeout_seconds=2.0,
            )
        )
        await asyncio.sleep(0.05)

        # Writer targets @qa
        await self.hub.send_message(
            "collab-room",
            "WriterAgent",
            "Calling all QA: test report ready",
            role="agent",
            member_token=self.tok_writer,
            to="@qa",
        )

        res = await asyncio.wait_for(observer_wait, timeout=1.5)
        self.assertEqual(res["status"], "new_messages")
        self.assertEqual(len(res["messages"]), 1)
        self.assertEqual(res["messages"][0]["content"], "Calling all QA: test report ready")


class TestV3RoleReminders(unittest.IsolatedAsyncioTestCase):
    """Verifies that role reminders are delivered once per wake-up."""

    async def asyncSetUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.db_path = self.tmp_dir / "test_v3.db"
        self.storage_v3 = StorageV3(self.db_path, logs_dir=self.tmp_dir / "logs")

        self.chat_storage = ChatStorage(self.db_path)
        self.chat_storage.v3 = self.storage_v3
        self.chat_storage._is_v3 = True

        self.hub = ChatHub(storage=self.chat_storage)

        self.admin_id = self.storage_v3.create_principal(kind="human", name="Rui")
        self.dev_id = self.storage_v3.create_principal(kind="agent", name="DevAgent")

        self.dev_token, _ = self.storage_v3.rotate_agent_token(self.dev_id)

        # Assign developer role
        dev_role = self.storage_v3.get_role_by_key("developer")
        conn = self.storage_v3._get_connection()
        with conn:
            conn.execute("INSERT INTO agents (principal_id, default_role_id) VALUES (?, ?);", (self.dev_id, dev_role["id"]))

        self.room_id = self.storage_v3.create_room("dev-room")["id"]
        self.storage_v3.grant_room_access(self.room_id, self.dev_id, role_id=dev_role["id"], can_write=1)

    async def asyncTearDown(self):
        self.storage_v3.close()

    async def test_role_reminder_present_in_wait_response(self):
        wait_task = asyncio.create_task(
            self.hub.wait_for_new_messages(
                room_name="dev-room",
                agent_name="DevAgent",
                since_id=0,
                timeout_seconds=2.0,
            )
        )
        await asyncio.sleep(0.05)

        # Human posts a message
        await self.hub.send_message(
            "dev-room",
            "Rui",
            "Please fix the bug in module A",
            role="human",
            human_token=self.hub.human_token,
        )

        res = await asyncio.wait_for(wait_task, timeout=1.5)
        self.assertEqual(res["status"], "new_messages")
        self.assertIn("role_reminder", res)
        self.assertTrue(res["role_reminder"].startswith("Tu és o Programador"))

    def test_role_reminder_in_check_new_messages(self):
        # Post message first
        self.storage_v3.add_message(
            room_name_or_id=self.room_id,
            sender="Rui",
            role="human",
            content="Task waiting",
            is_verified=True,
        )
        # Check new messages
        res = self.hub.check_new_messages("dev-room", agent_name="DevAgent", since_id=0)
        self.assertIn("role_reminder", res)
        self.assertTrue(res["role_reminder"].startswith("Tu és o Programador"))


class TestV3AgentCycleProtection(unittest.IsolatedAsyncioTestCase):
    """Verifies that consecutive agent-to-agent message loops are halted until human intervention."""

    async def asyncSetUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.db_path = self.tmp_dir / "test_v3.db"
        self.storage_v3 = StorageV3(self.db_path, logs_dir=self.tmp_dir / "logs")

        self.chat_storage = ChatStorage(self.db_path)
        self.chat_storage.v3 = self.storage_v3
        self.chat_storage._is_v3 = True

        self.hub = ChatHub(storage=self.chat_storage)

        self.admin_id = self.storage_v3.create_principal(kind="human", name="Rui")
        self.bot1_id = self.storage_v3.create_principal(kind="agent", name="Bot1")
        self.bot2_id = self.storage_v3.create_principal(kind="agent", name="Bot2")

        self.tok1, _ = self.storage_v3.rotate_agent_token(self.bot1_id)
        self.tok2, _ = self.storage_v3.rotate_agent_token(self.bot2_id)

        self.room_id = self.storage_v3.create_room("loop-room")["id"]
        self.storage_v3.grant_room_access(self.room_id, self.bot1_id, can_write=1)
        self.storage_v3.grant_room_access(self.room_id, self.bot2_id, can_write=1)

    async def asyncTearDown(self):
        self.storage_v3.close()

    async def test_cycle_protection_triggers_and_resets_on_human_message(self):
        # Temporarily configure low threshold of 3 for fast testing
        os.environ["AICHAT_MAX_AGENT_CYCLES"] = "3"
        try:
            # Agent turn 1 (directed to Bot2)
            await self.hub.send_message("loop-room", "Bot1", "Ping 1", role="agent", member_token=self.tok1, to="@Bot2")
            self.assertEqual(self.storage_v3.count_consecutive_agent_messages(self.room_id), 1)

            # Agent turn 2 (directed to Bot1)
            await self.hub.send_message("loop-room", "Bot2", "Pong 1", role="agent", member_token=self.tok2, to="@Bot1")
            self.assertEqual(self.storage_v3.count_consecutive_agent_messages(self.room_id), 2)

            # Agent turn 3 (reaches threshold limit 3)
            await self.hub.send_message("loop-room", "Bot1", "Ping 2", role="agent", member_token=self.tok1, to="@Bot2")
            self.assertEqual(self.storage_v3.count_consecutive_agent_messages(self.room_id), 3)

            # Agent turn 4 -> must be blocked by cycle protection!
            with self.assertRaises(ValueError) as ctx:
                await self.hub.send_message("loop-room", "Bot2", "Pong 2", role="agent", member_token=self.tok2, to="@Bot1")
            self.assertIn("Proteção de ciclo ativada", str(ctx.exception))

            # System message alerting humans was published
            recent = self.storage_v3.get_messages(self.room_id, limit=5)
            sys_msgs = [m for m in recent if m["role"] == "system" and "Proteção de ciclo ativada" in m["content"]]
            self.assertTrue(len(sys_msgs) >= 1)

            # System message does not reset the human requirement
            self.storage_v3.add_message(
                room_name_or_id=self.room_id,
                sender="System",
                role="system",
                content="[System notification]",
                is_verified=True,
            )
            self.assertEqual(self.storage_v3.count_consecutive_agent_messages(self.room_id), 3)

            # Bot2 still blocked
            with self.assertRaises(ValueError):
                await self.hub.send_message("loop-room", "Bot2", "Pong 2", role="agent", member_token=self.tok2)

            # Human intervenes
            await self.hub.send_message(
                "loop-room",
                "Rui",
                "Aprovado, podem continuar.",
                role="human",
                human_token=self.hub.human_token,
            )
            # Counter is reset to 0!
            self.assertEqual(self.storage_v3.count_consecutive_agent_messages(self.room_id), 0)

            # Agents can now converse again!
            msg_ok = await self.hub.send_message("loop-room", "Bot1", "Ping 3 after human reset", role="agent", member_token=self.tok1, to="@Bot2")
            self.assertEqual(msg_ok["content"], "Ping 3 after human reset")
            self.assertEqual(self.storage_v3.count_consecutive_agent_messages(self.room_id), 1)
        finally:
            os.environ.pop("AICHAT_MAX_AGENT_CYCLES", None)


class TestV3Phase2ReviewFixes(unittest.IsolatedAsyncioTestCase):
    """
    Direct regression tests for QC review feedback points (1) through (6):
    1. Message loss with cursor 0 & cursor > 0 with >50 messages
    2. Read cursor creation in grant_room_access
    3. Cycle protection system notification & agent-to-agent only count
    4. Rejecting recipients without room access
    5. Ambiguity between role and callsign & prefix disambiguation
    6. check_new_messages without new messages does not dump 20 recent messages; wake-up includes skipped IDs
    """

    async def asyncSetUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.db_path = self.tmp_dir / "test_v3.db"
        self.storage_v3 = StorageV3(self.db_path, logs_dir=self.tmp_dir / "logs")

        self.chat_storage = ChatStorage(self.db_path)
        self.chat_storage.v3 = self.storage_v3
        self.chat_storage._is_v3 = True

        self.hub = ChatHub(storage=self.chat_storage)

        self.admin_id = self.storage_v3.create_principal(kind="human", name="RuiAdmin")
        self.agent_x_id = self.storage_v3.create_principal(kind="agent", name="AgentX")
        self.agent_y_id = self.storage_v3.create_principal(kind="agent", name="AgentY")

        self.tok_x, _ = self.storage_v3.rotate_agent_token(self.agent_x_id)
        self.tok_y, _ = self.storage_v3.rotate_agent_token(self.agent_y_id)

        self.room = self.storage_v3.create_room("qc-room", created_by=self.admin_id)
        self.room_id = self.room["id"]
        self.storage_v3.grant_room_access(self.room_id, self.agent_x_id, can_write=1)
        self.storage_v3.grant_room_access(self.room_id, self.agent_y_id, can_write=1)

    async def asyncTearDown(self):
        self.storage_v3.close()

    async def test_repro_1a_cursor_zero_more_than_50_messages_no_loss(self):
        """(1A) Cursor 0 in empty room, msg 1 to X, 60 msgs to Y: X must receive msg 1 without loss."""
        # Ensure Agent X has cursor at 0
        conn = self.storage_v3._get_connection()
        with conn:
            conn.execute("UPDATE read_cursors SET last_message_id = 0 WHERE principal_id = ? AND room_id = ?;", (self.agent_x_id, self.room_id))

        # Message 1 sent to AgentX
        await self.hub.send_message("qc-room", "AgentY", "Msg 1 to X", role="agent", member_token=self.tok_y, to="@AgentX")

        # 60 messages sent to AgentY
        for i in range(2, 62):
            await self.hub.send_message("qc-room", "RuiAdmin", f"Msg {i} to Y", role="human", human_token=self.hub.human_token, to="@AgentY")

        # AgentX checks unread messages with cursor 0
        res = await self.hub.wait_for_new_messages(
            room_name="qc-room",
            agent_name="AgentX",
            since_id=0,
            timeout_seconds=2.0,
        )
        self.assertEqual(res["status"], "new_messages")
        self.assertEqual(len(res["messages"]), 1)
        self.assertEqual(res["messages"][0]["content"], "Msg 1 to X")
        self.assertEqual(res["skipped_count"], 60)
        # Verify read_cursor in DB moved to 61
        cur_db = self.storage_v3.get_read_cursor(self.agent_x_id, self.room_id)
        self.assertEqual(cur_db, 61)

    async def test_repro_1b_cursor_gt_zero_more_than_50_messages_no_loss(self):
        """(1B) Cursor > 0, 60 msgs to others before msg to X: X receives msg without timeout."""
        # Send 10 initial messages
        for i in range(1, 11):
            await self.hub.send_message("qc-room", "RuiAdmin", f"Init {i}", role="human", human_token=self.hub.human_token, to="all")

        # Agent X cursor is at 10
        self.storage_v3.update_read_cursor(self.agent_x_id, self.room_id, 10)

        # 60 messages sent to AgentY (IDs 11..70)
        for i in range(11, 71):
            await self.hub.send_message("qc-room", "RuiAdmin", f"Other {i}", role="human", human_token=self.hub.human_token, to="@AgentY")

        # Message 71 sent to AgentX
        await self.hub.send_message("qc-room", "AgentY", "Targeted 71", role="agent", member_token=self.tok_y, to="@AgentX")

        # Agent X waits: must immediately receive Message 71
        res = await self.hub.wait_for_new_messages(
            room_name="qc-room",
            agent_name="AgentX",
            since_id=0,
            timeout_seconds=2.0,
        )
        self.assertEqual(res["status"], "new_messages")
        self.assertEqual(len(res["messages"]), 1)
        self.assertEqual(res["messages"][0]["content"], "Targeted 71")
        self.assertEqual(res["skipped_count"], 60)
        self.assertEqual(self.storage_v3.get_read_cursor(self.agent_x_id, self.room_id), 71)

    async def test_repro_2_grant_room_access_creates_cursor_no_message_loss(self):
        """(2) Cursor is created in grant_room_access: new member does not lose messages sent before first wait."""
        # 5 messages posted to room
        for i in range(1, 6):
            await self.hub.send_message("qc-room", "RuiAdmin", f"Early {i}", role="human", human_token=self.hub.human_token, to="all")

        # Create new agent and grant access
        new_bot_id = self.storage_v3.create_principal(kind="agent", name="NewBot")
        self.storage_v3.grant_room_access(self.room_id, new_bot_id, can_write=1)

        # Cursor exists and is set to 5
        self.assertTrue(self.storage_v3.has_read_cursor(new_bot_id, self.room_id))
        self.assertEqual(self.storage_v3.get_read_cursor(new_bot_id, self.room_id), 5)

        # Message 6 posted for NewBot
        await self.hub.send_message("qc-room", "RuiAdmin", "Task for NewBot", role="human", human_token=self.hub.human_token, to="@NewBot")

        # NewBot waits for new messages for the first time
        res = await self.hub.wait_for_new_messages(
            room_name="qc-room",
            agent_name="NewBot",
            since_id=0,
            timeout_seconds=2.0,
        )
        self.assertEqual(res["status"], "new_messages")
        self.assertEqual(len(res["messages"]), 1)
        self.assertEqual(res["messages"][0]["content"], "Task for NewBot")

    async def test_repro_3_cycle_protection_agent_to_agent_only_and_system_notification(self):
        """(3) Cycle protection counts agent messages (except those directed only to humans) and posts a system message on trigger."""
        os.environ["AICHAT_MAX_AGENT_CYCLES"] = "2"
        try:
            # 5 messages from agent directed to human: should NOT increment cycle counter
            for i in range(5):
                await self.hub.send_message("qc-room", "AgentX", f"Update to human {i}", role="agent", member_token=self.tok_x, to="@RuiAdmin")
            self.assertEqual(self.storage_v3.count_consecutive_agent_messages(self.room_id), 0)

            # Agent-to-agent message 1
            await self.hub.send_message("qc-room", "AgentX", "A2A 1", role="agent", member_token=self.tok_x, to="@AgentY")
            self.assertEqual(self.storage_v3.count_consecutive_agent_messages(self.room_id), 1)

            # Agent-to-agent message 2 (reaches threshold 2)
            await self.hub.send_message("qc-room", "AgentY", "A2A 2", role="agent", member_token=self.tok_y, to="@AgentX")
            self.assertEqual(self.storage_v3.count_consecutive_agent_messages(self.room_id), 2)

            # Agent-to-agent message 3 -> triggers cycle protection!
            with self.assertRaises(ValueError) as ctx:
                await self.hub.send_message("qc-room", "AgentX", "A2A 3", role="agent", member_token=self.tok_x, to="@AgentY")
            self.assertIn("Proteção de ciclo ativada", str(ctx.exception))

            # System warning message was posted to the room
            msgs = self.storage_v3.get_messages(self.room_id, limit=3)
            sys_msg = next((m for m in msgs if m["role"] == "system" and "Proteção de ciclo ativada" in m["content"]), None)
            self.assertIsNotNone(sys_msg)
            # Verify system warning is targeted only to humans
            recips = self.storage_v3.get_message_recipients(sys_msg["id"])
            self.assertTrue(all(r["target_principal_kind"] == "human" for r in recips))
        finally:
            os.environ.pop("AICHAT_MAX_AGENT_CYCLES", None)

    def test_repro_4_reject_recipients_without_room_access(self):
        """(4) Reject messages targeting principal or role without access to the room."""
        # Non-member agent
        outsider_id = self.storage_v3.create_principal(kind="agent", name="OutsiderBot")
        with self.assertRaises(ValueError) as ctx:
            self.storage_v3.add_message(self.room_id, sender="RuiAdmin", role="human", to="@OutsiderBot")
        self.assertIn("não tem acesso à sala", str(ctx.exception))

        # Role with no members in this room (qa exists in agent_roles, but not in qc-room)
        with self.assertRaises(ValueError) as ctx:
            self.storage_v3.add_message(self.room_id, sender="RuiAdmin", role="human", to="@qa")
        self.assertIn("não está atribuído a nenhum membro", str(ctx.exception))

    def test_repro_5_role_and_callsign_ambiguity_and_prefixes(self):
        """(5) Disambiguate role vs callsign with same name via prefixes; bare name raises ValueError."""
        # Create an agent named 'developer' colliding with role 'developer'
        dev_bot_id = self.storage_v3.create_principal(kind="agent", name="developer")

        # Explicit role prefix
        r_role = self.storage_v3.resolve_recipients("@role:developer")
        self.assertEqual(r_role[0]["target_kind"], "role")

        # Explicit agent prefix
        r_agent = self.storage_v3.resolve_recipients("@agent:developer")
        self.assertEqual(r_agent[0]["target_kind"], "principal")
        self.assertEqual(r_agent[0]["target_id"], dev_bot_id)

        # Ambiguous bare name raises ValueError
        with self.assertRaises(ValueError) as ctx:
            self.storage_v3.resolve_recipients("@developer")
        self.assertIn("é ambíguo", str(ctx.exception))

    async def test_repro_6_check_new_messages_no_recent_dump_and_skipped_ids(self):
        """(6) check_new_messages with no new messages does not dump 20 recent messages; wake-up returns skipped IDs."""
        # Post 5 messages targeting AgentY
        for i in range(1, 6):
            await self.hub.send_message("qc-room", "RuiAdmin", f"For Y {i}", role="human", human_token=self.hub.human_token, to="@AgentY")

        # AgentX checks for new messages: must NOT return the 5 messages
        chk = self.hub.check_new_messages(room_name="qc-room", agent_name="AgentX")
        self.assertFalse(chk["has_new"])
        self.assertEqual(chk["count"], 0)
        self.assertEqual(chk["messages"], [])
        self.assertEqual(chk["skipped_count"], 5)
        self.assertEqual(len(chk["skipped_ids"]), 5)

    async def test_review2_cycle_protection_triggers_on_to_all(self):
        """(Review 2 - 1) Cycle protection triggers when agents exchange messages with default to='all'."""
        os.environ["AICHAT_MAX_AGENT_CYCLES"] = "4"
        try:
            # 4 messages exchanged between agents with to="all"
            await self.hub.send_message("qc-room", "AgentX", "Msg 1", role="agent", member_token=self.tok_x, to="all")
            await self.hub.send_message("qc-room", "AgentY", "Msg 2", role="agent", member_token=self.tok_y, to="all")
            await self.hub.send_message("qc-room", "AgentX", "Msg 3", role="agent", member_token=self.tok_x, to="all")
            await self.hub.send_message("qc-room", "AgentY", "Msg 4", role="agent", member_token=self.tok_y, to="all")
            self.assertEqual(self.storage_v3.count_consecutive_agent_messages(self.room_id), 4)

            # 5th message must be blocked by cycle protection
            with self.assertRaises(ValueError) as ctx:
                await self.hub.send_message("qc-room", "AgentX", "Msg 5", role="agent", member_token=self.tok_x, to="all")
            self.assertIn("Proteção de ciclo ativada", str(ctx.exception))

            # Human intervention resets the cycle counter
            await self.hub.send_message("qc-room", "RuiAdmin", "Human intervention here", role="human", human_token=self.hub.human_token, to="all")
            self.assertEqual(self.storage_v3.count_consecutive_agent_messages(self.room_id), 0)

            # Agents can now resume chatting
            res = await self.hub.send_message("qc-room", "AgentX", "Resumed", role="agent", member_token=self.tok_x, to="all")
            self.assertEqual(res["content"], "Resumed")
            self.assertEqual(self.storage_v3.count_consecutive_agent_messages(self.room_id), 1)
        finally:
            os.environ.pop("AICHAT_MAX_AGENT_CYCLES", None)

    async def test_review2_cycle_warning_does_not_wake_bystander_agents(self):
        """(Review 2 - 2) Cycle warning notification is targeted only to room humans and does not wake bystander agents."""
        os.environ["AICHAT_MAX_AGENT_CYCLES"] = "2"
        try:
            # Create a bystander agent with access to qc-room
            bystander_id = self.storage_v3.create_principal(kind="agent", name="BystanderAgent")
            self.storage_v3.grant_room_access(self.room_id, bystander_id, can_write=1)

            # BystanderAgent starts waiting for new messages
            wait_task = asyncio.create_task(
                self.hub.wait_for_new_messages(
                    room_name="qc-room",
                    agent_name="BystanderAgent",
                    since_id=0,
                    timeout_seconds=0.5,
                )
            )
            # Give wait loop time to register listener
            await asyncio.sleep(0.05)

            # AgentX and AgentY send 2 messages to reach threshold, directed to each other
            await self.hub.send_message("qc-room", "AgentX", "Msg 1", role="agent", member_token=self.tok_x, to="@AgentY")
            await self.hub.send_message("qc-room", "AgentY", "Msg 2", role="agent", member_token=self.tok_y, to="@AgentX")

            # AgentX sends 3rd message, triggering cycle protection & system warning
            with self.assertRaises(ValueError):
                await self.hub.send_message("qc-room", "AgentX", "Msg 3", role="agent", member_token=self.tok_x, to="@AgentY")

            # Await BystanderAgent's wait_task - it should NOT have been woken by the cycle warning
            # Because it wasn't woken, it will hit its 0.5s timeout (status == 'timeout')
            res = await wait_task
            self.assertEqual(res["status"], "timeout")
            self.assertEqual(res["count"], 0)

            # Check that the system warning was indeed posted to the room and only targets the human(s)
            msgs = self.storage_v3.get_messages(self.room_id, limit=1)
            sys_msg = msgs[-1]
            self.assertEqual(sys_msg["role"], "system")
            self.assertIn("Proteção de ciclo ativada", sys_msg["content"])
            recips = self.storage_v3.get_message_recipients(sys_msg["id"])
            self.assertTrue(len(recips) > 0)
            self.assertTrue(all(r["target_principal_kind"] == "human" for r in recips))
        finally:
            os.environ.pop("AICHAT_MAX_AGENT_CYCLES", None)

    async def test_review2_skipped_ids_limited_and_ranges(self):
        """(Review 2 - 3) skipped_ids is capped at 20 while skipped_count is exact and skipped_ranges shows intervals."""
        # 60 messages targeting AgentY (IDs 1..60)
        for i in range(1, 61):
            await self.hub.send_message("qc-room", "RuiAdmin", f"For Y {i}", role="human", human_token=self.hub.human_token, to="@AgentY")

        # AgentX checks unread messages
        chk = self.hub.check_new_messages(room_name="qc-room", agent_name="AgentX")
        self.assertEqual(chk["skipped_count"], 60)
        self.assertEqual(len(chk["skipped_ids"]), 20)
        self.assertEqual(chk["skipped_ids"][:3], [1, 2, 3])
        self.assertEqual(chk["skipped_ids"][-3:], [58, 59, 60])
        self.assertEqual(chk["skipped_ranges"], ["1-60"])


if __name__ == "__main__":
    unittest.main()
