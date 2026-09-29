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

        # Grant access
        self.storage_v3.grant_room_access(self.room_a_id, self.agent1_id, can_write=1)
        self.storage_v3.grant_room_access(self.room_a_id, self.agent2_id, can_write=1)
        self.storage_v3.grant_room_access(self.room_b_id, self.agent1_id, can_write=1)
        self.storage_v3.grant_room_access(self.room_b_id, self.agent2_id, can_write=1)

    async def asyncTearDown(self):
        self.storage_v3.close()

    async def test_read_cursor_advances_and_prevents_re_reading_past(self):
        """When since_id=0, read_cursor is initialized to max_id, and updates on delivery."""
        # 1. Past message sent before Agent1 ever listened
        await self.hub.send_message("room-a", "Agent2", "Old message", role="agent", member_token=self.tok2)

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
            # Agent turn 1
            await self.hub.send_message("loop-room", "Bot1", "Ping 1", role="agent", member_token=self.tok1)
            self.assertEqual(self.storage_v3.count_consecutive_agent_messages(self.room_id), 1)

            # Agent turn 2
            await self.hub.send_message("loop-room", "Bot2", "Pong 1", role="agent", member_token=self.tok2)
            self.assertEqual(self.storage_v3.count_consecutive_agent_messages(self.room_id), 2)

            # Agent turn 3 (reaches threshold limit 3)
            await self.hub.send_message("loop-room", "Bot1", "Ping 2", role="agent", member_token=self.tok1)
            self.assertEqual(self.storage_v3.count_consecutive_agent_messages(self.room_id), 3)

            # Agent turn 4 -> must be blocked by cycle protection!
            with self.assertRaises(ValueError) as ctx:
                await self.hub.send_message("loop-room", "Bot2", "Pong 2", role="agent", member_token=self.tok2)
            self.assertIn("Proteção de ciclo ativada", str(ctx.exception))

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
            msg_ok = await self.hub.send_message("loop-room", "Bot1", "Ping 3 after human reset", role="agent", member_token=self.tok1)
            self.assertEqual(msg_ok["content"], "Ping 3 after human reset")
            self.assertEqual(self.storage_v3.count_consecutive_agent_messages(self.room_id), 1)
        finally:
            os.environ.pop("AICHAT_MAX_AGENT_CYCLES", None)


if __name__ == "__main__":
    unittest.main()
