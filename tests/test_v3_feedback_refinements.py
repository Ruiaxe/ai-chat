"""
Tests for Rui's feedback refinements:
1. Default t_idle is 30 minutes (1800s) instead of 3 minutes.
2. Cycle protection is disabled by default (AICHAT_MAX_AGENT_CYCLES=0).
3. list_rooms_for_principal returns message_count for both admin and regular principals.
"""
import os
import tempfile
import unittest
from pathlib import Path

from aichat.hub import ChatHub
from aichat.storage import ChatStorage
from aichat.storage_v3 import StorageV3


class TestFeedbackRefinements(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.db_path = self.tmp_dir / "test_feedback.db"
        self.storage_v3 = StorageV3(self.db_path, logs_dir=self.tmp_dir / "logs")

        self.chat_storage = ChatStorage(self.db_path)
        self.chat_storage.v3 = self.storage_v3
        self.chat_storage._is_v3 = True

        self.hub = ChatHub(storage=self.chat_storage)

        self.admin_id = self.storage_v3.create_human(
            username="admin", password="AdminPassword123!", display_name="Admin", access_role="admin"
        )
        self.user_id = self.storage_v3.create_human(
            username="user1", password="UserPassword123!", display_name="User 1", access_role="user"
        )
        self.agent1_id = self.storage_v3.create_principal(
            kind="agent", name="BotA", display_name="BotA"
        )
        self.agent2_id = self.storage_v3.create_principal(
            kind="agent", name="BotB", display_name="BotB"
        )

        self.tok1, _ = self.storage_v3.rotate_agent_token(self.agent1_id)
        self.tok2, _ = self.storage_v3.rotate_agent_token(self.agent2_id)

        self.room = self.storage_v3.create_room("general", created_by=self.admin_id)
        self.room_id = self.room["id"]

        self.storage_v3.grant_room_access(self.room_id, self.user_id, can_write=1)
        self.storage_v3.grant_room_access(self.room_id, self.agent1_id, can_write=1)
        self.storage_v3.grant_room_access(self.room_id, self.agent2_id, can_write=1)

    async def asyncTearDown(self):
        self.storage_v3.close()

    def test_default_t_idle_is_30_minutes(self):
        """Verify default t_idle is 1800s (30m) instead of 180s."""
        thresholds = self.storage_v3.get_system_thresholds()
        self.assertEqual(thresholds["t_idle_seconds"], 1800)
        self.assertEqual(thresholds["t_idle_minutes"], 30)

    def test_list_rooms_for_principal_includes_message_count(self):
        """Verify list_rooms_for_principal returns message_count for admin and member."""
        admin_p = self.storage_v3.get_principal_by_id(self.admin_id)
        user_p = self.storage_v3.get_principal_by_id(self.user_id)

        # Before any messages
        admin_rooms = self.storage_v3.list_rooms_for_principal(admin_p)
        self.assertEqual(len(admin_rooms), 1)
        self.assertEqual(admin_rooms[0]["message_count"], 0)

        user_rooms = self.storage_v3.list_rooms_for_principal(user_p)
        self.assertEqual(len(user_rooms), 1)
        self.assertEqual(user_rooms[0]["message_count"], 0)

        # Add 3 messages
        self.storage_v3.add_message(self.room_id, "User 1", "Hello 1", role="human")
        self.storage_v3.add_message(self.room_id, "Bot A", "Hi there 1", role="agent")
        self.storage_v3.add_message(self.room_id, "Bot B", "Hi there 2", role="agent")

        # After messages
        admin_rooms = self.storage_v3.list_rooms_for_principal(admin_p)
        self.assertEqual(admin_rooms[0]["message_count"], 3)

        user_rooms = self.storage_v3.list_rooms_for_principal(user_p)
        self.assertEqual(user_rooms[0]["message_count"], 3)

    async def test_cycle_protection_disabled_by_default(self):
        """Verify agents can exchange >10 messages consecutively without cycle limit by default."""
        os.environ.pop("AICHAT_MAX_AGENT_CYCLES", None)

        # Send 15 consecutive messages between agents
        for i in range(15):
            sender = "BotA" if i % 2 == 0 else "BotB"
            tok = self.tok1 if i % 2 == 0 else self.tok2
            target = "@BotB" if i % 2 == 0 else "@BotA"
            msg = await self.hub.send_message(
                "general",
                sender,
                f"Agent msg #{i}",
                role="agent",
                member_token=tok,
                to=target,
            )
            self.assertEqual(msg["sender"], sender)

        consecutive = self.storage_v3.count_consecutive_agent_messages(self.room_id)
        self.assertEqual(consecutive, 15)

    async def test_cycle_protection_enforced_when_configured(self):
        """Verify cycle protection is enforced if AICHAT_MAX_AGENT_CYCLES is set to >0."""
        os.environ["AICHAT_MAX_AGENT_CYCLES"] = "2"
        try:
            await self.hub.send_message("general", "BotA", "Msg 1", role="agent", member_token=self.tok1, to="@BotB")
            await self.hub.send_message("general", "BotB", "Msg 2", role="agent", member_token=self.tok2, to="@BotA")

            # 3rd should fail
            with self.assertRaises(ValueError) as ctx:
                await self.hub.send_message("general", "BotA", "Msg 3", role="agent", member_token=self.tok1, to="@BotB")
            self.assertIn("Proteção de ciclo ativada", str(ctx.exception))
        finally:
            os.environ.pop("AICHAT_MAX_AGENT_CYCLES", None)


if __name__ == "__main__":
    unittest.main()
