import asyncio
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from aichat.hub import ChatHub
from aichat.mcp_server import (
    create_room as tool_create_room,
    join_room as tool_join_room,
    list_rooms as tool_list_rooms,
    list_my_rooms as tool_list_my_rooms,
    read_messages as tool_read_messages,
    send_message as tool_send_message,
    wait_for_new_messages as tool_wait_for_new_messages,
)
from aichat.storage import ChatStorage
from aichat.web_app import create_app


class TestChatStorage(unittest.TestCase):
    """Tests for SQLite database operations and parallel file logs."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_chat.db"
        self.logs_dir = Path(self.temp_dir) / "logs"
        self.storage = ChatStorage(db_path=self.db_path, logs_dir=self.logs_dir)

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_create_room_and_db_persistence(self):
        room = self.storage.create_room("general", topic="General Chat", is_protected=False)
        self.assertEqual(room["name"], "general")
        self.assertEqual(room["topic"], "General Chat")
        self.assertFalse(room["is_protected"])

        # Fetch room
        fetched = self.storage.get_room("general")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["name"], "general")

        # Verify log file was initialized
        log_file = self.storage.get_room_log_file("general")
        self.assertTrue(log_file.exists())
        self.assertIn("=== Chat Room: general ===", log_file.read_text(encoding="utf-8"))

    def test_add_message_and_logs(self):
        self.storage.create_room("dev-team")
        msg = self.storage.add_message(
            room_name="dev-team",
            sender="CodeAgent",
            role="agent",
            content="Hello world from CodeAgent!",
        )
        self.assertGreater(msg["id"], 0)
        self.assertEqual(msg["sender"], "CodeAgent")
        self.assertEqual(msg["role"], "agent")

        # Check SQLite retrieval
        msgs = self.storage.get_messages("dev-team")
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0]["content"], "Hello world from CodeAgent!")

        # Check text log
        log_file = self.storage.get_room_log_file("dev-team")
        content = log_file.read_text(encoding="utf-8")
        self.assertIn("Hello world from CodeAgent!", content)
        self.assertIn("[Agent] CodeAgent", content)

        # Check jsonl log
        jsonl_file = self.storage.get_room_jsonl_file("dev-team")
        self.assertTrue(jsonl_file.exists())
        with open(jsonl_file, "r", encoding="utf-8") as f:
            line = f.readline()
            data = json.loads(line)
            self.assertEqual(data["sender"], "CodeAgent")
            self.assertEqual(data["content"], "Hello world from CodeAgent!")

    def test_member_token_storage_and_verification(self):
        self.storage.create_room("auth-room")
        token = self.storage.add_or_update_member("auth-room", "Agent1", "agent", generate_token=True)
        self.assertTrue(len(token) > 10)

        # Correct token
        valid, err = self.storage.verify_member_token("auth-room", "Agent1", token)
        self.assertTrue(valid)
        self.assertEqual(err, "")

        # Wrong token
        valid, err = self.storage.verify_member_token("auth-room", "Agent1", "wrong-token")
        self.assertFalse(valid)
        self.assertIn("Token fornecido é inválido", err)

        # Missing token for registered agent
        valid, err = self.storage.verify_member_token("auth-room", "Agent1", "")
        self.assertFalse(valid)
        self.assertIn("Token fornecido é inválido", err)

        # Non-registered member
        valid, err = self.storage.verify_member_token("auth-room", "Unregistered", "")
        self.assertTrue(valid)

    def test_member_rooms_and_verified_messages(self):
        self.storage.create_room("room-alpha")
        self.storage.create_room("room-beta")
        self.storage.add_or_update_member("room-alpha", "MultiAgent", "agent")
        self.storage.add_or_update_member("room-beta", "MultiAgent", "agent")

        rooms = self.storage.get_member_rooms("MultiAgent")
        self.assertIn("room-alpha", rooms)
        self.assertIn("room-beta", rooms)

        # Verified message
        msg_v = self.storage.add_message("room-alpha", "MultiAgent", "agent", "Verified text", is_verified=True)
        self.assertTrue(msg_v["is_verified"])

        # Unverified message
        msg_uv = self.storage.add_message("room-alpha", "MultiAgent", "agent", "Unverified text", is_verified=False)
        self.assertFalse(msg_uv["is_verified"])

        msgs = self.storage.get_messages("room-alpha")
        self.assertTrue(msgs[0]["is_verified"])
        self.assertFalse(msgs[1]["is_verified"])



class TestChatHubAndAuth(unittest.IsolatedAsyncioTestCase):
    """Tests for ChatHub, password protection, and agent notifications."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_chat.db"
        self.logs_dir = Path(self.temp_dir) / "logs"
        self.storage = ChatStorage(db_path=self.db_path, logs_dir=self.logs_dir)
        self.hub = ChatHub(storage=self.storage)

    def tearDown(self):
        self.storage.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def test_password_protection(self):
        # Create password-protected room
        self.hub.create_room("secret-room", password="SuperSecretPassword123", topic="Top Secret")

        # Unauthorized access should fail
        self.assertFalse(self.hub.verify_room_access("secret-room", password="wrong"))
        self.assertFalse(self.hub.verify_room_access("secret-room", password=""))

        # Authorized access should pass
        self.assertTrue(self.hub.verify_room_access("secret-room", password="SuperSecretPassword123"))

        # Sending message without password should raise PermissionError
        with self.assertRaises(PermissionError):
            await self.hub.send_message(
                room_name="secret-room",
                sender="HackerAgent",
                content="I shouldn't be here",
                password="wrong",
            )

        # Sending message with correct password succeeds
        msg = await self.hub.send_message(
            room_name="secret-room",
            sender="AuthorizedAgent",
            content="Access granted.",
            password="SuperSecretPassword123",
        )
        self.assertEqual(msg["content"], "Access granted.")

    async def test_agent_notification_long_polling(self):
        """Tests that wait_for_new_messages wakes up when another agent sends a message."""
        self.hub.create_room("collab")

        # Agent A waits for messages in background
        async def agent_a_wait():
            return await self.hub.wait_for_new_messages(
                room_name="collab",
                agent_name="AgentA",
                since_id=0,
                timeout_seconds=5.0,
            )

        wait_task = asyncio.create_task(agent_a_wait())

        # Give small tick to ensure agent_a is waiting
        await asyncio.sleep(0.05)

        # Agent B sends a message
        await self.hub.send_message(
            room_name="collab",
            sender="AgentB",
            content="Task is ready for review!",
            role="agent",
        )

        # Wait task should finish immediately with the new message
        result = await asyncio.wait_for(wait_task, timeout=2.0)
        self.assertEqual(result["status"], "new_messages")
        self.assertEqual(len(result["messages"]), 1)
        self.assertEqual(result["messages"][0]["sender"], "AgentB")
        self.assertEqual(result["messages"][0]["content"], "Task is ready for review!")

    async def test_agent_notification_timeout(self):
        """Tests that wait_for_new_messages returns timeout status if no messages arrive."""
        self.hub.create_room("quiet-room")
        result = await self.hub.wait_for_new_messages(
            room_name="quiet-room",
            agent_name="AgentA",
            since_id=0,
            timeout_seconds=0.2,
        )
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(result["count"], 0)

    async def test_wait_with_existing_messages_does_not_return_old_when_since_zero(self):
        """When since_id=0 and the room already has past messages, wait_for_new_messages must WAIT for future messages instead of returning old ones."""
        self.hub.create_room("active-room")
        # Pre-existing messages from Human and AgentB
        await self.hub.send_message("active-room", "Human", "Welcome to the room!", role="human")
        await self.hub.send_message("active-room", "AgentB", "Hi Human!", role="agent")

        # AgentA joins and waits with since_id=0
        wait_task = asyncio.create_task(
            self.hub.wait_for_new_messages(
                room_name="active-room",
                agent_name="AgentA",
                since_id=0,
                timeout_seconds=3.0,
            )
        )
        await asyncio.sleep(0.05)
        # Verify wait_task is still pending (did not prematurely return old messages!)
        self.assertFalse(wait_task.done())

        # AgentB sends a brand new message
        await self.hub.send_message("active-room", "AgentB", "Here is new info!", role="agent")

        result = await asyncio.wait_for(wait_task, timeout=2.0)
        self.assertEqual(result["status"], "new_messages")
        self.assertEqual(len(result["messages"]), 1)
        self.assertEqual(result["messages"][0]["content"], "Here is new info!")

    async def test_wait_continues_if_own_message_is_sent_during_wait(self):
        """If the waiting agent itself sends a message, it should not break the wait with an empty list; it should keep waiting until another sender posts."""
        self.hub.create_room("self-test-room")
        wait_task = asyncio.create_task(
            self.hub.wait_for_new_messages(
                room_name="self-test-room",
                agent_name="Claude",
                since_id=0,
                timeout_seconds=3.0,
            )
        )
        await asyncio.sleep(0.05)

        # Claude sends a message while waiting (should be ignored by Claude's wait)
        await self.hub.send_message("self-test-room", "Claude", "I am working...", role="agent")
        await asyncio.sleep(0.05)
        self.assertFalse(wait_task.done())

        # Someone else sends a message
        await self.hub.send_message("self-test-room", "Human", "Good job!", role="human")

        result = await asyncio.wait_for(wait_task, timeout=2.0)
        self.assertEqual(result["status"], "new_messages")
        self.assertEqual(len(result["messages"]), 1)
        self.assertEqual(result["messages"][0]["sender"], "Human")

    async def test_case_insensitive_agent_and_room_matching(self):
        """Agent names and room names should match case-insensitively for notifications."""
        self.hub.create_room("Collab-Case")
        # Pre-seed message
        await self.hub.send_message("collab-case", "claude", "First message", role="agent")

        # Waiting with 'CLAUDE' and lowercase room name 'collab-case'
        wait_task = asyncio.create_task(
            self.hub.wait_for_new_messages(
                room_name="collab-case",
                agent_name="CLAUDE",
                since_id=0,
                timeout_seconds=3.0,
            )
        )
        await asyncio.sleep(0.05)
        self.assertFalse(wait_task.done())

        # Send from 'PartnerAgent' to 'COLLAB-CASE'
        await self.hub.send_message("COLLAB-CASE", "PartnerAgent", "Hey Claude!", role="agent")
        result = await asyncio.wait_for(wait_task, timeout=2.0)
        self.assertEqual(result["status"], "new_messages")
        self.assertEqual(result["messages"][0]["content"], "Hey Claude!")

    def test_check_new_messages_non_blocking(self):
        """check_new_messages returns immediately without blocking."""
        self.hub.create_room("check-room")
        check1 = self.hub.check_new_messages("check-room", agent_name="AgentA", since_id=0)
        self.assertEqual(check1["status"], "success")
        self.assertEqual(check1["has_new"], False)
        self.assertEqual(check1["room_max_id"], 0)

    async def test_sender_token_authentication_and_anti_impersonation(self):
        """Tests that member tokens authenticate senders and prevent impersonation."""
        self.hub.create_room("secure-room")
        join_res = self.hub.join_room("secure-room", "Alice", role="agent")
        alice_token = join_res["member_token"]
        self.assertTrue(len(alice_token) > 0)

        # Alice sends message with token -> Verified
        msg_ok = await self.hub.send_message("secure-room", "Alice", "Hello from Alice", role="agent", member_token=alice_token)
        self.assertTrue(msg_ok["is_verified"])

        # Impersonator tries without token -> PermissionError
        with self.assertRaises(PermissionError):
            await self.hub.send_message("secure-room", "Alice", "I am fake Alice", role="agent", member_token="")

        # Impersonator tries with bad token -> PermissionError
        with self.assertRaises(PermissionError):
            await self.hub.send_message("secure-room", "Alice", "I am fake Alice", role="agent", member_token="bad-token")

        # Unregistered agent sends message without token -> unverified but allowed
        msg_unreg = await self.hub.send_message("secure-room", "UnregisteredBob", "Hello all", role="agent")
        self.assertFalse(msg_unreg["is_verified"])

        # Human message -> verified by default
        msg_human = await self.hub.send_message("secure-room", "Rui", "Hello team", role="human")
        self.assertTrue(msg_human["is_verified"])

    async def test_multi_room_subscription_and_waiting(self):
        """Tests that agents can subscribe to rooms and receive messages from any subscribed room."""
        self.hub.create_room("proj-frontend")
        self.hub.create_room("proj-backend")
        self.hub.create_room("proj-other")

        self.hub.join_room("proj-frontend", "WatcherAgent", role="agent")
        self.hub.join_room("proj-backend", "WatcherAgent", role="agent")

        # Check list_my_rooms
        my_rooms = self.hub.list_my_rooms("WatcherAgent")
        self.assertEqual(len(my_rooms), 2)
        room_names = [r["name"] for r in my_rooms]
        self.assertIn("proj-frontend", room_names)
        self.assertIn("proj-backend", room_names)
        self.assertNotIn("proj-other", room_names)

        # WatcherAgent waits across 'subscribed' rooms
        wait_task = asyncio.create_task(
            self.hub.wait_for_new_messages(
                room_name="subscribed",
                agent_name="WatcherAgent",
                since_id=0,
                timeout_seconds=3.0,
            )
        )
        await asyncio.sleep(0.05)
        self.assertFalse(wait_task.done())

        # Message sent to proj-backend by BackendDev
        await self.hub.send_message("proj-backend", "BackendDev", "API deployed!", role="agent")

        result = await asyncio.wait_for(wait_task, timeout=2.0)
        self.assertEqual(result["status"], "new_messages")
        self.assertEqual(result["room"], "proj-backend")
        self.assertEqual(len(result["messages"]), 1)
        self.assertEqual(result["messages"][0]["content"], "API deployed!")



class TestWebAppAndApi(unittest.TestCase):
    """Tests for REST API endpoints and Web UI."""

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = TestClient(cls.app)

    def test_web_ui_root(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("AI Agent Hub", response.text)

    def test_api_rooms_and_messages(self):
        import uuid
        room_name = f"api-test-{uuid.uuid4().hex[:6]}"
        # Create room via API
        res = self.client.post("/api/rooms", json={"name": room_name, "topic": "API Testing"})
        self.assertIn(res.status_code, [200, 201])

        # Post message
        post_res = self.client.post(
            f"/api/rooms/{room_name}/messages",
            json={"sender": "UserTest", "content": "Hello from API!", "role": "human"},
        )
        self.assertEqual(post_res.status_code, 201)

        # Get messages
        get_res = self.client.get(f"/api/rooms/{room_name}/messages")
        self.assertEqual(get_res.status_code, 200)
        msgs = get_res.json()
        self.assertTrue(any(m["content"] == "Hello from API!" for m in msgs))

        # Download log
        log_res = self.client.get(f"/api/rooms/{room_name}/log")
        self.assertEqual(log_res.status_code, 200)
        self.assertIn("Hello from API!", log_res.text)

    def test_api_tts_voices(self):
        res = self.client.get("/api/tts/voices")
        self.assertEqual(res.status_code, 200)
        voices = res.json()
        self.assertTrue(isinstance(voices, list))
        self.assertTrue(any(v["id"] == "pt-PT-DuarteNeural" for v in voices))


class TestMCPTools(unittest.IsolatedAsyncioTestCase):
    """Tests for FastMCP tool functions directly."""

    async def test_mcp_tools_flow(self):
        import uuid
        room_name = f"mcp-test-{uuid.uuid4().hex[:6]}"
        create_res = json.loads(tool_create_room(room_name, topic="MCP Tool Test"))
        self.assertEqual(create_res["status"], "success")

        # Join room
        join_res = json.loads(tool_join_room(room_name, agent_name="MCPTester"))
        self.assertEqual(join_res["status"], "success")
        token = join_res["member_token"]
        self.assertTrue(len(token) > 0)

        # List my rooms
        my_rooms_res = json.loads(tool_list_my_rooms("MCPTester"))
        self.assertEqual(my_rooms_res["status"], "success")
        self.assertTrue(any(r["name"] == room_name for r in my_rooms_res["rooms"]))

        # Send verified message
        send_res = json.loads(await tool_send_message(room_name, sender_name="MCPTester", content="Hello from MCP", member_token=token))
        self.assertEqual(send_res["status"], "success")
        self.assertTrue(send_res["is_verified"])

        # Send without token -> error
        err_res = json.loads(await tool_send_message(room_name, sender_name="MCPTester", content="Impersonator", member_token=""))
        self.assertEqual(err_res["status"], "error")
        self.assertIn("Impersonation blocked", err_res["error"])

        # Read messages
        read_res = json.loads(tool_read_messages(room_name))
        self.assertEqual(read_res["status"], "success")
        self.assertEqual(len(read_res["messages"]), 1)
        self.assertTrue(read_res["messages"][0]["is_verified"])


if __name__ == "__main__":
    unittest.main()

