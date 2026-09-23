import asyncio
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from aichat.hub import ChatHub
from aichat.mcp_server import (
    hub,
    create_room as tool_create_room,
    join_room as tool_join_room,
    list_rooms as tool_list_rooms,
    list_my_rooms as tool_list_my_rooms,
    read_messages as tool_read_messages,
    send_message as tool_send_message,
    wait_for_new_messages as tool_wait_for_new_messages,
    check_new_messages as tool_check_new_messages,
    react_to_message as tool_react_to_message,
    call_human as tool_call_human,
    create_poll as tool_create_poll,
    cast_vote as tool_cast_vote,
    get_poll as tool_get_poll,
    close_poll as tool_close_poll,
    archive_room as tool_archive_room,
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

    def test_storage_reactions_and_decisions(self):
        self.storage.create_room("reaction-room")
        msg = self.storage.add_message("reaction-room", "AgentA", "agent", "Test message")
        
        # Toggle reaction (add)
        res1 = self.storage.toggle_reaction(msg["id"], "reaction-room", "User1", "👍")
        self.assertEqual(res1["action"], "added")
        self.assertEqual(len(res1["reactions"]), 1)
        self.assertEqual(res1["reactions"][0]["count"], 1)

        # Another user reacts with same emoji
        res2 = self.storage.toggle_reaction(msg["id"], "reaction-room", "User2", "👍")
        self.assertEqual(res2["action"], "added")
        self.assertEqual(res2["reactions"][0]["count"], 2)

        # User1 removes reaction
        res3 = self.storage.toggle_reaction(msg["id"], "reaction-room", "User1", "👍")
        self.assertEqual(res3["action"], "removed")
        self.assertEqual(res3["reactions"][0]["count"], 1)

        # Add decision request
        dmsg = self.storage.add_message(
            "reaction-room", "AgentA", "agent", "Need decision",
            message_type="decision_request",
            metadata={"status": "pending", "options": ["Yes", "No"]},
        )
        self.assertEqual(dmsg["message_type"], "decision_request")
        resolved = self.storage.resolve_decision(dmsg["id"], "Yes", decider="Admin")
        self.assertEqual(resolved["status"], "resolved")
        self.assertEqual(resolved["decision"], "Yes")
        self.assertEqual(resolved["decided_by"], "Admin")

    def test_storage_polls(self):
        self.storage.create_room("poll-room")
        poll = self.storage.create_poll("poll-room", "AgentCreator", "Deploy to prod?", ["Yes", "No"])
        self.assertEqual(poll["question"], "Deploy to prod?")
        self.assertEqual(len(poll["options"]), 2)
        self.assertFalse(poll["is_closed"])

        # Vote
        poll = self.storage.cast_vote(poll["id"], "Voter1", 0)
        self.assertEqual(poll["total_votes"], 1)
        self.assertEqual(poll["options"][0]["votes"], 1)
        self.assertEqual(poll["options"][0]["percentage"], 100.0)

        # Second vote
        poll = self.storage.cast_vote(poll["id"], "Voter2", 1)
        self.assertEqual(poll["total_votes"], 2)
        self.assertEqual(poll["options"][0]["percentage"], 50.0)
        self.assertEqual(poll["options"][1]["percentage"], 50.0)

        # Close poll
        closed = self.storage.close_poll(poll["id"])
        self.assertTrue(closed["is_closed"])

    def test_storage_archive_room(self):
        self.storage.create_room("arch-room")
        self.storage.archive_room("arch-room")
        room = self.storage.get_room("arch-room")
        self.assertTrue(room["is_archived"])

        rooms_active = self.storage.list_rooms(include_archived=False)
        self.assertFalse(any(r["name"] == "arch-room" for r in rooms_active))

        self.storage.unarchive_room("arch-room")
        room_un = self.storage.get_room("arch-room")
        self.assertFalse(room_un["is_archived"])


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
        await self.hub.send_message("active-room", "Human", "Welcome to the room!", role="human", human_token=self.hub.human_token)
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
        await self.hub.send_message("self-test-room", "Human", "Good job!", role="human", human_token=self.hub.human_token)

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

        # Human message without token -> PermissionError
        with self.assertRaises(PermissionError):
            await self.hub.send_message("secure-room", "Rui", "Hello team without token", role="human")

        # Human message with valid human_token -> verified
        msg_human = await self.hub.send_message("secure-room", "Rui", "Hello team", role="human", human_token=self.hub.human_token)
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

    async def test_hub_call_human_and_decision_resolve(self):
        self.hub.create_room("decision-room")
        msg = await self.hub.call_human(
            "decision-room",
            sender="CodeAgent",
            question="Which database to use?",
            options=["PostgreSQL", "SQLite"],
        )
        self.assertEqual(msg["message_type"], "decision_request")
        self.assertEqual(msg["metadata"]["status"], "pending")

        res = await self.hub.resolve_human_decision(msg["id"], "decision-room", "PostgreSQL", decider="HumanRui")
        self.assertEqual(res["metadata"]["status"], "resolved")
        self.assertEqual(res["metadata"]["decision"], "PostgreSQL")
        # Check confirmation message was posted
        msgs = self.hub.read_messages("decision-room")
        self.assertTrue(any("Opção escolhida: **PostgreSQL**" in m["content"] for m in msgs))

    async def test_hub_polls_and_archive_restrictions(self):
        self.hub.create_room("poll-archive-room")
        poll = await self.hub.create_poll(
            "poll-archive-room",
            creator="PollAgent",
            question="Merge PR?",
            options=["Yes", "No"],
        )
        self.assertEqual(poll["question"], "Merge PR?")

        # Vote
        poll = await self.hub.cast_vote(poll["id"], "Reviewer1", 0)
        self.assertEqual(poll["options"][0]["votes"], 1)

        # Non-creator agent trying to close poll raises PermissionError
        with self.assertRaises(PermissionError):
            await self.hub.close_poll(poll["id"], closer="IntruderAgent", is_human=False)

        # Human can close poll
        closed = await self.hub.close_poll(poll["id"], closer="HumanRui", is_human=True)
        self.assertTrue(closed["is_closed"])

        # Agent cannot archive room
        with self.assertRaises(PermissionError):
            self.hub.archive_room("poll-archive-room", requester_role="agent")

        # Human can archive room
        arch = self.hub.archive_room("poll-archive-room", requester_role="human")
        self.assertEqual(arch["status"], "archived")

        # Sending message to archived room fails
        with self.assertRaises(ValueError):
            await self.hub.send_message("poll-archive-room", "Agent1", "Hello?", role="agent")

        # Human can unarchive
        unarch = self.hub.unarchive_room("poll-archive-room", requester_role="human")
        self.assertEqual(unarch["status"], "unarchived")

        # Can send message now
        msg_ok = await self.hub.send_message("poll-archive-room", "Agent1", "Hello again!", role="agent")
        self.assertEqual(msg_ok["content"], "Hello again!")



class TestWebAppAndApi(unittest.TestCase):
    """Tests for REST API endpoints and Web UI."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.test_storage = ChatStorage(
            db_path=Path(cls.temp_dir) / "test_api.db",
            logs_dir=Path(cls.temp_dir) / "logs",
        )
        cls.orig_storage = hub.storage
        hub.storage = cls.test_storage
        cls.app = create_app()
        cls.client = TestClient(cls.app)

    @classmethod
    def tearDownClass(cls):
        hub.storage.close()
        hub.storage = cls.orig_storage
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_web_ui_root(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("AI Agent", response.text)
        self.assertNotIn("window.__HUMAN_AUTH_TOKEN__", response.text)

        # Authenticating via ?auth= sets HttpOnly session cookie and redirects
        auth_resp = self.client.get(f"/?auth={hub.human_token}", follow_redirects=False)
        self.assertEqual(auth_resp.status_code, 303)
        self.assertIn("human_session", auth_resp.headers.get("set-cookie", ""))

    def test_auth_endpoints_lifecycle(self):
        # 1. Unauthenticated status
        res = self.client.get("/api/auth/status")
        self.assertEqual(res.status_code, 200)
        self.assertFalse(res.json()["authenticated"])
        self.assertEqual(res.json()["human_name"], "Rui")

        # 2. Login invalid
        res_bad = self.client.post("/api/auth/login", json={"token": "bad-token"})
        self.assertEqual(res_bad.status_code, 401)

        # 3. Login valid
        res_login = self.client.post("/api/auth/login", json={"token": hub.human_token})
        self.assertEqual(res_login.status_code, 200)
        self.assertTrue(res_login.json()["success"])
        self.assertIn("human_session", res_login.headers.get("set-cookie", ""))
        self.assertIn("max-age=", res_login.headers.get("set-cookie", "").lower())
        self.assertIn("samesite=lax", res_login.headers.get("set-cookie", "").lower())

        # 4. Check status with cookie
        res_auth = self.client.get("/api/auth/status", cookies={"human_session": hub.human_token})
        self.assertEqual(res_auth.status_code, 200)
        self.assertTrue(res_auth.json()["authenticated"])

        # 5. Logout
        res_logout = self.client.post("/api/auth/logout")
        self.assertEqual(res_logout.status_code, 200)

    def test_api_rooms_and_messages(self):
        import uuid
        room_name = f"api-test-{uuid.uuid4().hex[:6]}"
        # Create room via API
        res = self.client.post("/api/rooms", json={"name": room_name, "topic": "API Testing"})
        self.assertIn(res.status_code, [200, 201])

        # Attempt to post as human without token -> 403 Forbidden
        post_fail = self.client.post(
            f"/api/rooms/{room_name}/messages",
            json={"sender": "UserTest", "content": "Fake Human", "role": "human"},
        )
        self.assertEqual(post_fail.status_code, 403)

        # Post message with valid human token -> 201 Created
        post_res = self.client.post(
            f"/api/rooms/{room_name}/messages",
            json={"sender": "UserTest", "content": "Hello from API!", "role": "human"},
            headers={"X-Human-Token": hub.human_token},
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

    def test_api_new_features_endpoints(self):
        import uuid
        room_name = f"api-feat-{uuid.uuid4().hex[:6]}"
        self.client.post("/api/rooms", json={"name": room_name, "topic": "Features API Testing"})

        # Send a message
        msg_res = self.client.post(
            f"/api/rooms/{room_name}/messages",
            json={"sender": "Tester", "content": "Let's react to this", "role": "human"},
            headers={"X-Human-Token": hub.human_token},
        )
        self.assertEqual(msg_res.status_code, 201)
        msg_id = msg_res.json()["id"]

        # Reaction endpoint
        react_res = self.client.post(
            f"/api/messages/{msg_id}/reactions",
            json={"room_name": room_name, "sender": "Tester", "emoji": "🚀"},
        )
        self.assertEqual(react_res.status_code, 200)
        self.assertEqual(react_res.json()["action"], "added")

        # Poll endpoint
        poll_res = self.client.post(
            "/api/polls",
            json={
                "room_name": room_name,
                "creator": "Tester",
                "question": "Feature ready?",
                "options": ["Yes", "Not yet"],
            },
        )
        self.assertEqual(poll_res.status_code, 201)
        poll_id = poll_res.json()["id"]

        # Vote endpoint
        vote_res = self.client.post(
            f"/api/polls/{poll_id}/vote",
            json={"voter": "Tester", "option_index": 0},
        )
        self.assertEqual(vote_res.status_code, 200)
        self.assertEqual(vote_res.json()["options"][0]["votes"], 1)

        # Archive room endpoint without token -> 403
        arch_fail = self.client.post(f"/api/rooms/{room_name}/archive")
        self.assertEqual(arch_fail.status_code, 403)

        # Archive room endpoint with token -> 200
        arch_res = self.client.post(f"/api/rooms/{room_name}/archive", headers={"X-Human-Token": hub.human_token})
        self.assertEqual(arch_res.status_code, 200)

        # Unarchive room endpoint with token -> 200
        unarch_res = self.client.post(f"/api/rooms/{room_name}/unarchive", headers={"X-Human-Token": hub.human_token})
        self.assertEqual(unarch_res.status_code, 200)


class TestMCPTools(unittest.IsolatedAsyncioTestCase):
    """Tests for FastMCP tool functions directly."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_storage = ChatStorage(
            db_path=Path(self.temp_dir) / "test_mcp.db",
            logs_dir=Path(self.temp_dir) / "logs",
        )
        self.orig_storage = hub.storage
        hub.storage = self.test_storage

    def tearDown(self):
        hub.storage.close()
        hub.storage = self.orig_storage
        shutil.rmtree(self.temp_dir, ignore_errors=True)

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

    async def test_mcp_new_tools_flow(self):
        import uuid
        room_name = f"mcp-feat-{uuid.uuid4().hex[:6]}"
        tool_create_room(room_name, topic="MCP Features")
        join_res = json.loads(tool_join_room(room_name, agent_name="FeatureAgent"))
        token = join_res["member_token"]

        # Send message
        s_res = json.loads(await tool_send_message(room_name, sender_name="FeatureAgent", content="Need help", member_token=token))
        msg_id = s_res["message_id"]

        # React tool
        r_res = json.loads(await tool_react_to_message(message_id=msg_id, room_name=room_name, agent_name="FeatureAgent", emoji="👍"))
        self.assertEqual(r_res["status"], "success")

        # Call human tool
        call_res = json.loads(await tool_call_human(room_name, agent_name="FeatureAgent", question="Deploy now?", options=["Yes", "Wait"], member_token=token))
        self.assertEqual(call_res["status"], "success")

        # Create poll tool
        p_res = json.loads(await tool_create_poll(room_name, agent_name="FeatureAgent", question="Is this great?", options=["Yes", "Definitely"], member_token=token))
        self.assertEqual(p_res["status"], "success")
        poll_id = p_res["poll"]["id"]

        # Vote tool
        v_res = json.loads(await tool_cast_vote(poll_id, voter_name="FeatureAgent", option_index=0))
        self.assertEqual(v_res["status"], "success")

        # Get poll tool
        gp_res = json.loads(tool_get_poll(poll_id))
        self.assertEqual(gp_res["status"], "success")
        self.assertEqual(gp_res["poll"]["options"][0]["votes"], 1)

        # Close poll tool
        cp_res = json.loads(await tool_close_poll(poll_id, closer_name="FeatureAgent", member_token=token))
        self.assertEqual(cp_res["status"], "success")

        # Archive room tool as agent -> blocked
        ar_res = json.loads(tool_archive_room(room_name, requester_name="FeatureAgent", requester_role="agent"))
        self.assertEqual(ar_res["status"], "error")
        self.assertIn("utilizador humano", ar_res["error"])

    async def test_mcp_human_impersonation_blocked(self):
        """Agents must be blocked from joining or sending as Human or Rui via MCP."""
        tool_create_room("mcp-secure-room")

        # Attempt to join as Human -> error
        join_human = json.loads(tool_join_room("mcp-secure-room", agent_name="Human"))
        self.assertEqual(join_human["status"], "error")
        self.assertIn("reservado", join_human["error"].lower())

        # Attempt to join as Rui -> error
        join_rui = json.loads(tool_join_room("mcp-secure-room", agent_name="Rui"))
        self.assertEqual(join_rui["status"], "error")
        self.assertIn("reservado", join_rui["error"].lower())

        # Attempt to send as Human -> error
        send_human = json.loads(await tool_send_message("mcp-secure-room", sender_name="Human", content="I am human"))
        self.assertEqual(send_human["status"], "error")
        self.assertIn("reserved", send_human["error"].lower())

        # Attempt to send as Rui -> error
        send_rui = json.loads(await tool_send_message("mcp-secure-room", sender_name="Rui", content="I am Rui"))
        self.assertEqual(send_rui["status"], "error")
        self.assertIn("reserved", send_rui["error"].lower())

    async def test_reactions_wakes_wait_for_new_messages(self):
        """wait_for_new_messages must wake up and return when an emoji reaction is added."""
        tool_create_room("mcp-react-room")
        join_res = json.loads(tool_join_room("mcp-react-room", agent_name="WorkerAgent"))
        token = join_res["member_token"]

        # Worker sends a proposal message
        msg_res = json.loads(await tool_send_message("mcp-react-room", sender_name="WorkerAgent", content="Proposal ready for approval", member_token=token))
        msg_id = msg_res["message_id"]

        # Worker waits for feedback
        wait_task = asyncio.create_task(
            hub.wait_for_new_messages(
                room_name="mcp-react-room",
                agent_name="WorkerAgent",
                since_id=msg_id,
                timeout_seconds=5.0,
            )
        )
        await asyncio.sleep(0.05)
        self.assertFalse(wait_task.done())

        # Rui reacts with 👍 to the worker's proposal
        await hub.toggle_reaction(message_id=msg_id, room_name="mcp-react-room", sender="Rui", emoji="👍")

        # Worker wait_task should immediately wake up with status 'new_reactions'
        result = await asyncio.wait_for(wait_task, timeout=2.0)
        self.assertEqual(result["status"], "new_reactions")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["reactions"][0]["emoji"], "👍")
        self.assertEqual(result["reactions"][0]["sender"], "Rui")
        self.assertEqual(result["reactions"][0]["message_id"], msg_id)

        # Check non-blocking check_new_messages also detects reactions
        chk_res = json.loads(tool_check_new_messages("mcp-react-room", agent_name="WorkerAgent", since_id=msg_id))
        self.assertTrue(chk_res["has_new_reactions"])

        # Check reading specific message returns reactions
        read_single = json.loads(tool_read_messages("mcp-react-room", message_id=msg_id))
        self.assertEqual(read_single["status"], "success")
        self.assertEqual(len(read_single["messages"]), 1)
        self.assertEqual(read_single["messages"][0]["id"], msg_id)
        self.assertTrue(any(r["emoji"] == "👍" for r in read_single["messages"][0]["reactions"]))


if __name__ == "__main__":
    unittest.main()

