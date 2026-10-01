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


class TestV3Phase3WakePreviewAndPresence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.db_path = Path(cls.tmp) / "chat_v3.db"
        cls.logs_dir = Path(cls.tmp) / "logs"
        cls.test_storage = ChatStorage(db_path=cls.db_path, logs_dir=cls.logs_dir, schema_version=3)
        cls.orig_storage = hub.storage
        hub.storage = cls.test_storage

        # Setup roles
        cls.role_qa = hub.storage.v3.get_role_by_key("qa")
        if not cls.role_qa:
            cls.role_qa = hub.storage.v3.create_role("custom_qa", "Quality Assurance", "Testar sistema")
        cls.role_dev = hub.storage.v3.get_role_by_key("dev")
        if not cls.role_dev:
            cls.role_dev = hub.storage.v3.create_role("custom_dev", "Developer", "Codificar funcionalidade")

        # Humans
        cls.admin_id = hub.storage.v3.create_human(
            "admin_user", "Admin123Pass!", display_name="Admin Boss", access_role="admin", must_change_password=0
        )
        cls.admin_token = hub.storage.v3.create_human_session(cls.admin_id)

        cls.user1_id = hub.storage.v3.create_human(
            "user_one", "User123Pass!", display_name="User One", access_role="user", must_change_password=0
        )
        cls.user1_token = hub.storage.v3.create_human_session(cls.user1_id)

        cls.user2_id = hub.storage.v3.create_human(
            "user_two", "User123Pass!", display_name="User Two", access_role="user", must_change_password=0
        )
        cls.user2_token = hub.storage.v3.create_human_session(cls.user2_id)

        # Agents
        cls.agent_dev_id, cls.agent_dev_token = hub.storage.v3.create_agent(
            "agent_dev", "Agent Dev", default_role_id=cls.role_dev["id"]
        )
        cls.agent_qa_id, cls.agent_qa_token = hub.storage.v3.create_agent(
            "agent_qa", "Agent QA", default_role_id=cls.role_qa["id"]
        )
        cls.agent_obs_id, cls.agent_obs_token = hub.storage.v3.create_agent(
            "agent_obs", "Agent Observer", default_role_id=cls.role_dev["id"]
        )

        # Rooms
        cls.main_room = hub.storage.v3.create_room("main-room", topic="Main Discussion")
        cls.secret_room = hub.storage.v3.create_room("secret-room", topic="Secret Room")

        # Room Access:
        # main-room: admin, user1, agent_dev, agent_qa, agent_obs (can_write=0)
        hub.storage.v3.grant_room_access(cls.main_room["id"], cls.admin_id)
        hub.storage.v3.grant_room_access(cls.main_room["id"], cls.user1_id)
        hub.storage.v3.grant_room_access(cls.main_room["id"], cls.agent_dev_id, can_write=1)
        hub.storage.v3.grant_room_access(cls.main_room["id"], cls.agent_qa_id, can_write=1)
        hub.storage.v3.grant_room_access(cls.main_room["id"], cls.agent_obs_id, can_write=0)

        # secret-room: admin only
        hub.storage.v3.grant_room_access(cls.secret_room["id"], cls.admin_id)

        cls.app = create_app()
        cls.client = TestClient(cls.app)

    @classmethod
    def tearDownClass(cls):
        hub.storage = cls.orig_storage
        cls.test_storage.close()

    def setUp(self):
        self.admin_headers = {"Cookie": f"human_session={self.admin_token}"}
        self.user1_headers = {"Cookie": f"human_session={self.user1_token}"}
        self.user2_headers = {"Cookie": f"human_session={self.user2_token}"}
        self.agent_dev_headers = {"Authorization": f"Bearer {self.agent_dev_token}"}

    def test_01_team_status_authorization_and_details(self):
        # 1. Unauthenticated -> 401
        res = self.client.get("/api/rooms/main-room/team-status")
        self.assertEqual(res.status_code, 401)

        # 2. Non-member user2 on secret-room -> 403
        res = self.client.get("/api/rooms/secret-room/team-status", headers=self.user2_headers)
        self.assertEqual(res.status_code, 403)
        self.assertIn("Acesso não autorizado", res.json()["error"])

        # 3. Non-existent room -> 404
        res = self.client.get("/api/rooms/non-existent/team-status", headers=self.user1_headers)
        self.assertEqual(res.status_code, 404)

        # 4. Member user1 on main-room -> 200
        res = self.client.get("/api/rooms/main-room/team-status", headers=self.user1_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        team = data["team"]
        self.assertIsInstance(team, list)
        agent_dev_entry = next((m for m in team if m["principal_id"] == self.agent_dev_id), None)
        self.assertIsNotNone(agent_dev_entry)
        self.assertIn("unread_messages", agent_dev_entry)
        self.assertIn("state_icon", agent_dev_entry)
        self.assertIn("state_label", agent_dev_entry)

    def test_02_wake_preview_authorization_and_validation(self):
        # 1. Unauthenticated -> 401
        res = self.client.post("/api/rooms/main-room/wake-preview", json={"to": "all"})
        self.assertEqual(res.status_code, 401)

        # 2. Non-member -> 403
        res = self.client.post("/api/rooms/secret-room/wake-preview", json={"to": "all"}, headers=self.user2_headers)
        self.assertEqual(res.status_code, 403)

        # 3. Non-existent room -> 404
        res = self.client.post("/api/rooms/unknown/wake-preview", json={"to": "all"}, headers=self.user1_headers)
        self.assertEqual(res.status_code, 404)

        # 4. Invalid recipient -> 400
        res = self.client.post("/api/rooms/main-room/wake-preview", json={"to": "@nonexistent_person_xyz"}, headers=self.user1_headers)
        self.assertEqual(res.status_code, 400)
        self.assertIn("não encontrado", res.json()["error"].lower())

    def test_03_wake_preview_simulation_logic(self):
        # 1. Broadcast 'all' from user1:
        # Dev and QA should wake up; Observer should NOT wake up (can_write=0 ignores broadcast)
        res = self.client.post("/api/rooms/main-room/wake-preview", json={"to": "all"}, headers=self.user1_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        waking_ids = [a["id"] for a in data["waking_agents"]]
        self.assertIn(self.agent_dev_id, waking_ids)
        self.assertIn(self.agent_qa_id, waking_ids)
        self.assertNotIn(self.agent_obs_id, waking_ids)
        self.assertEqual(data["count"], 2)
        self.assertTrue(data["preview_text"].startswith("Vai acordar:"))

        # 2. Targeted role '@role:qa'
        res = self.client.post("/api/rooms/main-room/wake-preview", json={"to": "@role:qa"}, headers=self.user1_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        waking_ids = [a["id"] for a in data["waking_agents"]]
        self.assertNotIn(self.agent_dev_id, waking_ids)
        self.assertIn(self.agent_qa_id, waking_ids)
        self.assertEqual(data["count"], 1)

        # 3. Targeted specific agent '@agent_dev'
        res = self.client.post("/api/rooms/main-room/wake-preview", json={"to": "@agent_dev"}, headers=self.user1_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        waking_ids = [a["id"] for a in data["waking_agents"]]
        self.assertEqual(waking_ids, [self.agent_dev_id])

        # 4. Direct message to observer specifically -> Observer wakes up
        res = self.client.post("/api/rooms/main-room/wake-preview", json={"to": "@agent_obs"}, headers=self.user1_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        waking_ids = [a["id"] for a in data["waking_agents"]]
        self.assertEqual(waking_ids, [self.agent_obs_id])

        # 5. Message sent by agent_dev to 'all' -> sender is excluded!
        res = self.client.post("/api/rooms/main-room/wake-preview", json={"to": "all"}, headers=self.agent_dev_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        waking_ids = [a["id"] for a in data["waking_agents"]]
        self.assertNotIn(self.agent_dev_id, waking_ids)
        self.assertIn(self.agent_qa_id, waking_ids)
        self.assertEqual(data["count"], 1)

        # 6. Message to human with access -> "Ninguém vai acordar"
        res = self.client.post("/api/rooms/main-room/wake-preview", json={"to": "@admin_user"}, headers=self.user1_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["count"], 0)
        self.assertEqual(data["waking_agents"], [])
        self.assertEqual(data["preview_text"], "Ninguém vai acordar")

    def test_04_read_cursor_and_unread_counters(self):
        # Verify initial room listing for user1
        res = self.client.get("/api/rooms", headers=self.user1_headers)
        self.assertEqual(res.status_code, 200)
        rooms = res.json()
        main_r = next(r for r in rooms if r["id"] == self.main_room["id"])
        self.assertEqual(main_r["unread_total"], 0)
        self.assertEqual(main_r["unread_directed"], 0)

        # Send direct message to user1
        post_res = self.client.post(
            "/api/rooms/main-room/messages",
            json={"content": "Hello user1!", "to": "@user_one"},
            headers=self.admin_headers,
        )
        self.assertEqual(post_res.status_code, 201)
        msg1_id = post_res.json()["id"]

        # Check user1 counters: unread_total=1, unread_directed=1
        res = self.client.get("/api/rooms", headers=self.user1_headers)
        rooms = res.json()
        main_r = next(r for r in rooms if r["id"] == self.main_room["id"])
        self.assertEqual(main_r["unread_total"], 1)
        self.assertEqual(main_r["unread_directed"], 1)

        # Send broadcast message
        post_res2 = self.client.post(
            "/api/rooms/main-room/messages",
            json={"content": "Broadcast message", "to": "all"},
            headers=self.admin_headers,
        )
        self.assertEqual(post_res2.status_code, 201)
        msg2_id = post_res2.json()["id"]

        # Check user1 counters: unread_total=2, unread_directed=1
        res = self.client.get("/api/rooms", headers=self.user1_headers)
        rooms = res.json()
        main_r = next(r for r in rooms if r["id"] == self.main_room["id"])
        self.assertEqual(main_r["unread_total"], 2)
        self.assertEqual(main_r["unread_directed"], 1)

        # Advance read cursor to msg2_id
        cursor_res = self.client.post(
            "/api/rooms/main-room/read-cursor",
            json={"last_message_id": msg2_id},
            headers=self.user1_headers,
        )
        self.assertEqual(cursor_res.status_code, 200)
        self.assertEqual(cursor_res.json()["status"], "success")

        # Now counters should be 0
        res = self.client.get("/api/rooms", headers=self.user1_headers)
        rooms = res.json()
        main_r = next(r for r in rooms if r["id"] == self.main_room["id"])
        self.assertEqual(main_r["unread_total"], 0)
        self.assertEqual(main_r["unread_directed"], 0)

    def test_05_wake_preview_matches_send_message_validation(self):
        """Verifies wake-preview and send_message apply identical recipient validations with matching errors."""
        # Setup an agent without access to main-room
        outsider_id, outsider_token = hub.storage.v3.create_agent(
            "outsider_bot", "Outsider Bot", default_role_id=self.role_dev["id"]
        )
        # Setup a role that is NOT assigned to any member of main-room
        orphan_role = hub.storage.v3.create_role("orphan_role", "Orphan Role", "Sem membros")

        cases = [
            # Case 1: Agent with no access to main-room
            {
                "to": "@outsider_bot",
                "expect_error": True,
            },
            # Case 2: Role with no members in main-room
            {
                "to": f"@role:{orphan_role['role_key']}",
                "expect_error": True,
            },
            # Case 3: Valid agent in main-room
            {
                "to": "@agent_dev",
                "expect_error": False,
            },
            # Case 4: Valid role in main-room
            {
                "to": "@role:qa",
                "expect_error": False,
            },
            # Case 5: 'all' broadcast
            {
                "to": "all",
                "expect_error": False,
            },
        ]

        for case in cases:
            to_val = case["to"]
            expect_err = case["expect_error"]

            preview_res = self.client.post(
                "/api/rooms/main-room/wake-preview",
                json={"to": to_val},
                headers=self.user1_headers,
            )
            send_res = self.client.post(
                "/api/rooms/main-room/messages",
                json={"content": f"Test message for {to_val}", "to": to_val},
                headers=self.user1_headers,
            )

            if expect_err:
                self.assertEqual(preview_res.status_code, 400, f"Expected 400 for wake-preview with to={to_val}")
                self.assertEqual(send_res.status_code, 400, f"Expected 400 for send_message with to={to_val}")
                # Exact equality of error message between preview and send
                preview_err = preview_res.json()["error"]
                send_err = send_res.json()["error"]
                self.assertEqual(
                    preview_err,
                    send_err,
                    f"Error mismatch for to={to_val}: preview='{preview_err}' vs send='{send_err}'",
                )
            else:
                self.assertEqual(preview_res.status_code, 200, f"Expected 200 for wake-preview with to={to_val}")
                self.assertEqual(send_res.status_code, 201, f"Expected 201 for send_message with to={to_val}")

    def test_06_read_cursor_human_only_and_clamping(self):
        """Verifies POST /api/rooms/{room}/read-cursor accepts only humans and clamps to max message ID."""
        # 1. Agent tries to call read-cursor -> rejected with 403 Forbidden
        agent_res = self.client.post(
            "/api/rooms/main-room/read-cursor",
            json={"last_message_id": 1},
            headers=self.agent_dev_headers,
        )
        self.assertEqual(agent_res.status_code, 403)
        self.assertIn("Apenas utilizadores humanos", agent_res.json()["error"])

        # 2. Human sends gigantic last_message_id = 10^9
        # Get actual max_mid in main-room
        max_mid = hub.storage.v3.get_max_message_id(self.main_room["id"])
        self.assertGreater(max_mid, 0)

        huge_id = 1_000_000_000
        human_res = self.client.post(
            "/api/rooms/main-room/read-cursor",
            json={"last_message_id": huge_id},
            headers=self.user1_headers,
        )
        self.assertEqual(human_res.status_code, 200)
        saved_mid = human_res.json()["last_message_id"]
        # Clamped to room's max message ID!
        self.assertEqual(saved_mid, max_mid)

        # Confirm in storage
        cursor_in_db = hub.storage.v3.get_read_cursor(self.user1_id, self.main_room["id"])
        self.assertEqual(cursor_in_db, max_mid)
        self.assertNotEqual(cursor_in_db, huge_id)

        # 3. New message arrives -> user1 should have unread_total = 1 (not blocked forever)
        post_new = self.client.post(
            "/api/rooms/main-room/messages",
            json={"content": "New message after clamping test", "to": "all"},
            headers=self.admin_headers,
        )
        self.assertEqual(post_new.status_code, 201)
        new_msg_id = post_new.json()["id"]
        self.assertGreater(new_msg_id, max_mid)

        # Query user1 room list: unread_total should be 1
        rooms_res = self.client.get("/api/rooms", headers=self.user1_headers)
        main_r = next(r for r in rooms_res.json() if r["id"] == self.main_room["id"])
        self.assertEqual(main_r["unread_total"], 1)
