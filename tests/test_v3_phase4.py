"""
Test Suite for AI Chat v3.0 Phase 4 — Multi-Human Support & Decentralized Decisions

Covers:
1. Dynamic human attribution (no hardcoded names like "Rui").
2. Message author display_name and sender_username attribution.
3. call_human targeted vs open (only targeted wakes, open wakes room humans, never agents).
4. Decentralized decisions (room writers and admins can resolve, decided_by = principal.id, 400 on re-resolve).
5. Polls: 1 vote per principal, votes mapped to voter identity, close restricted to creator/admin (403 for others).
6. Room archiving restricted to admin (403 for regular users).
7. Role 'user' vs 'admin' room visibility: user only sees accessible rooms on /api/rooms, 403 on /api/rooms/{room}/messages, 4403 on /ws/{room}.
"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from aichat.hub import ChatHub
from aichat.storage_v3 import StorageV3
from aichat.web_app import create_app


class TestV3Phase4MultiHumanDecentralized(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.db_path = self.tmp / "test_v3_p4.db"
        self.logs_dir = self.tmp / "logs"
        self.storage = StorageV3(self.db_path, self.logs_dir)
        self.hub = ChatHub(storage=self.storage)

        # Wire test storage into global hub
        from aichat.mcp_server import hub
        self.orig_storage = hub.storage
        hub.storage = self.storage

        # Create 2 admins: admin_alice, admin_bob
        self.admin_alice_id = self.storage.create_human(
            username="alice_admin",
            password="Password123!",
            display_name="Alice Administrator",
            access_role="admin",
            must_change_password=0,
        )
        self.admin_bob_id = self.storage.create_human(
            username="bob_admin",
            password="Password123!",
            display_name="Bob Administrator",
            access_role="admin",
            must_change_password=0,
        )

        # Create 2 regular users: user_charlie, user_diana
        self.user_charlie_id = self.storage.create_human(
            username="charlie",
            password="Password123!",
            display_name="Charlie Engineer",
            access_role="user",
            must_change_password=0,
        )
        self.user_diana_id = self.storage.create_human(
            username="diana",
            password="Password123!",
            display_name="Diana Designer",
            access_role="user",
            must_change_password=0,
        )

        # Create agents: agent_sentinel, agent_bot
        self.agent_sentinel_id, self.agent_sentinel_token = self.storage.create_agent(
            callsign="sentinel",
            display_name="Sentinel Agent",
            role_key="qa",
        )
        self.agent_bot_id, self.agent_bot_token = self.storage.create_agent(
            callsign="builder-bot",
            display_name="Builder Bot",
            role_key="developer",
        )

        # Create sessions
        self.session_alice = self.storage.create_human_session(self.admin_alice_id)
        self.session_bob = self.storage.create_human_session(self.admin_bob_id)
        self.session_charlie = self.storage.create_human_session(self.user_charlie_id)
        self.session_diana = self.storage.create_human_session(self.user_diana_id)

        # Rooms
        self.room_public = self.storage.create_room(
            name="proj-core",
            topic="Core Development",
            created_by=self.admin_alice_id,
        )
        self.room_private = self.storage.create_room(
            name="proj-secret",
            topic="Confidential Room",
            created_by=self.admin_alice_id,
        )

        # Grant access:
        # proj-core: charlie has write access, sentinel has write access
        self.storage.grant_room_access(self.room_public["id"], self.user_charlie_id, can_write=1)
        self.storage.grant_room_access(self.room_public["id"], self.agent_sentinel_id, can_write=1)
        # diana is observer in proj-core
        self.storage.grant_room_access(self.room_public["id"], self.user_diana_id, can_write=0)

        # proj-secret: only admin_alice, admin_bob (as admins) and diana (as writer)
        self.storage.grant_room_access(self.room_private["id"], self.user_diana_id, can_write=1)

        self.app = create_app()
        self.client = TestClient(self.app, base_url="http://127.0.0.1")

    def tearDown(self):
        from aichat.mcp_server import hub
        self.storage.close()
        hub.storage = self.orig_storage
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ------------------------------------------------------------------ 1. Dynamic Human Attribution
    def test_dynamic_human_attribution_on_message(self):
        """Sending messages via authenticated human session records correct sender_id and display_name."""
        res = self.client.post(
            "/api/rooms/proj-core/messages",
            json={"content": "Hello from Charlie!"},
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertEqual(data["sender_id"], self.user_charlie_id)
        self.assertEqual(data["display_name"], "Charlie Engineer")
        self.assertEqual(data["sender_username"], "charlie")
        self.assertNotIn("Rui", data["sender"])
        self.assertNotIn("Rui", data["display_name"])

    # ------------------------------------------------------------------ 2. Message author display
    def test_get_messages_includes_display_name_and_username(self):
        """GET /api/rooms/{room}/messages returns author display_name and sender_username."""
        self.client.post(
            "/api/rooms/proj-core/messages",
            json={"content": "First message from Alice"},
            cookies={"human_session": self.session_alice},
        )
        res = self.client.get(
            "/api/rooms/proj-core/messages",
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(res.status_code, 200)
        messages = res.json()
        self.assertGreaterEqual(len(messages), 1)
        last_msg = messages[-1]
        self.assertEqual(last_msg["display_name"], "Alice Administrator")
        self.assertEqual(last_msg["sender_username"], "alice_admin")

    # ------------------------------------------------------------------ 3. call_human targeted vs open
    def test_call_human_targeted_wakes_only_target(self):
        """Targeted call_human wakes only the targeted human; other admins and agents do not wake."""
        import asyncio

        # Agent sentinel calls charlie specifically
        call_res = asyncio.run(
            self.hub.call_human(
                room_name="proj-core",
                sender="sentinel",
                question="Charlie, please approve this PR?",
                options=["Approve", "Reject"],
                member_token=self.agent_sentinel_token,
                target_human="charlie",
            )
        )
        msg_id = call_res["id"]
        msg = self.storage.get_message_by_id(msg_id)

        # Charlie should wake
        self.assertTrue(self.storage.is_message_for_principal(msg, self.user_charlie_id, self.room_public["id"]))
        # Untargeted admin Alice should NOT wake because message is targeted to Charlie specifically
        self.assertFalse(self.storage.is_message_for_principal(msg, self.admin_alice_id, self.room_public["id"]))
        # Untargeted admin Bob should NOT wake
        self.assertFalse(self.storage.is_message_for_principal(msg, self.admin_bob_id, self.room_public["id"]))
        # Agent builder-bot should NOT wake
        self.assertFalse(self.storage.is_message_for_principal(msg, self.agent_bot_id, self.room_public["id"]))
        # Sender sentinel should NOT wake
        self.assertFalse(self.storage.is_message_for_principal(msg, self.agent_sentinel_id, self.room_public["id"]))

    def test_call_human_open_wakes_all_room_humans_never_agents(self):
        """Open call_human wakes all humans with access to the room, but NEVER agents."""
        import asyncio

        call_res = asyncio.run(
            self.hub.call_human(
                room_name="proj-core",
                sender="sentinel",
                question="Need an approval from any human!",
                options=["Yes", "No"],
                member_token=self.agent_sentinel_token,
                to=None,  # Open
            )
        )
        msg_id = call_res["id"]
        msg = self.storage.get_message_by_id(msg_id)

        # Both admins have room access -> wake
        self.assertTrue(self.storage.is_message_for_principal(msg, self.admin_alice_id, self.room_public["id"]))
        self.assertTrue(self.storage.is_message_for_principal(msg, self.admin_bob_id, self.room_public["id"]))
        # Charlie is room member -> wakes
        self.assertTrue(self.storage.is_message_for_principal(msg, self.user_charlie_id, self.room_public["id"]))
        # Diana is observer in proj-core -> in v3 get_room_humans includes all human members + admins
        # Agents in room (or outside) must NEVER wake
        self.assertFalse(self.storage.is_message_for_principal(msg, self.agent_bot_id, self.room_public["id"]))
        self.assertFalse(self.storage.is_message_for_principal(msg, self.agent_sentinel_id, self.room_public["id"]))

    def test_call_human_open_with_no_humans_does_not_wake_agents(self):
        """If get_room_humans is empty (e.g. room with only agents), agents must NOT wake."""
        import asyncio

        room_agent_only = self.storage.create_room("agent-den", "Agents only room")
        self.storage.grant_room_access(room_agent_only["id"], self.agent_sentinel_id, can_write=1)

        # Temporarily mock get_room_humans returning empty list
        orig_get_room_humans = self.storage.get_room_humans
        self.storage.get_room_humans = lambda r_id: []
        try:
            call_res = asyncio.run(
                self.hub.call_human(
                    room_name="agent-den",
                    sender="sentinel",
                    question="Anyone out there?",
                    member_token=self.agent_sentinel_token,
                )
            )
            msg_id = call_res["id"]
            msg = self.storage.get_message_by_id(msg_id)
            self.assertFalse(self.storage.is_message_for_principal(msg, self.agent_sentinel_id, room_agent_only["id"]))
            self.assertFalse(self.storage.is_message_for_principal(msg, self.agent_bot_id, room_agent_only["id"]))
        finally:
            self.storage.get_room_humans = orig_get_room_humans

    # ------------------------------------------------------------------ 4. Decentralized Decisions
    def test_resolve_decision_by_room_writer_and_re_resolve_rejection(self):
        """Any human with write access in room can resolve; records decided_by; re-resolve returns 400."""
        import asyncio

        # Create decision
        call_res = asyncio.run(
            self.hub.call_human(
                room_name="proj-core",
                sender="sentinel",
                question="Should we merge branch feat/auth?",
                options=["Merge", "Cancel"],
                member_token=self.agent_sentinel_token,
            )
        )
        msg_id = call_res["id"]

        # Observer Diana tries to resolve -> 403 Forbidden (can_write = 0)
        res_diana = self.client.post(
            f"/api/decisions/{msg_id}/resolve",
            json={"room_name": "proj-core", "decision": "Merge"},
            cookies={"human_session": self.session_diana},
        )
        self.assertEqual(res_diana.status_code, 403)

        # Agent tries to resolve -> 403
        res_agent = self.client.post(
            f"/api/decisions/{msg_id}/resolve",
            json={"room_name": "proj-core", "decision": "Merge"},
            headers={"Authorization": f"Bearer {self.agent_sentinel_token}"},
        )
        self.assertEqual(res_agent.status_code, 403)

        # Charlie (room writer) resolves -> 200 OK
        res_charlie = self.client.post(
            f"/api/decisions/{msg_id}/resolve",
            json={"room_name": "proj-core", "decision": "Merge"},
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(res_charlie.status_code, 200)
        data = res_charlie.json()
        meta = data.get("metadata", data)
        self.assertEqual(meta["status"], "resolved")
        self.assertEqual(meta["decision"], "Merge")
        self.assertEqual(meta["decided_by"], self.user_charlie_id)
        self.assertEqual(meta["decided_by_name"], "Charlie Engineer")

        # Second attempt to resolve already resolved decision -> 400 Bad Request
        res_repeat = self.client.post(
            f"/api/decisions/{msg_id}/resolve",
            json={"room_name": "proj-core", "decision": "Cancel"},
            cookies={"human_session": self.session_alice},
        )
        self.assertEqual(res_repeat.status_code, 400)
        self.assertIn("já foi resolvida", res_repeat.json()["error"])

    # ------------------------------------------------------------------ 5. Polls: 1 vote per principal & identity
    def test_polls_one_vote_per_principal_and_closing_authorization(self):
        """Polls allow 1 vote per principal, track voter identity, and allow closing only by creator or admin."""
        # Charlie creates poll
        res_create = self.client.post(
            "/api/polls",
            json={
                "room_name": "proj-core",
                "question": "Which architecture pattern?",
                "options": ["Monolith", "Microservices", "Serverless"],
            },
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(res_create.status_code, 201)
        poll = res_create.json()
        poll_id = poll["id"]
        self.assertEqual(poll["creator_id"], self.user_charlie_id)

        # Charlie votes for option 0 (Monolith)
        res_vote1 = self.client.post(
            f"/api/polls/{poll_id}/vote",
            json={"option_index": 0},
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(res_vote1.status_code, 200)
        p_data = res_vote1.json()
        self.assertEqual(p_data["total_votes"], 1)
        self.assertEqual(p_data["results"][0]["votes"], 1)
        self.assertIn("Charlie Engineer", p_data["results"][0]["voters"])

        # Charlie changes vote to option 1 (Microservices) -> vote count stays 1!
        res_vote2 = self.client.post(
            f"/api/polls/{poll_id}/vote",
            json={"option_index": 1},
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(res_vote2.status_code, 200)
        p_data2 = res_vote2.json()
        self.assertEqual(p_data2["total_votes"], 1)
        self.assertEqual(p_data2["results"][0]["votes"], 0)
        self.assertEqual(p_data2["results"][1]["votes"], 1)

        # Observer Diana tries to vote -> 403 Forbidden (can_write = 0)
        res_vote_diana = self.client.post(
            f"/api/polls/{poll_id}/vote",
            json={"option_index": 0},
            cookies={"human_session": self.session_diana},
        )
        self.assertEqual(res_vote_diana.status_code, 403)

        # Admin Alice votes for option 0 -> total votes becomes 2
        res_vote3 = self.client.post(
            f"/api/polls/{poll_id}/vote",
            json={"option_index": 0},
            cookies={"human_session": self.session_alice},
        )
        self.assertEqual(res_vote3.status_code, 200)
        p_data3 = res_vote3.json()
        self.assertEqual(p_data3["total_votes"], 2)
        self.assertEqual(p_data3["results"][0]["votes"], 1)
        self.assertIn("Alice Administrator", p_data3["results"][0]["voters"])

        # Non-creator Diana tries to close poll -> 403 Forbidden
        res_close_diana = self.client.post(
            f"/api/polls/{poll_id}/close",
            json={},
            cookies={"human_session": self.session_diana},
        )
        self.assertEqual(res_close_diana.status_code, 403)

        # Agent tries to close poll -> 403 Forbidden
        res_close_agent = self.client.post(
            f"/api/polls/{poll_id}/close",
            json={},
            headers={"Authorization": f"Bearer {self.agent_sentinel_token}"},
        )
        self.assertEqual(res_close_agent.status_code, 403)

        # Creator Charlie closes poll -> 200 OK
        res_close_creator = self.client.post(
            f"/api/polls/{poll_id}/close",
            json={},
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(res_close_creator.status_code, 200)
        self.assertTrue(res_close_creator.json()["is_closed"])

        # Admin Bob closes another poll created by Charlie
        res_create2 = self.client.post(
            "/api/polls",
            json={
                "room_name": "proj-core",
                "question": "Release now?",
                "options": ["Yes", "No"],
            },
            cookies={"human_session": self.session_charlie},
        )
        poll2_id = res_create2.json()["id"]
        res_close_admin = self.client.post(
            f"/api/polls/{poll2_id}/close",
            json={},
            cookies={"human_session": self.session_bob},
        )
        self.assertEqual(res_close_admin.status_code, 200)
        self.assertTrue(res_close_admin.json()["is_closed"])

    # ------------------------------------------------------------------ 6. Room Archiving
    def test_room_archiving_restricted_to_admin(self):
        """Room archiving is restricted to admin (403 for regular users)."""
        # Regular user Charlie tries to archive room -> 403 Forbidden
        res_user_archive = self.client.post(
            "/api/rooms/proj-core/archive",
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(res_user_archive.status_code, 403)

        # Admin Alice archives room -> 200 OK
        res_admin_archive = self.client.post(
            "/api/rooms/proj-core/archive",
            cookies={"human_session": self.session_alice},
        )
        self.assertEqual(res_admin_archive.status_code, 200)
        room = self.storage.get_room("proj-core")
        self.assertTrue(room["is_archived"])

        # Regular user Charlie tries to unarchive -> 403 Forbidden
        res_user_unarchive = self.client.post(
            "/api/rooms/proj-core/unarchive",
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(res_user_unarchive.status_code, 403)

        # Admin Alice unarchives -> 200 OK
        res_admin_unarchive = self.client.post(
            "/api/rooms/proj-core/unarchive",
            cookies={"human_session": self.session_alice},
        )
        self.assertEqual(res_admin_unarchive.status_code, 200)
        room = self.storage.get_room("proj-core")
        self.assertFalse(room["is_archived"])

    # ------------------------------------------------------------------ 7. Role user vs admin visibility & room access
    def test_role_user_visibility_and_room_access(self):
        """User only sees accessible rooms on /api/rooms; 403 on inaccessible messages; 4403 on /ws."""
        # 1. /api/rooms visibility:
        # Charlie has access to proj-core only
        res_charlie_rooms = self.client.get(
            "/api/rooms",
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(res_charlie_rooms.status_code, 200)
        charlie_room_names = [r["name"] for r in res_charlie_rooms.json()]
        self.assertIn("proj-core", charlie_room_names)
        self.assertNotIn("proj-secret", charlie_room_names)

        # Diana has access to proj-core and proj-secret
        res_diana_rooms = self.client.get(
            "/api/rooms",
            cookies={"human_session": self.session_diana},
        )
        self.assertEqual(res_diana_rooms.status_code, 200)
        diana_room_names = [r["name"] for r in res_diana_rooms.json()]
        self.assertIn("proj-core", diana_room_names)
        self.assertIn("proj-secret", diana_room_names)

        # Admin Bob sees both rooms
        res_bob_rooms = self.client.get(
            "/api/rooms",
            cookies={"human_session": self.session_bob},
        )
        self.assertEqual(res_bob_rooms.status_code, 200)
        bob_room_names = [r["name"] for r in res_bob_rooms.json()]
        self.assertIn("proj-core", bob_room_names)
        self.assertIn("proj-secret", bob_room_names)

        # 2. Access to messages:
        # Charlie tries to read proj-secret messages -> 403 Forbidden
        res_secret_msgs = self.client.get(
            "/api/rooms/proj-secret/messages",
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(res_secret_msgs.status_code, 403)

        # Diana can read proj-secret messages -> 200 OK
        res_diana_secret = self.client.get(
            "/api/rooms/proj-secret/messages",
            cookies={"human_session": self.session_diana},
        )
        self.assertEqual(res_diana_secret.status_code, 200)

        # 3. WebSocket access:
        # Charlie connecting to /ws/proj-secret -> closed with code 4403
        with self.assertRaises(Exception):
            with self.client.websocket_connect(
                "/ws/proj-secret",
                cookies={"human_session": self.session_charlie},
            ) as ws:
                pass


if __name__ == "__main__":
    unittest.main()
