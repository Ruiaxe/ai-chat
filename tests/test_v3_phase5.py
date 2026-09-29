"""
Test Suite for AI Chat v3.0 Phase 5 — Gantt Tasks, Dependencies, Hand-off & Calendar Reservations

Covers:
1. Tasks with Gantt fields (start_at, due_at, progress_percent, parent_task_id, dependencies).
2. Cycle detection on dependency creation and update (self-loop, 2-node, 3-node, REST endpoints).
3. Targeted unblock/hand-off notifications on task completion (strictly targeted, never to="all").
4. Personal calendar events privacy (visible to owner and admin, hidden from other users/agents).
5. Calendar scope filtering (room, personal, resource, all).
6. Resource reservations and global conflict detection (overlapping rejected with 409, non-overlapping allowed, force override).
"""
import asyncio
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from aichat.hub import ChatHub
from aichat.storage_v3 import StorageV3
from aichat.web_app import create_app


class TestV3Phase5GanttDependenciesCalendar(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.db_path = self.tmp / "test_v3_p5.db"
        self.logs_dir = self.tmp / "logs"
        self.storage = StorageV3(self.db_path, self.logs_dir)
        self.hub = ChatHub(storage=self.storage)

        # Wire test storage into global hub
        from aichat.mcp_server import hub
        self.orig_storage = hub.storage
        hub.storage = self.storage

        # Create admin: alice
        self.admin_alice_id = self.storage.create_human(
            username="alice_admin",
            password="Password123!",
            display_name="Alice Administrator",
            access_role="admin",
            must_change_password=0,
        )

        # Create users: charlie, diana
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

        # Create agents: builder_bot, sentinel
        self.agent_builder_id, self.agent_builder_token = self.storage.create_agent(
            callsign="builder-bot",
            display_name="Builder Bot",
            role_key="developer",
        )
        self.agent_sentinel_id, self.agent_sentinel_token = self.storage.create_agent(
            callsign="sentinel",
            display_name="Sentinel Agent",
            role_key="qa",
        )

        # Create sessions
        self.session_alice = self.storage.create_human_session(self.admin_alice_id)
        self.session_charlie = self.storage.create_human_session(self.user_charlie_id)
        self.session_diana = self.storage.create_human_session(self.user_diana_id)

        # Rooms
        self.room_proj = self.storage.create_room(
            name="proj-alpha",
            topic="Alpha Project",
            created_by=self.admin_alice_id,
        )
        self.room_lab = self.storage.create_room(
            name="lab-infra",
            topic="Infrastructure Lab",
            created_by=self.admin_alice_id,
        )

        # Grant access
        self.storage.grant_room_access(self.room_proj["id"], self.user_charlie_id, can_write=1)
        self.storage.grant_room_access(self.room_proj["id"], self.user_diana_id, can_write=1)
        self.storage.grant_room_access(self.room_proj["id"], self.agent_builder_id, can_write=1)
        self.storage.grant_room_access(self.room_proj["id"], self.agent_sentinel_id, can_write=1)

        self.storage.grant_room_access(self.room_lab["id"], self.user_charlie_id, can_write=1)
        self.storage.grant_room_access(self.room_lab["id"], self.agent_builder_id, can_write=1)

        self.app = create_app()
        self.client = TestClient(self.app, base_url="http://127.0.0.1")

    def tearDown(self):
        from aichat.mcp_server import hub
        self.storage.close()
        hub.storage = self.orig_storage
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ------------------------------------------------------------------ 1. Gantt Tasks
    def test_task_creation_with_gantt_fields(self):
        """Task created with start_at, due_at, progress_percent, parent_task_id."""
        parent = self.storage.create_task(
            room_name_or_id="proj-alpha",
            title="Parent Epic",
            created_by=self.user_charlie_id,
        )
        child = self.storage.create_task(
            room_name_or_id="proj-alpha",
            title="Subtask Implementation",
            parent_task_id=parent["id"],
            start_at="2026-10-01T09:00:00",
            due_at="2026-10-03T18:00:00",
            progress_percent=35,
            assignee=self.agent_builder_id,
            created_by=self.user_charlie_id,
        )
        self.assertEqual(child["parent_task_id"], parent["id"])
        self.assertEqual(child["start_at"], "2026-10-01T09:00:00")
        self.assertEqual(child["due_at"], "2026-10-03T18:00:00")
        self.assertEqual(child["progress_percent"], 35)

        # Verify via list_tasks
        tasks = self.storage.list_tasks(room_name_or_id="proj-alpha")
        task_map = {t["id"]: t for t in tasks}
        self.assertIn(child["id"], task_map)
        self.assertEqual(task_map[child["id"]]["parent_task_id"], parent["id"])
        self.assertEqual(task_map[child["id"]]["progress_percent"], 35)

    def test_task_rest_api_gantt_fields(self):
        """REST API creates and updates tasks with Gantt attributes."""
        res = self.client.post(
            "/api/rooms/proj-alpha/tasks",
            json={
                "title": "API Gantt Task",
                "start_at": "2026-10-05T10:00:00",
                "due_at": "2026-10-08T18:00:00",
                "progress_percent": 15,
            },
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(res.status_code, 201)
        task_data = res.json()
        task_id = task_data["id"]
        self.assertEqual(task_data["progress_percent"], 15)
        self.assertEqual(task_data["start_at"], "2026-10-05T10:00:00")
        self.assertEqual(task_data["due_at"], "2026-10-08T18:00:00")

        # Update progress and status via PATCH
        patch_res = self.client.patch(
            f"/api/tasks/{task_id}",
            json={
                "progress_percent": 75,
                "due_at": "2026-10-10T20:00:00",
            },
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(patch_res.status_code, 200)
        updated = patch_res.json()
        self.assertEqual(updated["progress_percent"], 75)
        self.assertEqual(updated["due_at"], "2026-10-10T20:00:00")

    # ------------------------------------------------------------------ 2. Dependencies & Cycle Detection
    def test_self_dependency_rejected(self):
        """A task cannot depend on itself."""
        t1 = self.storage.create_task(room_name_or_id="proj-alpha", title="Self Dep Task")
        with self.assertRaises(ValueError) as ctx:
            self.storage.add_task_dependency(t1["id"], t1["id"])
        self.assertIn("si própria", str(ctx.exception).lower())

    def test_two_node_cycle_rejected(self):
        """Task 1 -> Task 2 -> Task 1 is rejected with cycle error."""
        t1 = self.storage.create_task(room_name_or_id="proj-alpha", title="Task 1")
        t2 = self.storage.create_task(room_name_or_id="proj-alpha", title="Task 2")
        self.storage.add_task_dependency(t2["id"], t1["id"])  # t2 depends on t1

        # Now attempting t1 depending on t2 must fail
        with self.assertRaises(ValueError) as ctx:
            self.storage.add_task_dependency(t1["id"], t2["id"])
        self.assertIn("circular", str(ctx.exception).lower())

    def test_three_node_cycle_rejected(self):
        """Task 1 -> Task 2 -> Task 3 -> Task 1 is rejected."""
        t1 = self.storage.create_task(room_name_or_id="proj-alpha", title="Task A")
        t2 = self.storage.create_task(room_name_or_id="proj-alpha", title="Task B")
        t3 = self.storage.create_task(room_name_or_id="proj-alpha", title="Task C")

        self.storage.add_task_dependency(t2["id"], t1["id"])  # B depends on A
        self.storage.add_task_dependency(t3["id"], t2["id"])  # C depends on B

        # A depends on C creates cycle A -> C -> B -> A
        with self.assertRaises(ValueError) as ctx:
            self.storage.add_task_dependency(t1["id"], t3["id"])
        self.assertIn("circular", str(ctx.exception).lower())

    def test_rest_api_dependency_endpoints_and_cycle_error(self):
        """POST and DELETE /api/tasks/{task_id}/dependencies endpoint tests."""
        t1 = self.storage.create_task(room_name_or_id="proj-alpha", title="Prerequisite")
        t2 = self.storage.create_task(room_name_or_id="proj-alpha", title="Dependent")

        # Add valid dependency via API
        res = self.client.post(
            f"/api/tasks/{t2['id']}/dependencies",
            json={"depends_on_task_id": t1["id"]},
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(res.status_code, 201)

        # Verify dependency exists
        deps = self.storage.get_task_dependencies(t2["id"])
        self.assertIn(t1["id"], deps)

        # Attempt to add reverse dependency -> returns 400 with cycle detection
        err_res = self.client.post(
            f"/api/tasks/{t1['id']}/dependencies",
            json={"depends_on_task_id": t2["id"]},
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(err_res.status_code, 400)
        self.assertIn("circular", err_res.json()["error"].lower())

        # Remove dependency via DELETE
        del_res = self.client.delete(
            f"/api/tasks/{t2['id']}/dependencies/{t1['id']}",
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(del_res.status_code, 200)
        deps_after = self.storage.get_task_dependencies(t2["id"])
        self.assertNotIn(t1["id"], deps_after)

    # ------------------------------------------------------------------ 3. Targeted Hand-off Notification
    def test_targeted_hand_off_notification_on_task_completion(self):
        """When prerequisite finishes, strictly targeted hand-off notification is sent (never to='all')."""
        # Task 1: Prerequisite
        t1 = self.storage.create_task(
            room_name_or_id="proj-alpha",
            title="Database Schema Migration",
            created_by=self.user_charlie_id,
        )
        # Task 2: Blocked task, assigned to builder-bot
        t2 = self.storage.create_task(
            room_name_or_id="proj-alpha",
            title="Backend Model Code Generation",
            assignee=self.agent_builder_id,
            dependencies=[t1["id"]],
            created_by=self.user_charlie_id,
        )

        # Complete Task 1 via hub.update_task
        asyncio.run(
            self.hub.update_task(
                task_id=t1["id"],
                status="done",
                human_token=self.hub.human_token,
                actor="Charlie Engineer",
            )
        )

        # Verify notification message in room
        messages = self.storage.list_messages(room_name_or_id="proj-alpha")
        hand_off_msgs = [m for m in messages if "DESBLOQUEADA" in m.get("content", "")]
        self.assertEqual(len(hand_off_msgs), 1)
        msg = hand_off_msgs[0]

        # Verify message text mentions tasks
        self.assertIn(f"#{t1['id']}", msg["content"])
        self.assertIn(f"#{t2['id']}", msg["content"])

        # Strictly targeted: 'to' must contain @builder-bot and NEVER 'all'
        to_list = msg.get("to", [])
        self.assertIn("@builder-bot", to_list)
        self.assertNotIn("all", to_list)

        # Check principal wake targeting
        self.assertTrue(self.storage.is_message_for_principal(msg, self.agent_builder_id, self.room_proj["id"]))
        # Sentinel and Diana must NOT wake
        self.assertFalse(self.storage.is_message_for_principal(msg, self.agent_sentinel_id, self.room_proj["id"]))
        self.assertFalse(self.storage.is_message_for_principal(msg, self.user_diana_id, self.room_proj["id"]))

    def test_multi_dependency_unblocks_only_when_all_satisfied(self):
        """Task with 2 prerequisites only unblocks when both are marked done."""
        t1 = self.storage.create_task(room_name_or_id="proj-alpha", title="Prereq 1")
        t2 = self.storage.create_task(room_name_or_id="proj-alpha", title="Prereq 2")
        t3 = self.storage.create_task(
            room_name_or_id="proj-alpha",
            title="Final Build",
            assignee=self.agent_builder_id,
            dependencies=[t1["id"], t2["id"]],
        )

        # Completing t1 should NOT unblock t3 yet
        unblocked_1 = self.storage.get_unblocked_tasks_on_completion(t1["id"])
        self.assertEqual(len(unblocked_1), 0)
        self.storage.update_task(t1["id"], status="done")

        # Completing t2 now unblocks t3
        unblocked_2 = self.storage.get_unblocked_tasks_on_completion(t2["id"])
        self.assertEqual(len(unblocked_2), 1)
        self.assertEqual(unblocked_2[0]["id"], t3["id"])

    # ------------------------------------------------------------------ 4. Calendar Events Privacy
    def test_personal_calendar_event_privacy(self):
        """Personal calendar events are visible only to the owner and admins."""
        # Charlie creates a personal event
        ev_charlie = self.storage.create_calendar_event(
            title="Charlie Private Dentist",
            start_at="2026-10-15T14:00:00",
            end_at="2026-10-15T15:00:00",
            created_by_id_or_name=self.user_charlie_id,
            owner_id_or_name=self.user_charlie_id,
            is_personal=True,
        )
        self.assertTrue(ev_charlie["is_personal"])
        self.assertIsNone(ev_charlie["room_id"])

        # Charlie queries events -> sees personal event
        charlie_events = self.storage.list_calendar_events(requester_id_or_name=self.user_charlie_id)
        charlie_ids = [e["id"] for e in charlie_events]
        self.assertIn(ev_charlie["id"], charlie_ids)

        # Admin Alice queries events -> sees personal event (admin access)
        alice_events = self.storage.list_calendar_events(requester_id_or_name=self.admin_alice_id)
        alice_ids = [e["id"] for e in alice_events]
        self.assertIn(ev_charlie["id"], alice_ids)

        # Regular user Diana queries events -> must NOT see Charlie's personal event
        diana_events = self.storage.list_calendar_events(requester_id_or_name=self.user_diana_id)
        diana_ids = [e["id"] for e in diana_events]
        self.assertNotIn(ev_charlie["id"], diana_ids)

        # Agent builder-bot queries events -> must NOT see Charlie's personal event
        agent_events = self.storage.list_calendar_events(requester_id_or_name=self.agent_builder_id)
        agent_ids = [e["id"] for e in agent_events]
        self.assertNotIn(ev_charlie["id"], agent_ids)

    # ------------------------------------------------------------------ 5. Calendar Scope Filters
    def test_calendar_scope_filters(self):
        """Calendar scope filters: 'room', 'personal', 'resource', 'all'."""
        # 1 Room event in proj-alpha
        ev_room = self.storage.create_calendar_event(
            room_name_or_id="proj-alpha",
            title="Team Sprint Planning",
            start_at="2026-10-20T10:00:00",
            created_by_id_or_name=self.user_charlie_id,
        )
        # 1 Personal event for Charlie
        ev_pers = self.storage.create_calendar_event(
            title="Charlie Doctor Appointment",
            start_at="2026-10-20T14:00:00",
            created_by_id_or_name=self.user_charlie_id,
            is_personal=True,
        )
        # 1 Resource reservation
        ev_res = self.storage.create_calendar_event(
            room_name_or_id="lab-infra",
            title="Benchmarking Run",
            start_at="2026-10-20T16:00:00",
            end_at="2026-10-20T18:00:00",
            resource="RTX_4090",
            created_by_id_or_name=self.user_charlie_id,
        )

        # Filter: room
        room_only = self.storage.list_calendar_events(filter_type="room", requester_id_or_name=self.user_charlie_id)
        r_ids = [e["id"] for e in room_only]
        self.assertIn(ev_room["id"], r_ids)
        self.assertNotIn(ev_pers["id"], r_ids)

        # Filter: personal
        pers_only = self.storage.list_calendar_events(filter_type="personal", requester_id_or_name=self.user_charlie_id)
        p_ids = [e["id"] for e in pers_only]
        self.assertIn(ev_pers["id"], p_ids)
        self.assertNotIn(ev_room["id"], p_ids)
        self.assertNotIn(ev_res["id"], p_ids)

        # Filter: resource
        res_only = self.storage.list_calendar_events(filter_type="resource", requester_id_or_name=self.user_charlie_id)
        res_ids = [e["id"] for e in res_only]
        self.assertIn(ev_res["id"], res_ids)
        self.assertNotIn(ev_room["id"], res_ids)
        self.assertNotIn(ev_pers["id"], res_ids)

    # ------------------------------------------------------------------ 6. Resource Conflict Detection (409)
    def test_global_resource_collision_detection_409(self):
        """Resource reservation collision returns 409, non-overlapping allowed, force bypasses."""
        # Initial booking: 10:00 to 12:00
        res1 = self.client.post(
            "/api/rooms/proj-alpha/calendar",
            json={
                "title": "LLM Fine-tuning Job",
                "start_at": "2026-10-25T10:00:00",
                "end_at": "2026-10-25T12:00:00",
                "resource": "RTX_3080",
            },
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(res1.status_code, 201)

        # Overlapping booking in lab-infra room: 11:00 to 13:00 -> Conflict 409
        res_conflict = self.client.post(
            "/api/rooms/lab-infra/calendar",
            json={
                "title": "Vision Training",
                "start_at": "2026-10-25T11:00:00",
                "end_at": "2026-10-25T13:00:00",
                "resource": "RTX_3080",
            },
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(res_conflict.status_code, 409)
        err_data = res_conflict.json()
        self.assertIn("conflito", err_data["error"].lower())
        self.assertGreaterEqual(len(err_data.get("conflicts", [])), 1)

        # Non-overlapping booking: 12:00 to 14:00 -> Allowed (201)
        res_ok = self.client.post(
            "/api/rooms/lab-infra/calendar",
            json={
                "title": "Evaluation Job",
                "start_at": "2026-10-25T12:00:00",
                "end_at": "2026-10-25T14:00:00",
                "resource": "RTX_3080",
            },
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(res_ok.status_code, 201)

        # Forced booking overriding conflict -> Allowed (201)
        res_forced = self.client.post(
            "/api/rooms/lab-infra/calendar",
            json={
                "title": "Priority Emergency Job",
                "start_at": "2026-10-25T11:00:00",
                "end_at": "2026-10-25T13:00:00",
                "resource": "RTX_3080",
                "force": True,
            },
            cookies={"human_session": self.session_charlie},
        )
        self.assertEqual(res_forced.status_code, 201)


if __name__ == "__main__":
    unittest.main()
