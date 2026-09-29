"""
Comprehensive Acceptance Test Suite for AI Chat v3:
Real v2 database migration, all MCP tools and REST write endpoints as agent (Bearer),
negative authorization checks (403), human decision resolution, conflict message,
and local Tailwind CSS verification.
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
    current_auth_token,
    current_principal,
    call_human as tool_call_human,
    create_task as tool_create_task,
    update_task as tool_update_task,
    list_tasks as tool_list_tasks,
    reorder_tasks as tool_reorder_tasks,
    create_calendar_event as tool_create_calendar_event,
    update_calendar_event as tool_update_calendar_event,
    delete_calendar_event as tool_delete_calendar_event,
    list_calendar_events as tool_list_calendar_events,
    create_poll as tool_create_poll,
    cast_vote as tool_cast_vote,
    get_poll as tool_get_poll,
    close_poll as tool_close_poll,
    react_to_message as tool_react_to_message,
    read_messages as tool_read_messages,
    send_message as tool_send_message,
    check_new_messages as tool_check_new_messages,
    list_rooms as tool_list_rooms,
    list_my_rooms as tool_list_my_rooms,
    who_is_listening as tool_who_is_listening,
    get_room_transcript as tool_get_room_transcript,
)


class TestV3AgentE2EAcceptance(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="fe2e_accept_"))
        cls.data_dir = cls.tmp / "data"
        cls.data_dir.mkdir(parents=True, exist_ok=True)
        cls.logs_dir = cls.tmp / "logs"
        cls.logs_dir.mkdir(parents=True, exist_ok=True)
        cls.v2_path = cls.data_dir / "v2.db"
        cls.v3_path = cls.data_dir / "v3.db"
        cls.out_dir = cls.data_dir / "out"

        # 1. Build authentic v2 database with rooms, agents, and memberships
        v2 = ChatStorage(db_path=cls.v2_path, logs_dir=cls.logs_dir)
        v2.create_room("geral")
        v2.create_room("controlo", password_hash="h", salt="s", is_protected=True, clear_password="pwd")
        for n in ("Claude-Dev", "Sentinel", "Builder"):
            v2.register_agent_admin(callsign=n)
        for room, n in (("geral", "Claude-Dev"), ("geral", "Builder"), ("controlo", "Sentinel")):
            v2.add_or_update_member(room, n, "agent")
        v2.add_message("controlo", "Sentinel", "agent", "SEGREDO-CONTROLO")
        v2.close()

        # 2. Run real v2 to v3 migration
        with contextlib.redirect_stdout(io.StringIO()):
            mig.main([
                "--source", str(cls.v2_path),
                "--target", str(cls.v3_path),
                "--admin-username", "Rui",
                "--out-dir", str(cls.out_dir),
            ])

        creds = next(cls.out_dir.glob("credentials_*")).read_text(encoding="utf-8")
        cls.TOK = {m.group(1): m.group(2) for m in re.finditer(r"^\s+(\S+)\s+(aic_\S+)", creds, re.M)}
        cls.ADMIN_PW = re.search(r"Admin initial password:\s+(\S+)", creds).group(1)
        cls.current_admin_pw = cls.ADMIN_PW

        # 3. Configure app environment to use migrated v3 DB
        os.environ["AICHAT_TESTING"] = "1"
        os.environ["AICHAT_DB_NAME"] = cls.v3_path.name
        cls.v3_storage = ChatStorage(db_path=cls.v3_path, logs_dir=cls.logs_dir)
        hub.storage = cls.v3_storage
        cls.app = create_app(allowed_hosts=["testserver", "localhost", "127.0.0.1"])
        cls.client = TestClient(cls.app, base_url="http://testserver")

    @classmethod
    def tearDownClass(cls):
        cls.v3_storage.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _login_admin(self) -> TestClient:
        admin_client = TestClient(self.app, base_url="http://testserver")
        login_res = admin_client.post("/api/auth/login", json={"username": "Rui", "password": self.current_admin_pw})
        if login_res.status_code == 401:
            login_res = admin_client.post("/api/auth/login", json={"username": "Rui", "password": self.ADMIN_PW})
        if login_res.status_code == 200 and login_res.json().get("must_change_password"):
            pw_res = admin_client.post("/api/auth/change-password", json={"current_password": self.ADMIN_PW, "new_password": "NovaPassword123!"})
            if pw_res.status_code == 200:
                TestV3AgentE2EAcceptance.current_admin_pw = "NovaPassword123!"
        return admin_client

    def _auth_header(self, agent_name: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.TOK[agent_name]}"}

    def _set_mcp_context(self, agent_name: str):
        tok = self.TOK[agent_name]
        p, _ = self.v3_storage.v3.authenticate_agent_token(tok)
        current_auth_token.set(tok)
        current_principal.set(p)
        return p, tok

    # ------------------------------------------------------------------
    # 1. MCP Tools as Agent (Bearer) Sweep
    # ------------------------------------------------------------------
    async def test_01_all_mcp_tools_as_agent(self):
        """Executes all MCP tools as Claude-Dev in room 'geral' without errors."""
        p, tok = self._set_mcp_context("Claude-Dev")

        # list_rooms & list_my_rooms
        lr = json.loads(tool_list_rooms())
        self.assertEqual(lr.get("status"), "success")
        lmr = json.loads(tool_list_my_rooms())
        self.assertEqual(lmr.get("status"), "success")
        self.assertIn("geral", [r["name"] for r in lmr["rooms"]])

        # send_message & read_messages
        sm = json.loads(await tool_send_message(room_name="geral", content="Sweep test message"))
        self.assertEqual(sm.get("status"), "success")
        msg_id = sm.get("message_id") or sm.get("id")

        rm = json.loads(tool_read_messages(room_name="geral"))
        self.assertEqual(rm.get("status"), "success")

        # check_new_messages
        cnm = json.loads(tool_check_new_messages(room_name="geral"))
        self.assertEqual(cnm.get("status"), "success")

        # react_to_message (previously failed with no such column: room_name)
        rx = json.loads(await tool_react_to_message(message_id=msg_id, room_name="geral", emoji="🚀"))
        self.assertEqual(rx.get("status"), "success")

        # create_poll & cast_vote & get_poll
        cp = json.loads(await tool_create_poll(room_name="geral", question="Qual a base?", options=["SQLite", "Postgres"]))
        self.assertEqual(cp.get("status"), "success")
        poll_id = cp["poll"]["id"]

        cv = json.loads(await tool_cast_vote(poll_id=poll_id, option_index=0))
        self.assertEqual(cv.get("status"), "success")

        gp = json.loads(tool_get_poll(poll_id=poll_id))
        self.assertEqual(gp.get("status"), "success")

        # create_task & list_tasks & update_task & reorder_tasks
        ct = json.loads(await tool_create_task(room_name="geral", title="MCP Task 1", priority="high"))
        self.assertEqual(ct.get("status"), "success")
        task_id = ct["task"]["id"]

        lt = json.loads(tool_list_tasks(room_name="geral"))
        self.assertEqual(lt.get("status"), "success")

        ut = json.loads(await tool_update_task(task_id=task_id, status="in_progress"))
        self.assertEqual(ut.get("status"), "success")

        ct2 = json.loads(await tool_create_task(room_name="geral", title="MCP Task 2", priority="medium"))
        task_id2 = ct2["task"]["id"]
        ro = json.loads(await tool_reorder_tasks(room_name="geral", task_ids=[task_id2, task_id]))
        self.assertEqual(ro.get("status"), "success")

        # create_calendar_event & list_calendar_events & update_calendar_event & delete_calendar_event
        ce = json.loads(await tool_create_calendar_event(
            room_name="geral",
            title="MCP Sync Meeting",
            start_at="2026-11-01T10:00:00",
            end_at="2026-11-01T11:00:00",
        ))
        self.assertEqual(ce.get("status"), "success")
        event_id = ce.get("event", {}).get("id") or ce.get("id")

        lce = json.loads(tool_list_calendar_events(room_name="geral"))
        self.assertEqual(lce.get("status"), "success")

        ue = json.loads(await tool_update_calendar_event(event_id=event_id, title="MCP Sync Updated"))
        self.assertEqual(ue.get("status"), "success")

        de = json.loads(await tool_delete_calendar_event(event_id=event_id))
        self.assertEqual(de.get("status"), "success")

        # call_human
        ch = json.loads(await tool_call_human(room_name="geral", question="Podemos fazer merge?", options=["Sim", "Não"]))
        self.assertEqual(ch.get("status"), "success")
        dec_id = ch.get("message_id")
        self.assertIsNotNone(dec_id)

        # who_is_listening & get_room_transcript
        wil = json.loads(tool_who_is_listening(room_name="geral"))
        self.assertIn("listeners", wil)

        trans = tool_get_room_transcript(room_name="geral")
        self.assertIn("Chat Room: geral", trans)

    # ------------------------------------------------------------------
    # 2. REST Write Endpoints as Agent (Bearer)
    # ------------------------------------------------------------------
    def test_02_rest_write_endpoints_as_agent(self):
        """Verifies REST POST/PATCH write endpoints with Bearer token on migrated DB."""
        headers = self._auth_header("Claude-Dev")

        # POST message
        r_msg = self.client.post("/api/rooms/geral/messages", json={"content": "REST agent msg"}, headers=headers)
        self.assertIn(r_msg.status_code, (200, 201))

        # POST task
        r_task = self.client.post("/api/rooms/geral/tasks", json={"title": "REST Agent Task", "priority": "medium"}, headers=headers)
        self.assertEqual(r_task.status_code, 201)
        t_data = r_task.json()
        self.assertEqual(t_data["creator_name"], "Claude-Dev")
        self.assertEqual(t_data["title"], "REST Agent Task")
        task_id = t_data["id"]

        # PATCH task
        r_up = self.client.patch(f"/api/tasks/{task_id}", json={"status": "in_progress"}, headers=headers)
        self.assertEqual(r_up.status_code, 200)
        self.assertEqual(r_up.json()["status"], "in_progress")

        # POST calendar event
        r_cal = self.client.post("/api/rooms/geral/calendar", json={
            "title": "REST Agent Event",
            "start_at": "2026-11-05T14:00:00",
            "end_at": "2026-11-05T15:00:00",
        }, headers=headers)
        self.assertEqual(r_cal.status_code, 201)
        ev_id = r_cal.json()["event"]["id"]

        # PATCH calendar event
        r_up_cal = self.client.patch(f"/api/calendar/events/{ev_id}", json={"title": "REST Agent Event Updated"}, headers=headers)
        self.assertEqual(r_up_cal.status_code, 200)

        # POST poll
        r_poll = self.client.post("/api/polls", json={
            "room_name": "geral",
            "question": "REST Poll?",
            "options": ["Opção 1", "Opção 2"],
        }, headers=headers)
        self.assertEqual(r_poll.status_code, 201)
        poll_id = r_poll.json()["id"]

        # POST vote
        r_vote = self.client.post(f"/api/polls/{poll_id}/vote", json={"option_index": 1}, headers=headers)
        self.assertEqual(r_vote.status_code, 200)

    # ------------------------------------------------------------------
    # 3. Negative Permission Checks (403)
    # ------------------------------------------------------------------
    def test_03_negative_permissions_as_agent(self):
        """Verifies agents receive 403 on unauthorized rooms and forbidden actions."""
        headers = self._auth_header("Claude-Dev")

        # 1. Agent creates task in room without write access (controlo) -> 403
        r_task = self.client.post("/api/rooms/controlo/tasks", json={"title": "Unauthorized Task"}, headers=headers)
        self.assertEqual(r_task.status_code, 403)

        # 2. Agent creates calendar event in room without write access (controlo) -> 403
        r_cal = self.client.post("/api/rooms/controlo/calendar", json={
            "title": "Unauthorized Cal",
            "start_at": "2026-11-10T10:00:00",
        }, headers=headers)
        self.assertEqual(r_cal.status_code, 403)

        # 3. Agent attempts force=True on calendar reservation -> 403
        r_force = self.client.post("/api/rooms/geral/calendar", json={
            "title": "Force GPU",
            "start_at": "2026-11-12T10:00:00",
            "force": True,
        }, headers=headers)
        self.assertEqual(r_force.status_code, 403)
        self.assertIn("Apenas utilizadores humanos podem forçar", r_force.json().get("error", ""))

        # 4. Agent attempts to close another user's poll -> 403
        # First create a poll as human
        admin_client = self._login_admin()
        r_hpoll = admin_client.post("/api/polls", json={"room_name": "geral", "question": "Admin Poll", "options": ["X", "Y"]})
        self.assertEqual(r_hpoll.status_code, 201)
        hpoll_id = r_hpoll.json()["id"]

        r_close = self.client.post(f"/api/polls/{hpoll_id}/close", json={}, headers=headers)
        self.assertEqual(r_close.status_code, 403)

    # ------------------------------------------------------------------
    # 4. Human Decision Resolution & Resource Conflict
    # ------------------------------------------------------------------
    async def test_04_human_decision_resolution_and_conflict_display(self):
        """Verifies human decision resolution and human creator name in conflict messages."""
        admin_client = self._login_admin()

        # 1. Admin creates a user 'ana'
        r_create = admin_client.post("/api/admin/humans", json={
            "username": "ana",
            "password": "AnaPassword999!",
            "access_role": "user",
            "must_change_password": 0,
        })
        self.assertIn(r_create.status_code, (200, 201))

        # Assign ana write access to geral
        humans_resp = admin_client.get("/api/admin/humans").json()
        ana_obj = next(h for h in (humans_resp.get("humans") or humans_resp) if h.get("name") == "ana")
        rooms_resp = admin_client.get("/api/admin/rooms").json()
        geral_obj = next(r for r in (rooms_resp.get("rooms") or rooms_resp) if r.get("name") == "geral")
        admin_client.post("/api/admin/rooms/bulk-grant", json={
            "grants": [{"room_id": geral_obj["id"], "principal_id": ana_obj["id"], "can_write": 1}]
        })

        # Login as ana
        ana_client = TestClient(self.app, base_url="http://testserver")
        r_ana_login = ana_client.post("/api/auth/login", json={"username": "ana", "password": "AnaPassword999!"})
        self.assertEqual(r_ana_login.status_code, 200)

        # 2. Ana creates calendar reservation for RTX_3080
        r_res = ana_client.post("/api/rooms/geral/calendar", json={
            "title": "GPU ana",
            "start_at": "2026-11-20T10:00:00",
            "end_at": "2026-11-20T12:00:00",
            "resource": "RTX_3080",
        })
        self.assertEqual(r_res.status_code, 201)

        # 3. Agent attempts conflicting reservation -> 409
        r_conflict = self.client.post("/api/rooms/geral/calendar", json={
            "title": "GPU agent conflict",
            "start_at": "2026-11-20T11:00:00",
            "end_at": "2026-11-20T13:00:00",
            "resource": "RTX_3080",
        }, headers=self._auth_header("Claude-Dev"))
        self.assertEqual(r_conflict.status_code, 409)
        err_msg = r_conflict.json()["error"]
        self.assertIn("@ana", err_msg)
        self.assertNotIn("@outro agente", err_msg)

        # 4. Create decision request as agent via MCP tool and resolve as ana
        p_c, tok_c = self._set_mcp_context("Claude-Dev")
        ch_resp = json.loads(await tool_call_human(
            room_name="geral",
            question="Autorização para build?",
            options=["Aprovado", "Rejeitado"],
        ))
        self.assertEqual(ch_resp.get("status"), "success")
        dec_id = ch_resp["message_id"]

        # Ana resolves decision
        r_resolve = ana_client.post(f"/api/decisions/{dec_id}/resolve", json={
            "room_name": "geral",
            "decision": "Aprovado",
        })
        self.assertEqual(r_resolve.status_code, 200)
        res_data = r_resolve.json()
        self.assertEqual(res_data["metadata"]["decision"], "Aprovado")
        self.assertEqual(res_data["metadata"]["decided_by_name"], "ana")

        # Second attempt must fail (already resolved)
        r_repeat = ana_client.post(f"/api/decisions/{dec_id}/resolve", json={
            "room_name": "geral",
            "decision": "Rejeitado",
        })
        self.assertEqual(r_repeat.status_code, 400)

    # ------------------------------------------------------------------
    # 5. Local Tailwind CSS Serving
    # ------------------------------------------------------------------
    def test_05_tailwind_served_locally(self):
        """Verifies Tailwind CSS is served locally and external CDN without SRI is removed."""
        r = self.client.get("/static/tailwind.min.css")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/css", r.headers.get("content-type", ""))
        self.assertGreater(len(r.content), 1000)

        # Verify index.html and admin.html
        r_index = self.client.get("/")
        self.assertEqual(r_index.status_code, 200)
        self.assertIn("/static/tailwind.min.css", r_index.text)
        self.assertNotIn("cdn.tailwindcss.com", r_index.text)

        admin_client = self._login_admin()
        r_admin = admin_client.get("/admin")
        self.assertEqual(r_admin.status_code, 200)
        self.assertIn("/static/tailwind.min.css", r_admin.text)
        self.assertNotIn("cdn.tailwindcss.com", r_admin.text)


if __name__ == "__main__":
    unittest.main()
