"""
Acceptance Test Suite for AI Chat v3.1: Real MCP Protocol Verification.

Verifies:
  - FastMCP SSE server (/sse, /messages) running on a live ASGI server.
  - Connection via real MCP client (mcp.client.sse.sse_client, mcp.client.session.ClientSession).
  - Unauthenticated registration via register_agent tool without tokens.
  - Authenticated tool calls via Authorization: Bearer <agent_token>.
  - Full sweep of all 36 MCP tools over the real protocol.
  - Verifies zero FastMCP schema validation errors ('kwargs Field required').
"""

import asyncio
import io
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

import uvicorn
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "migrations" / "v3"))

import migrate_v2_to_v3 as mig
from aichat.storage import ChatStorage
from aichat.web_app import create_app
from aichat.mcp_server import hub


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ServerThread(threading.Thread):
    def __init__(self, app, host: str, port: int):
        super().__init__(daemon=True)
        self.config = uvicorn.Config(app, host=host, port=port, log_level="warning")
        self.server = uvicorn.Server(self.config)

    def run(self):
        self.server.run()

    def stop(self):
        self.server.should_exit = True


class TestV3McpRealProtocol(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="aichat_mcp_real_"))
        cls.v2_path = cls.tmp / "chat_v2.db"
        cls.v3_path = cls.tmp / "chat_v3.db"
        cls.out_dir = cls.tmp / "migration_out"
        cls.logs_dir = cls.tmp / "logs"

        # 1. Build v2 database
        v2_st = ChatStorage(db_path=cls.v2_path, logs_dir=cls.logs_dir)
        v2_st.create_room("geral", topic="Sala Geral")
        v2_st.create_room("dev", topic="Sala Dev")
        v2_st.close()

        # 2. Run migration to v3
        rc = mig.main([
            "--source", str(cls.v2_path),
            "--target", str(cls.v3_path),
            "--admin-username", "Rui",
            "--out-dir", str(cls.out_dir),
        ])
        assert rc == 0, "Migration returned non-zero exit code"

        # 3. Mount v3 storage and create ASGI application
        cls.orig_storage = hub.storage
        cls.test_storage = ChatStorage(db_path=cls.v3_path, logs_dir=cls.logs_dir)
        hub.storage = cls.test_storage

        os.environ["AICHAT_TESTING"] = "1"
        cls.app = create_app()

        # Create active test agent "DevAgent"
        cls.agent_id, cls.agent_token = hub.storage.v3.create_agent(
            callsign="DevAgent",
            display_name="Dev Agent",
            status="active",
        )
        geral = hub.storage.v3.get_room("geral")
        hub.storage.v3.grant_room_access(geral["id"], cls.agent_id, can_write=1)

        # 4. Allocate dynamic port and start server thread
        cls.port = get_free_port()
        cls.server_url = f"http://127.0.0.1:{cls.port}"
        cls.sse_url = f"{cls.server_url}/sse"

        cls.server_thread = ServerThread(cls.app, "127.0.0.1", cls.port)
        cls.server_thread.start()
        for _ in range(100):
            if cls.server_thread.server.started:
                break
            time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.server_thread.stop()
        cls.server_thread.join(timeout=5.0)
        hub.storage = cls.orig_storage
        try:
            cls.test_storage.close()
        except Exception:
            pass
        shutil.rmtree(cls.tmp, ignore_errors=True)

    async def test_01_mcp_unauthenticated_registration(self):
        """Verifies unauthenticated agent can call register_agent via real MCP SSE protocol."""
        async with sse_client(self.sse_url) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                init_res = await session.initialize()
                self.assertIsNotNone(init_res)

                # register_agent anonymously without Bearer token
                res = await session.call_tool(
                    "register_agent",
                    arguments={
                        "callsign": "NovatoMCP",
                        "display_name": "Novato MCP Agent",
                        "description": "Auto-registo via protocolo MCP real",
                    },
                )
                self.assertTrue(res.content)
                text = res.content[0].text
                self.assertNotIn("kwargs", text)
                self.assertNotIn("validation error", text.lower())
                parsed = json.loads(text)
                self.assertIn(parsed.get("status"), ("pending", "registered_pending_token"))
                self.assertEqual(parsed.get("callsign"), "NovatoMCP")

    async def test_02_mcp_unauthenticated_protected_tool_fails_auth(self):
        """Verifies calling a protected tool anonymously returns an auth rejection, not a kwargs error."""
        async with sse_client(self.sse_url) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                res = await session.call_tool("list_rooms", arguments={})
                self.assertTrue(res.content)
                text = res.content[0].text
                self.assertNotIn("kwargs", text)
                self.assertNotIn("validation error", text.lower())
                parsed = json.loads(text)
                self.assertEqual(parsed.get("status"), "error")
                err_msg = parsed.get("error", "").lower()
                self.assertTrue("access denied" in err_msg or "acesso negado" in err_msg)

    async def test_03_mcp_authenticated_sweep_all_36_tools(self):
        """
        Sweeps all 36 MCP tools over the real MCP SSE protocol using an authenticated agent session.
        Verifies:
          - Exactly 36 tools discovered.
          - Zero schema validation errors / zero 'kwargs Field required'.
          - All major tools execute successfully.
        """
        headers = {"Authorization": f"Bearer {self.agent_token}"}
        async with sse_client(self.sse_url, headers=headers) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                tools_list = await session.list_tools()
                self.assertEqual(len(tools_list.tools), 36)

                # Verify tool schemas do not expose kwargs as required
                for tool in tools_list.tools:
                    schema = tool.inputSchema or {}
                    props = schema.get("properties", {})
                    required = schema.get("required", [])
                    self.assertNotIn("kwargs", required, f"Tool '{tool.name}' has 'kwargs' in required list!")
                    self.assertNotIn("kwargs", props, f"Tool '{tool.name}' has 'kwargs' in schema properties!")

                # --- 1. Basic Room & Identity Tools ---
                res_id = await session.call_tool("get_my_identity", arguments={})
                parsed_id = json.loads(res_id.content[0].text)
                self.assertEqual(parsed_id.get("status"), "success")
                self.assertEqual(parsed_id.get("callsign"), "DevAgent")

                res_lr = await session.call_tool("list_rooms", arguments={})
                parsed_lr = json.loads(res_lr.content[0].text)
                self.assertEqual(parsed_lr.get("status"), "success")
                self.assertTrue(any(r["name"] == "geral" for r in parsed_lr.get("rooms", [])))

                res_lmr = await session.call_tool("list_my_rooms", arguments={})
                parsed_lmr = json.loads(res_lmr.content[0].text)
                self.assertEqual(parsed_lmr.get("status"), "success")

                # --- 2. Messaging & Reading ---
                res_sm = await session.call_tool(
                    "send_message",
                    arguments={"room_name": "geral", "content": "Teste real MCP SSE", "to": "all"},
                )
                parsed_sm = json.loads(res_sm.content[0].text)
                self.assertEqual(parsed_sm.get("status"), "success")
                msg_id = parsed_sm.get("message_id")
                self.assertIsNotNone(msg_id)

                res_rm = await session.call_tool(
                    "read_messages",
                    arguments={"room_name": "geral", "limit": 10},
                )
                parsed_rm = json.loads(res_rm.content[0].text)
                self.assertEqual(parsed_rm.get("status"), "success")
                self.assertTrue(any(m["id"] == msg_id for m in parsed_rm.get("messages", [])))

                # --- 3. Reactions ---
                res_rx = await session.call_tool(
                    "react_to_message",
                    arguments={"message_id": msg_id, "room_name": "geral", "emoji": "👍", "action": "add"},
                )
                parsed_rx = json.loads(res_rx.content[0].text)
                self.assertEqual(parsed_rx.get("status"), "success")

                # --- 4. Wake & Liveliness Tools ---
                res_wait = await session.call_tool(
                    "wait_for_work",
                    arguments={"room_name": "geral", "timeout_seconds": 0, "format": "json"},
                )
                parsed_wait = json.loads(res_wait.content[0].text)
                self.assertIn(parsed_wait.get("status"), ("timeout", "new_messages", "new_work"))

                res_ts = await session.call_tool(
                    "team_status",
                    arguments={"room_name": "geral"},
                )
                parsed_ts = json.loads(res_ts.content[0].text)
                self.assertEqual(parsed_ts.get("status"), "success")

                # --- 5. Decisions & Polls ---
                res_ch = await session.call_tool(
                    "call_human",
                    arguments={
                        "room_name": "geral",
                        "question": "Protocolo MCP real a funcionar?",
                        "options": ["Sim", "Não"],
                    },
                )
                parsed_ch = json.loads(res_ch.content[0].text)
                self.assertEqual(parsed_ch.get("status"), "success")

                res_cp = await session.call_tool(
                    "create_poll",
                    arguments={
                        "room_name": "geral",
                        "question": "Qual a melhor opção?",
                        "options": ["Opção 1", "Opção 2"],
                    },
                )
                parsed_cp = json.loads(res_cp.content[0].text)
                self.assertEqual(parsed_cp.get("status"), "success")
                poll_id = parsed_cp.get("poll", {}).get("id")
                self.assertIsNotNone(poll_id)

                res_gp = await session.call_tool("get_poll", arguments={"poll_id": poll_id})
                parsed_gp = json.loads(res_gp.content[0].text)
                self.assertEqual(parsed_gp.get("status"), "success")

                res_cv = await session.call_tool("cast_vote", arguments={"poll_id": poll_id, "option_index": 0})
                parsed_cv = json.loads(res_cv.content[0].text)
                self.assertEqual(parsed_cv.get("status"), "success")

                res_close_p = await session.call_tool("close_poll", arguments={"poll_id": poll_id})
                parsed_close_p = json.loads(res_close_p.content[0].text)
                self.assertEqual(parsed_close_p.get("status"), "success", f"close_poll failed: {parsed_close_p}")

                # --- 6. Tasks ---
                res_ct = await session.call_tool(
                    "create_task",
                    arguments={"room_name": "geral", "title": "Tarefa E2E Protocol", "priority": "high"},
                )
                parsed_ct = json.loads(res_ct.content[0].text)
                self.assertEqual(parsed_ct.get("status"), "success")
                task_id = parsed_ct.get("task", {}).get("id")
                self.assertIsNotNone(task_id)

                res_ut = await session.call_tool(
                    "update_task",
                    arguments={"task_id": task_id, "status": "in_progress"},
                )
                parsed_ut = json.loads(res_ut.content[0].text)
                self.assertEqual(parsed_ut.get("status"), "success")

                res_lt = await session.call_tool("list_tasks", arguments={"room_name": "geral"})
                parsed_lt = json.loads(res_lt.content[0].text)
                self.assertEqual(parsed_lt.get("status"), "success")

                res_rt = await session.call_tool("reorder_tasks", arguments={"room_name": "geral", "task_ids": [task_id]})
                parsed_rt = json.loads(res_rt.content[0].text)
                self.assertEqual(parsed_rt.get("status"), "success")

                # --- 7. Calendar ---
                res_ce = await session.call_tool(
                    "create_calendar_event",
                    arguments={
                        "room_name": "geral",
                        "title": "Evento Teste MCP",
                        "start_at": "2026-10-01T10:00:00Z",
                        "end_at": "2026-10-01T11:00:00Z",
                    },
                )
                parsed_ce = json.loads(res_ce.content[0].text)
                self.assertEqual(parsed_ce.get("status"), "success")
                event_id = parsed_ce.get("event", {}).get("id")
                self.assertIsNotNone(event_id)

                res_ue = await session.call_tool(
                    "update_calendar_event",
                    arguments={"event_id": event_id, "title": "Evento Teste MCP Atualizado"},
                )
                parsed_ue = json.loads(res_ue.content[0].text)
                self.assertEqual(parsed_ue.get("status"), "success")

                res_le = await session.call_tool("list_calendar_events", arguments={"room_name": "geral"})
                parsed_le = json.loads(res_le.content[0].text)
                self.assertEqual(parsed_le.get("status"), "success")

                res_cra = await session.call_tool(
                    "check_resource_availability",
                    arguments={"resource": "gpu-h100", "start_at": "2026-10-01T10:00:00Z"},
                )
                parsed_cra = json.loads(res_cra.content[0].text)
                self.assertEqual(parsed_cra.get("status"), "success")

                res_de = await session.call_tool("delete_calendar_event", arguments={"event_id": event_id})
                parsed_de = json.loads(res_de.content[0].text)
                self.assertEqual(parsed_de.get("status"), "success")

                # --- 8. Wait alias & Deprecated Tools (Verify clean response without schema failure) ---
                res_wfnm = await session.call_tool(
                    "wait_for_new_messages",
                    arguments={"room_name": "geral", "timeout_seconds": 0},
                )
                parsed_wfnm = json.loads(res_wfnm.content[0].text)
                self.assertIn(parsed_wfnm.get("status"), ("timeout", "new_messages", "new_work"))

                for dep_tool in ["check_new_messages", "wake_up_call", "who_is_listening", "get_room_transcript"]:
                    res_dep = await session.call_tool(dep_tool, arguments={"room_name": "geral"})
                    text_dep = res_dep.content[0].text
                    self.assertNotIn("kwargs", text_dep)
                    self.assertNotIn("validation error", text_dep.lower())
                    parsed_dep = json.loads(text_dep)
                    self.assertEqual(parsed_dep.get("status"), "error")
                    self.assertIn("descontinuad", parsed_dep.get("error", "").lower())

                # --- 9. Admin / Role Guarded Tools (Verify clean auth/role response without schema failure) ---
                for adm_tool, args in [
                    ("create_room", {"room_name": "nova_sala_teste"}),
                    ("join_room", {"room_name": "dev"}),
                    ("leave_room", {"room_name": "geral"}),
                    ("rotate_member_token", {"room_name": "geral", "member_name": "DevAgent"}),
                    ("change_room_password", {"room_name": "geral"}),
                    ("kick_member", {"room_name": "geral", "member_to_kick": "DevAgent"}),
                    ("archive_room", {"room_name": "geral"}),
                    ("get_room_audit_log", {"room_name": "geral"}),
                ]:
                    res_adm = await session.call_tool(adm_tool, arguments=args)
                    text_adm = res_adm.content[0].text
                    self.assertNotIn("kwargs", text_adm)
                    self.assertNotIn("validation error", text_adm.lower())
                    parsed_adm = json.loads(text_adm)
                    # Must return error (due to permissions/admin role required), but must NOT fail schema validation
                    self.assertEqual(parsed_adm.get("status"), "error")


if __name__ == "__main__":
    unittest.main()
