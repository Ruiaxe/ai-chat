"""
Test suite for ai-chat v3.1 Camada 2: Universal Wake-up Client (aichat-wait.py).
Verifies:
  - Script served at GET /tools/aichat-wait.py
  - CLI arguments and sub-process execution
  - Exit codes: 0 (new work / selftest), 2 (connection error), 3 (timeout no work), 4 (auth error)
  - Output formats: text, json, --hook claude-code, --hook opencode
  - Self-test mode (--selftest)
  - Batch confirmation via ACK
"""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from unittest.mock import patch

from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "migrations" / "v3"))

import migrate_v2_to_v3 as mig
from aichat.storage import ChatStorage
from aichat.web_app import create_app
from aichat.mcp_server import hub

# Import standalone client module dynamically
TOOLS_SCRIPT = ROOT / "tools" / "aichat-wait.py"
import importlib.util
spec = importlib.util.spec_from_file_location("aichat_wait", str(TOOLS_SCRIPT))
aichat_wait = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aichat_wait)


class MockUrlopenBridge:
    """Bridges urllib.request.urlopen directly to Starlette TestClient in-memory."""
    def __init__(self, client: TestClient):
        self.client = client

    def __call__(self, req, timeout=None):
        url = req.full_url
        headers = dict(req.headers)
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        if parsed.query:
            path = f"{path}?{parsed.query}"

        res = self.client.get(path, headers=headers)
        if res.status_code >= 400:
            fp = io.BytesIO(res.content)
            reason = getattr(res, "reason_phrase", str(res.status_code))
            raise urllib.error.HTTPError(url, res.status_code, reason, res.headers, fp)

        class MockResponse:
            def __init__(self, response):
                self._resp = response

            def getcode(self):
                return self._resp.status_code

            def read(self):
                return self._resp.content

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        return MockResponse(res)


class TestV3WakeLayer2(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="aichat_wake_l2_"))
        cls.src_path = cls.tmp / "chat_v2.db"
        cls.logs_dir = cls.tmp / "logs"

        # 1. Build v2 database
        v2_st = ChatStorage(db_path=cls.src_path, logs_dir=cls.logs_dir)
        v2_st.create_room("geral", topic="Sala Geral")
        v2_st.create_room("dev", topic="Sala Dev")
        v2_st.close()

        # 2. Run migration to v3
        cls.out_dir = cls.tmp / "migration_out"
        cls.dst_path = cls.tmp / "chat_v3.db"
        rc = mig.main([
            "--source", str(cls.src_path),
            "--target", str(cls.dst_path),
            "--admin-username", "Rui",
            "--out-dir", str(cls.out_dir),
        ])
        assert rc == 0, "Migration returned non-zero exit code"

        # 3. Mount v3 storage into global hub and create Starlette app
        cls.orig_storage = hub.storage
        cls.test_storage = ChatStorage(db_path=cls.dst_path, logs_dir=cls.logs_dir)
        assert cls.test_storage.is_v3()
        hub.storage = cls.test_storage

        os.environ["AICHAT_TESTING"] = "1"
        cls.app = create_app()
        cls.client = TestClient(cls.app)
        cls.bridge = MockUrlopenBridge(cls.client)

        # Create active test agent "ana" via storage
        pid, raw_token = hub.storage.v3.create_agent(
            callsign="ana",
            display_name="Ana Researcher",
            status="active",
        )
        cls.ana_id = pid
        cls.ana_token = raw_token

        # Create active test agent "carlos" via storage
        pid_c, raw_token_c = hub.storage.v3.create_agent(
            callsign="carlos",
            display_name="Carlos Dev",
            status="active",
        )
        cls.carlos_id = pid_c
        cls.carlos_token = raw_token_c

        # Join rooms
        geral = hub.storage.v3.get_room("geral")
        hub.storage.v3.grant_room_access(geral["id"], cls.ana_id, can_write=1)
        hub.storage.v3.grant_room_access(geral["id"], cls.carlos_id, can_write=1)

    @classmethod
    def tearDownClass(cls):
        hub.storage = cls.orig_storage
        try:
            cls.test_storage.close()
        except Exception:
            pass
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_01_script_file_exists_and_served_by_endpoint(self):
        """Verifies aichat-wait.py is in tools/, static/tools/ and served at GET /tools/aichat-wait.py."""
        self.assertTrue(TOOLS_SCRIPT.exists(), f"{TOOLS_SCRIPT} does not exist")
        static_script = ROOT / "aichat" / "static" / "tools" / "aichat-wait.py"
        self.assertTrue(static_script.exists(), f"{static_script} does not exist")

        res = self.client.get("/tools/aichat-wait.py")
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/x-python", res.headers.get("content-type", ""))
        self.assertIn("ai-chat Universal Wake-up Client", res.text)

    def test_02_cli_help_and_syntax(self):
        """Verifies CLI help runs via subprocess and outputs usage."""
        proc = subprocess.run(
            [sys.executable, str(TOOLS_SCRIPT), "--help"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("ai-chat Universal Wake-up Client", proc.stdout)
        self.assertIn("--url", proc.stdout)
        self.assertIn("--token", proc.stdout)
        self.assertIn("--selftest", proc.stdout)
        self.assertIn("--hook", proc.stdout)

    def test_03_missing_token_exit_4(self):
        """Verifies exit code 4 when token is missing."""
        err_buf = io.StringIO()
        with patch("sys.stderr", err_buf):
            code = aichat_wait.main(["--url", "http://testserver", "--token", ""])
        self.assertEqual(code, aichat_wait.EXIT_AUTH_ERROR)
        self.assertIn("Token do agente em falta", err_buf.getvalue())

    def test_04_connection_error_exit_2(self):
        """Verifies exit code 2 when ai-chat server is unreachable."""
        # Test directly via subprocess against an unused port
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOLS_SCRIPT),
                "--url", "http://127.0.0.1:59998",
                "--token", "aic_test_token",
                "--timeout", "1",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, aichat_wait.EXIT_CONNECTION_ERROR)
        self.assertIn("ERRO", proc.stderr)

    def test_05_selftest_success_and_failure(self):
        """Verifies --selftest behavior for valid tokens, bad tokens, and connection failures."""
        # 1. Success case with valid token
        err_buf = io.StringIO()
        with patch("urllib.request.urlopen", self.bridge), patch("sys.stderr", err_buf):
            code = aichat_wait.main([
                "--url", "http://testserver",
                "--token", self.ana_token,
                "--room", "geral",
                "--selftest",
            ])
        self.assertEqual(code, aichat_wait.EXIT_SUCCESS)
        out = err_buf.getvalue()
        self.assertIn("[OK] Ligação ao servidor bem sucedida", out)
        self.assertIn("[OK] Token de agente válido e autenticado", out)
        self.assertIn("[OK] Todos os testes passaram com sucesso!", out)

        # 2. Failure with invalid token -> Exit 4
        err_buf_bad = io.StringIO()
        with patch("urllib.request.urlopen", self.bridge), patch("sys.stderr", err_buf_bad):
            code_bad = aichat_wait.main([
                "--url", "http://testserver",
                "--token", "aic_invalid_tok_xyz",
                "--room", "geral",
                "--selftest",
            ])
        self.assertEqual(code_bad, aichat_wait.EXIT_AUTH_ERROR)
        self.assertIn("[FAIL] Autenticação rejeitada", err_buf_bad.getvalue())

    def test_06_timeout_no_work_exit_3(self):
        """Verifies exit code 3 when polling completes without work."""
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with patch("urllib.request.urlopen", self.bridge), patch("sys.stdout", out_buf), patch("sys.stderr", err_buf):
            code = aichat_wait.main([
                "--url", "http://testserver",
                "--token", self.carlos_token,
                "--room", "geral",
                "--timeout", "0",
            ])
        self.assertEqual(code, aichat_wait.EXIT_TIMEOUT_NO_WORK)

    async def test_07_new_work_received_exit_0_text_and_json(self):
        """Verifies exit code 0 when new messages arrive, testing text and json output formats."""
        # Ana sends a message to Carlos
        res_m = await hub.send_message(
            room_name="geral",
            sender="ana",
            content="@carlos preparar testes para entrega da camada 2.",
            member_token=self.ana_token,
        )
        msg_id = res_m["id"]

        # 1. Test text format output
        text_out = io.StringIO()
        with patch("urllib.request.urlopen", self.bridge), patch("sys.stdout", text_out):
            code_text = aichat_wait.main([
                "--url", "http://testserver",
                "--token", self.carlos_token,
                "--room", "geral",
                "--timeout", "0",
                "--format", "text",
            ])
        self.assertEqual(code_text, aichat_wait.EXIT_SUCCESS)
        text_val = text_out.getvalue()
        self.assertTrue("ana" in text_val.lower() or "Ana Researcher" in text_val)
        self.assertIn("preparar testes para entrega da camada 2", text_val)

        # 2. Test JSON format output (redelivered batch)
        json_out = io.StringIO()
        with patch("urllib.request.urlopen", self.bridge), patch("sys.stdout", json_out):
            code_json = aichat_wait.main([
                "--url", "http://testserver",
                "--token", self.carlos_token,
                "--room", "geral",
                "--timeout", "0",
                "--format", "json",
            ])
        self.assertEqual(code_json, aichat_wait.EXIT_SUCCESS)
        parsed = json.loads(json_out.getvalue())
        self.assertIn(parsed.get("status"), ("new_work", "new_messages"))
        self.assertTrue(len(parsed.get("messages", [])) >= 1)
        self.assertEqual(parsed["messages"][0]["id"], msg_id)

    def test_08_hook_formats_claude_code_and_opencode(self):
        """Verifies hook format output for claude-code and opencode."""
        mock_data = {
            "status": "new_work",
            "messages": [
                {
                    "id": 101,
                    "sender": "ana",
                    "room": "geral",
                    "content": "Por favor reveja o PR de wake-up universal.",
                }
            ],
            "count": 1,
        }

        # Claude Code hook
        cc_out = aichat_wait.format_claude_code_hook(mock_data, "geral")
        self.assertIn("Nova atividade no ai-chat", cc_out)
        self.assertIn("[#geral] @ana:", cc_out)
        self.assertIn("Por favor reveja o PR de wake-up universal.", cc_out)

        # OpenCode hook
        oc_out = aichat_wait.format_opencode_hook(mock_data, "geral")
        self.assertIn("[ai-chat:opencode] #geral @ana:", oc_out)
        self.assertIn("Por favor reveja o PR de wake-up universal.", oc_out)

        # Main with --hook claude-code
        out_buf = io.StringIO()
        with patch("urllib.request.urlopen", self.bridge), patch("sys.stdout", out_buf):
            code_hook = aichat_wait.main([
                "--url", "http://testserver",
                "--token", self.carlos_token,
                "--room", "geral",
                "--timeout", "0",
                "--hook", "claude-code",
            ])
        self.assertEqual(code_hook, aichat_wait.EXIT_SUCCESS)
        self.assertIn("Nova atividade no ai-chat", out_buf.getvalue())

    async def test_09_ack_and_redelivery_in_wait_script(self):
        """Verifies batch confirmation using --ack <id> in aichat-wait.py."""
        # Ana sends a message to Carlos
        res_m = await hub.send_message(
            room_name="geral",
            sender="ana",
            content="@carlos confirmação de teste ACK final.",
            member_token=self.ana_token,
        )
        msg_id = res_m["id"]

        # Call with ack=0 -> unconfirmed batch is recorded
        with patch("urllib.request.urlopen", self.bridge), patch("sys.stdout", io.StringIO()):
            code1 = aichat_wait.main([
                "--url", "http://testserver",
                "--token", self.carlos_token,
                "--room", "geral",
                "--timeout", "0",
                "--ack", "0",
            ])
        self.assertEqual(code1, aichat_wait.EXIT_SUCCESS)
        carlos_row = hub.storage.v3.get_principal_by_id(self.carlos_id)
        self.assertTrue(carlos_row.get("unconfirmed_batch_ids"))

        # Call with ack=msg_id -> unconfirmed batch is cleared
        with patch("urllib.request.urlopen", self.bridge), patch("sys.stdout", io.StringIO()):
            code2 = aichat_wait.main([
                "--url", "http://testserver",
                "--token", self.carlos_token,
                "--room", "geral",
                "--timeout", "0",
                "--ack", str(msg_id),
            ])
        # carlos batch is cleared; since there is no new work, returns EXIT_TIMEOUT_NO_WORK (3)
        self.assertEqual(code2, aichat_wait.EXIT_TIMEOUT_NO_WORK)
        carlos_cleared = hub.storage.v3.get_principal_by_id(self.carlos_id)
        self.assertFalse(carlos_cleared.get("unconfirmed_batch_ids"))


if __name__ == "__main__":
    unittest.main()
