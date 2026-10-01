"""
Tests for ai-chat v3.2 Phase 3 Block E: Claude Code Stop Hook Mode.
Verifies:
  - Structured output {"decision": "block", "reason": "..."} when work is available.
  - Role reminder and messages properly included in block reason.
  - Structured output {"decision": "allow", ...} and exit 0 when timeout/no work.
  - Structured output {"decision": "allow", ...} and exit 0 when network error / server offline (graceful, no crash).
  - Structured output {"decision": "allow", ...} and exit 0 when server returns 500 or error status.
  - Real subprocess CLI invocation against offline server exits with code 0.
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "migrations" / "v3"))

import importlib.util

TOOLS_SCRIPT = ROOT / "tools" / "aichat-wait.py"
spec = importlib.util.spec_from_file_location("aichat_wait", str(TOOLS_SCRIPT))
aichat_wait = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aichat_wait)


class TestV3Phase3ClaudeCodeHook(unittest.TestCase):
    def test_01_format_hook_with_work_and_role_reminder(self):
        """Verifies JSON block format with role reminder and room messages."""
        data = {
            "status": "new_work",
            "role_reminder": {
                "role_key": "developer",
                "display_name": "Desenvolvedor Backend",
                "reminder_text": "Escreve código limpo e testes automatizados.",
            },
            "messages": [
                {
                    "id": 1,
                    "sender": "ana",
                    "room_name": "dev",
                    "content": "Implementa o hook para Claude Code.",
                },
                {
                    "id": 2,
                    "sender_name": "carlos",
                    "room": "geral",
                    "content": "Confirmar se os testes passam.",
                },
            ],
        }

        output = aichat_wait.format_claude_code_hook(data, default_room="geral")
        parsed = json.loads(output)

        self.assertEqual(parsed.get("decision"), "block")
        reason = parsed.get("reason", "")
        self.assertIn("Nova atividade no ai-chat:", reason)
        self.assertIn("[Lembrete de Papel] Desenvolvedor Backend: Escreve código limpo e testes automatizados.", reason)
        self.assertIn("[#dev] @ana: Implementa o hook para Claude Code.", reason)
        self.assertIn("[#geral] @carlos: Confirmar se os testes passam.", reason)
        self.assertIn("Processa estas mensagens e responde no ai-chat.", reason)

    def test_02_format_hook_without_work(self):
        """Verifies JSON allow format when messages list is empty."""
        data = {"status": "timeout", "messages": []}
        output = aichat_wait.format_claude_code_hook(data, default_room="geral")
        parsed = json.loads(output)

        self.assertEqual(parsed.get("decision"), "allow")
        self.assertIn("Sem novas tarefas", parsed.get("message", ""))

    def test_03_main_hook_with_work(self):
        """Verifies main() returns 0 and outputs block JSON when work is returned."""
        fake_response_data = {
            "status": "new_work",
            "batch_id": "batch-12345",
            "role_reminder": {
                "role_key": "qa",
                "display_name": "Engenheiro de QA",
                "reminder_text": "Verifica cobertura de testes.",
            },
            "messages": [
                {
                    "id": 10,
                    "sender": "rui",
                    "room": "geral",
                    "content": "Verificar se o Stop hook está operacional.",
                }
            ],
        }

        class MockResponse:
            def __init__(self):
                self.status = 200

            def getcode(self):
                return 200

            def read(self):
                return json.dumps(fake_response_data).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        out_buf = io.StringIO()
        with patch.dict(os.environ, {"AICHAT_AGENT_TOKEN": "token_qa"}), \
             patch("urllib.request.urlopen", return_value=MockResponse()), \
             patch("sys.stdout", out_buf):
            code = aichat_wait.main([
                "--url", "http://testserver",
                "--agent", "qa-bot",
                "--timeout", "0",
                "--hook", "claude-code",
            ])

        self.assertEqual(code, aichat_wait.EXIT_SUCCESS)
        output = out_buf.getvalue()
        parsed = json.loads(output)
        self.assertEqual(parsed.get("decision"), "block")
        self.assertIn("Engenheiro de QA", parsed.get("reason", ""))
        self.assertIn("Verificar se o Stop hook está operacional.", parsed.get("reason", ""))

    def test_04_main_hook_timeout_no_work(self):
        """Verifies main() returns 0 and outputs allow JSON on timeout."""
        fake_response_data = {
            "status": "timeout",
            "messages": [],
            "count": 0,
        }

        class MockResponse:
            def getcode(self):
                return 200

            def read(self):
                return json.dumps(fake_response_data).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        out_buf = io.StringIO()
        with patch.dict(os.environ, {"AICHAT_AGENT_TOKEN": "token_qa"}), \
             patch("urllib.request.urlopen", return_value=MockResponse()), \
             patch("sys.stdout", out_buf):
            code = aichat_wait.main([
                "--url", "http://testserver",
                "--agent", "qa-bot",
                "--timeout", "0",
                "--hook", "claude-code",
            ])

        self.assertEqual(code, aichat_wait.EXIT_SUCCESS)
        output = out_buf.getvalue()
        parsed = json.loads(output)
        self.assertEqual(parsed.get("decision"), "allow")
        self.assertIn("Sem novas tarefas", parsed.get("message", ""))

    def test_05_main_hook_network_error_resilience(self):
        """Verifies main() exits 0 and outputs allow JSON when network fails (no crash)."""
        out_buf = io.StringIO()
        with patch.dict(os.environ, {"AICHAT_AGENT_TOKEN": "token_qa"}), \
             patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")), \
             patch("sys.stdout", out_buf):
            code = aichat_wait.main([
                "--url", "http://testserver",
                "--agent", "qa-bot",
                "--timeout", "0",
                "--hook", "claude-code",
            ])

        self.assertEqual(code, aichat_wait.EXIT_SUCCESS)
        output = out_buf.getvalue()
        parsed = json.loads(output)
        self.assertEqual(parsed.get("decision"), "allow")
        self.assertIn("indisponível", parsed.get("message", "").lower())

    def test_06_main_hook_server_500_resilience(self):
        """Verifies main() exits 0 and outputs allow JSON when server returns 500 error."""
        class Mock500Response:
            def getcode(self):
                return 500

            def read(self):
                return json.dumps({"error": "Erro interno de teste"}).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        out_buf = io.StringIO()
        err_500 = urllib.error.HTTPError(
            "http://testserver/api/wake",
            500,
            "Internal Server Error",
            {},
            io.BytesIO(b'{"error": "Erro interno de teste"}'),
        )
        with patch.dict(os.environ, {"AICHAT_AGENT_TOKEN": "token_qa"}), \
             patch("urllib.request.urlopen", side_effect=err_500), \
             patch("sys.stdout", out_buf):
            code = aichat_wait.main([
                "--url", "http://testserver",
                "--agent", "qa-bot",
                "--timeout", "0",
                "--hook", "claude-code",
            ])

        self.assertEqual(code, aichat_wait.EXIT_SUCCESS)
        output = out_buf.getvalue()
        parsed = json.loads(output)
        self.assertEqual(parsed.get("decision"), "allow")

    def test_07_main_hook_missing_token_resilience(self):
        """Verifies main() exits 0 and outputs allow JSON when token is missing in hook mode."""
        out_buf = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), patch("sys.stdout", out_buf):
            os.environ.pop("AICHAT_AGENT_TOKEN", None)
            code = aichat_wait.main([
                "--url", "http://testserver",
                "--agent", "inexistent-agent-xyz-99",
                "--timeout", "0",
                "--hook", "claude-code",
            ])

        self.assertEqual(code, aichat_wait.EXIT_SUCCESS)
        output = out_buf.getvalue()
        parsed = json.loads(output)
        self.assertEqual(parsed.get("decision"), "allow")
        self.assertIn("Token não configurado", parsed.get("message", ""))

    def test_08_cli_subprocess_offline_server(self):
        """Verifies actual subprocess execution against a closed port exits cleanly with code 0."""
        cmd = [
            sys.executable,
            str(TOOLS_SCRIPT),
            "--url", "http://127.0.0.1:59998",
            "--agent", "test-agent",
            "--timeout", "0",
            "--hook", "claude-code",
        ]
        env = dict(os.environ)
        env["AICHAT_AGENT_TOKEN"] = "test-token-1234"
        result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=10)

        self.assertEqual(result.returncode, 0, f"Expected 0 but got {result.returncode}. Stderr: {result.stderr}")
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed.get("decision"), "allow")


if __name__ == "__main__":
    unittest.main()
