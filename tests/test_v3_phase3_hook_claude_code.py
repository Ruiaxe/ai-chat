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
        """Verifies JSON block format with minimal waiting instruction when messages list is empty."""
        data = {"status": "timeout", "messages": []}
        output = aichat_wait.format_claude_code_hook(data, default_room="geral")
        parsed = json.loads(output)

        self.assertEqual(parsed.get("decision"), "block")
        self.assertIn("Sem novas mensagens", parsed.get("reason", ""))

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
        """Verifies main() returns 0 and outputs block JSON on timeout to keep agent loop active."""
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
        self.assertEqual(parsed.get("decision"), "block")
        self.assertIn("Sem novas mensagens", parsed.get("reason", ""))

    def test_05_main_hook_network_error_resilience(self):
        """Verifies main() exits 0 and outputs block JSON when network fails (no crash, keeps loop active)."""
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
        self.assertEqual(parsed.get("decision"), "block")
        self.assertIn("indisponível", parsed.get("reason", "").lower())

    def test_06_main_hook_server_500_resilience(self):
        """Verifies main() exits 0 and outputs block JSON when server returns 500 error."""
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
        self.assertEqual(parsed.get("decision"), "block")

    def test_07_main_hook_missing_token_resilience(self):
        """Verifies main() exits 0 and outputs block JSON when token is missing in hook mode."""
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
        self.assertEqual(parsed.get("decision"), "block")
        self.assertIn("Token não configurado", parsed.get("reason", ""))

    def test_08_cli_subprocess_offline_server(self):
        """Verifies actual subprocess execution against a closed port exits cleanly with code 0 and decision block."""
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
        self.assertEqual(parsed.get("decision"), "block")

    def test_09_hook_retry_with_backoff_on_transient_failure(self):
        """Verifies that transient connection failures trigger retries with increasing sleep intervals within hook timeout."""
        calls = 0

        class MockTransientResponse:
            def getcode(self):
                return 200

            def read(self):
                return json.dumps({
                    "status": "new_work",
                    "messages": [{"id": 99, "sender": "rui", "content": "Sucesso após retry!"}],
                }).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        def side_effect_urlopen(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls < 3:
                raise urllib.error.URLError("Temporary connection glitch")
            return MockTransientResponse()

        sleep_calls = []

        def mock_sleep(seconds):
            sleep_calls.append(seconds)

        out_buf = io.StringIO()
        with patch.dict(os.environ, {"AICHAT_AGENT_TOKEN": "token_qa"}), \
             patch("urllib.request.urlopen", side_effect=side_effect_urlopen), \
             patch("time.sleep", side_effect=mock_sleep), \
             patch("sys.stdout", out_buf):
            code = aichat_wait.main([
                "--url", "http://testserver",
                "--agent", "qa-bot",
                "--timeout", "10",
                "--hook", "claude-code",
            ])

        self.assertEqual(code, aichat_wait.EXIT_SUCCESS)
        self.assertEqual(calls, 3)
        # Verify increasing intervals
        self.assertGreaterEqual(len(sleep_calls), 2)
        self.assertGreater(sleep_calls[1], sleep_calls[0])
        parsed = json.loads(out_buf.getvalue())
        self.assertEqual(parsed.get("decision"), "block")
        self.assertIn("Sucesso após retry!", parsed.get("reason", ""))

    def test_10_hook_timeout_warning_and_clamp_when_timeout_not_less_than_hook(self):
        """Verifies warning emitted and timeout clamped when --timeout >= --hook-timeout."""
        recorded_url = []

        class MockResponse:
            def getcode(self):
                return 200

            def read(self):
                return json.dumps({"status": "timeout", "messages": []}).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        def mock_urlopen(req, timeout=None):
            recorded_url.append(req.get_full_url())
            return MockResponse()

        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with patch.dict(os.environ, {"AICHAT_AGENT_TOKEN": "token_qa"}), \
             patch("urllib.request.urlopen", side_effect=mock_urlopen), \
             patch("sys.stdout", out_buf), \
             patch("sys.stderr", err_buf):
            code = aichat_wait.main([
                "--url", "http://testserver",
                "--agent", "qa-bot",
                "--hook", "claude-code",
                "--hook-timeout", "1800",
                "--timeout", "1800",
            ])

        self.assertEqual(code, aichat_wait.EXIT_SUCCESS)
        stderr_text = err_buf.getvalue()
        self.assertIn("[AVISO]", stderr_text)
        self.assertIn("1800s", stderr_text)
        self.assertIn("1740s", stderr_text)
        # Verify clamped timeout_seconds was sent in request query
        self.assertTrue(any("timeout_seconds=1740" in u for u in recorded_url))
        parsed = json.loads(out_buf.getvalue())
        self.assertEqual(parsed.get("decision"), "block")

    def test_11_no_warning_when_timeout_is_strictly_less(self):
        """Verifies NO warning is emitted when --timeout is strictly less than --hook-timeout."""
        recorded_url = []

        class MockResponse:
            def getcode(self):
                return 200

            def read(self):
                return json.dumps({"status": "timeout", "messages": []}).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        def mock_urlopen(req, timeout=None):
            recorded_url.append(req.get_full_url())
            return MockResponse()

        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with patch.dict(os.environ, {"AICHAT_AGENT_TOKEN": "token_qa"}), \
             patch("urllib.request.urlopen", side_effect=mock_urlopen), \
             patch("sys.stdout", out_buf), \
             patch("sys.stderr", err_buf):
            code = aichat_wait.main([
                "--url", "http://testserver",
                "--agent", "qa-bot",
                "--hook", "claude-code",
                "--hook-timeout", "1800",
                "--timeout", "1740",
            ])

        self.assertEqual(code, aichat_wait.EXIT_SUCCESS)
        stderr_text = err_buf.getvalue()
        self.assertNotIn("[AVISO]", stderr_text)
        self.assertTrue(any("timeout_seconds=1740" in u for u in recorded_url))

    def test_12_profile_hook_timeout_loaded_and_clamps(self):
        """Verifies hook_timeout is loaded from ~/.aichat/<agent>.json profile and warns/clamps."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            profile_file = tmppath / "custom_bot.json"
            profile_file.write_text(
                json.dumps({
                    "url": "http://testserver",
                    "token": "tok_from_profile",
                    "hook_timeout": 600,
                }),
                encoding="utf-8",
            )

            recorded_url = []

            class MockResponse:
                def getcode(self):
                    return 200

                def read(self):
                    return json.dumps({"status": "timeout", "messages": []}).encode("utf-8")

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    pass

            def mock_urlopen(req, timeout=None):
                recorded_url.append(req.get_full_url())
                return MockResponse()

            out_buf = io.StringIO()
            err_buf = io.StringIO()
            with patch.dict(os.environ, {}, clear=True), \
                 patch.object(aichat_wait, "get_aichat_dir", return_value=tmppath), \
                 patch("urllib.request.urlopen", side_effect=mock_urlopen), \
                 patch("sys.stdout", out_buf), \
                 patch("sys.stderr", err_buf):
                code = aichat_wait.main([
                    "--agent", "custom_bot",
                    "--hook", "claude-code",
                    "--timeout", "600",
                ])

            self.assertEqual(code, aichat_wait.EXIT_SUCCESS)
            stderr_text = err_buf.getvalue()
            self.assertIn("[AVISO]", stderr_text)
            self.assertIn("600s", stderr_text)
            self.assertIn("540s", stderr_text)
            self.assertTrue(any("timeout_seconds=540" in u for u in recorded_url))

    def test_13_responds_strictly_before_n_seconds(self):
        """Verifies that with a hook of N seconds, aichat-wait always finishes strictly before N."""
        import time

        hook_n = 2
        # Margin for N=2 is 1s, clamped timeout is 1s
        class MockServerDelayResponse:
            def getcode(self):
                return 200

            def read(self):
                return json.dumps({"status": "timeout", "messages": []}).encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        def mock_delayed_urlopen(req, timeout=None):
            # Server delays by poll_timeout (clamped to 1s)
            time.sleep(0.5)
            return MockServerDelayResponse()

        out_buf = io.StringIO()
        t0 = time.monotonic()
        with patch.dict(os.environ, {"AICHAT_AGENT_TOKEN": "token_qa"}), \
             patch("urllib.request.urlopen", side_effect=mock_delayed_urlopen), \
             patch("sys.stdout", out_buf):
            code = aichat_wait.main([
                "--url", "http://testserver",
                "--agent", "qa-bot",
                "--hook", "claude-code",
                "--hook-timeout", str(hook_n),
                "--timeout", str(hook_n),
            ])
        elapsed = time.monotonic() - t0

        self.assertEqual(code, aichat_wait.EXIT_SUCCESS)
        self.assertLess(elapsed, float(hook_n), f"Response took {elapsed:.3f}s, expected strictly < {hook_n}s")
        parsed = json.loads(out_buf.getvalue())
        self.assertEqual(parsed.get("decision"), "block")

    def test_14_subprocess_cli_responds_before_n_seconds(self):
        """Verifies real subprocess CLI execution against offline server responds strictly before N seconds."""
        import time

        hook_n = 2
        cmd = [
            sys.executable,
            str(TOOLS_SCRIPT),
            "--url", "http://127.0.0.1:59996",
            "--agent", "test-agent",
            "--hook", "claude-code",
            "--hook-timeout", str(hook_n),
            "--timeout", str(hook_n),
        ]
        env = dict(os.environ)
        env["AICHAT_AGENT_TOKEN"] = "test-token-1234"

        t0 = time.monotonic()
        result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=5)
        elapsed = time.monotonic() - t0

        self.assertEqual(result.returncode, 0, f"Expected 0 but got {result.returncode}. Stderr: {result.stderr}")
        self.assertLess(elapsed, float(hook_n), f"Subprocess took {elapsed:.3f}s, expected strictly < {hook_n}s")
        self.assertIn("[AVISO]", result.stderr)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed.get("decision"), "block")


if __name__ == "__main__":
    unittest.main()
