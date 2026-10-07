"""
tests/test_ui_smoke_playwright.py
Headless browser smoke test using Playwright.
Verifies that:
1. /admin loads cleanly and all principal modals open without any console or page errors (guards against missing references like refreshRolesList, agentsCache, etc.).
2. / (chat) loads cleanly and all principal modals open without any console or page errors (guards against missing references like escapeJs, formatRelativeTime, etc.).

If Playwright is not installed or no supported browser is available in the environment,
the test is skipped with a descriptive message.
"""

import os
os.environ["AICHAT_TESTING"] = "1"

import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

import uvicorn
import pytest

# Check for Playwright availability
try:
    from playwright.sync_api import sync_playwright, Error as PlaywrightError
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    sync_playwright = None
    PlaywrightError = Exception

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


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="playwright is not installed in environment")
class TestUISmokePlaywright(unittest.TestCase):
    """Playwright headless browser smoke tests for / and /admin."""

    server_thread = None
    playwright_instance = None
    browser = None
    base_url = None
    admin_token = None
    user_token = None
    room_id = None
    agent_id = None
    user_id = None
    orig_storage = None
    test_storage = None
    tmp_dir = None

    @classmethod
    def setUpClass(cls):
        if not PLAYWRIGHT_AVAILABLE:
            raise unittest.SkipTest("playwright is not installed")

        # 1. Try launching Playwright browser (chromium, msedge, or chrome)
        cls.playwright_instance = sync_playwright().start()
        cls.browser = None
        for channel in [None, "msedge", "chrome"]:
            try:
                if channel:
                    cls.browser = cls.playwright_instance.chromium.launch(headless=True, channel=channel)
                else:
                    cls.browser = cls.playwright_instance.chromium.launch(headless=True)
                break
            except Exception:
                continue

        if not cls.browser:
            cls.playwright_instance.stop()
            raise unittest.SkipTest("No Playwright or compatible system browser (chromium/edge/chrome) available")

        # 2. Set up isolated test storage
        cls.tmp_dir = Path(tempfile.mkdtemp(prefix="aichat_smoke_playwright_"))
        v3_path = cls.tmp_dir / "chat_smoke.db"
        logs_dir = cls.tmp_dir / "logs"

        cls.orig_storage = hub.storage
        cls.test_storage = ChatStorage(db_path=v3_path, logs_dir=logs_dir, schema_version=3)
        hub.storage = cls.test_storage

        # 3. Create test users and rooms
        admin_id = hub.storage.v3.create_human(
            "admin_test", "AdminPass123!", display_name="Admin Test", access_role="admin", must_change_password=0
        )
        cls.admin_token = hub.storage.v3.create_human_session(admin_id)

        cls.user_id = hub.storage.v3.create_human(
            "user_test", "UserPass123!", display_name="User Test", access_role="user", must_change_password=0
        )
        cls.user_token = hub.storage.v3.create_human_session(cls.user_id)

        room = hub.storage.v3.create_room("general", topic="Sala Geral")
        cls.room_id = room["id"]

        cls.agent_id, _ = hub.storage.v3.create_agent("bot_test", "Bot Test", status="active")
        hub.storage.v3.grant_room_access(cls.room_id, cls.agent_id, can_write=1)
        hub.storage.v3.grant_room_access(cls.room_id, admin_id, can_write=1)
        hub.storage.v3.grant_room_access(cls.room_id, cls.user_id, can_write=1)

        # 4. Start ephemeral test server
        cls.port = get_free_port()
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.app = create_app(["*"])
        cls.server_thread = ServerThread(cls.app, "127.0.0.1", cls.port)
        cls.server_thread.start()

        for _ in range(50):
            if cls.server_thread.server.started:
                break
            time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        if cls.browser:
            cls.browser.close()
        if cls.playwright_instance:
            cls.playwright_instance.stop()
        if cls.server_thread:
            cls.server_thread.stop()
            cls.server_thread.join(timeout=4.0)
        if cls.test_storage:
            cls.test_storage.close()
        if cls.orig_storage:
            hub.storage = cls.orig_storage

    def test_01_admin_console_and_modals(self):
        """Opens /admin, switches all tabs, and triggers all principal modals without any console/page error."""
        console_errors = []
        page_errors = []

        context = self.browser.new_context()
        context.add_cookies([{
            "name": "human_session",
            "value": self.admin_token,
            "domain": "127.0.0.1",
            "path": "/"
        }])
        page = context.new_page()

        page.on("console", lambda msg: (
            console_errors.append(f"[{msg.type}] {msg.text}")
            if msg.type == "error" and "favicon.ico" not in msg.text
            else None
        ))
        page.on("pageerror", lambda err: page_errors.append(str(err)))

        # Load /admin
        resp = page.goto(f"{self.base_url}/admin", wait_until="networkidle")
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status, 200, f"/admin returned HTTP {resp.status}")

        # Switch through tabs
        tabs = ['agents', 'rooms', 'humans', 'roles', 'audit', 'settings', 'system', 'matrix']
        for tab in tabs:
            page.evaluate(f"switchTab('{tab}')")

        # Open and test admin modals
        page.evaluate("openCreateUserModal()")
        page.evaluate(f"openResetPasswordModal({self.user_id}, 'user_test')")
        page.evaluate("openCreateAgentModal()")
        page.evaluate("openCreateRoomModal()")
        # openEditMemberModal specifically exercises role loading and member editing
        page.evaluate(f"openEditMemberModal({self.room_id}, {self.agent_id}, 'membro', 1, 'bot_test', null)")
        page.evaluate(f"openAddMemberModal({self.room_id})")
        page.evaluate(f"openBulkGrantModal({self.room_id})")
        page.evaluate(f"openWakeSnippetModal({self.agent_id}, 'bot_test', 'claude-code', 'background')")
        page.evaluate(f"openAgentRoomsModal({self.agent_id}, 'bot_test')")
        page.evaluate("openCreateRoleModal()")

        context.close()

        self.assertEqual(
            page_errors,
            [],
            f"/admin threw uncaught JavaScript errors: {page_errors}"
        )
        self.assertEqual(
            console_errors,
            [],
            f"/admin logged console errors: {console_errors}"
        )

    def test_02_index_chat_and_modals(self):
        """Opens / (chat UI) and triggers all principal modals without any console/page error."""
        console_errors = []
        page_errors = []

        context = self.browser.new_context()
        context.add_cookies([{
            "name": "human_session",
            "value": self.user_token,
            "domain": "127.0.0.1",
            "path": "/"
        }])
        page = context.new_page()

        page.on("console", lambda msg: (
            console_errors.append(f"[{msg.type}] {msg.text}")
            if msg.type == "error" and "favicon.ico" not in msg.text
            else None
        ))
        page.on("pageerror", lambda err: page_errors.append(str(err)))
        page.on("response", lambda r: print(f"RESPONSE >= 400: {r.status} {r.url}") if r.status >= 400 else None)

        # Load /
        resp = page.goto(f"{self.base_url}/", wait_until="networkidle")
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status, 200, f"/ returned HTTP {resp.status}")

        # Trigger modals
        page.evaluate("openCreateRoomModal()")
        page.evaluate("openCreatePollModal()")
        page.evaluate("openChangePasswordModal()")
        page.evaluate("openCurrentRoomTokenModal()")
        # openAgentUnreadModal specifically exercises escapeJs and formatRelativeTime
        page.evaluate(f"openAgentUnreadModal('bot_test', {self.agent_id})")
        page.evaluate("closeModal('modal-agent-unread')")

        context.close()

        self.assertEqual(
            page_errors,
            [],
            f"/ threw uncaught JavaScript errors: {page_errors}"
        )
        self.assertEqual(
            console_errors,
            [],
            f"/ logged console errors: {console_errors}"
        )


if __name__ == "__main__":
    unittest.main()
