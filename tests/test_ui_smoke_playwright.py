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

        # Open and test admin modals with visibility assertions
        admin_modals = [
            ("openCreateUserModal()", "modal-create-user"),
            (f"openResetPasswordModal({self.user_id}, 'user_test')", "modal-reset-password"),
            ("openCreateAgentModal()", "modal-create-agent"),
            ("openCreateRoomModal()", "modal-create-room"),
            (f"openEditMemberModal({self.room_id}, {self.agent_id}, 'membro', 1, 'bot_test', null)", "modal-edit-member"),
            (f"openAddMemberModal({self.room_id})", "modal-add-member"),
            (f"openBulkGrantModal({self.room_id})", "modal-bulk-grant"),
            (f"openWakeSnippetModal({self.agent_id}, 'bot_test', 'claude-code', 'background')", "modal-wake-snippet"),
            (f"openAgentRoomsModal({self.agent_id}, 'bot_test')", "modal-agent-rooms"),
            ("openCreateRoleModal()", "modal-role"),
        ]

        for open_call, modal_id in admin_modals:
            page.evaluate(open_call)
            self.assertTrue(
                page.is_visible(f"#{modal_id}"),
                f"Admin modal #{modal_id} should be visible after {open_call}"
            )
            page.evaluate(f"closeModal('{modal_id}')")
            self.assertFalse(
                page.is_visible(f"#{modal_id}"),
                f"Admin modal #{modal_id} should be hidden after closeModal"
            )

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
        """Opens / (chat UI) and triggers all principal modals with visibility assertions."""
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

        # Load /
        resp = page.goto(f"{self.base_url}/", wait_until="networkidle")
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status, 200, f"/ returned HTTP {resp.status}")

        # Trigger modals and assert visibility
        chat_modals = [
            ("openCreateRoomModal()", "create-room-modal", "closeCreateRoomModal()"),
            ("openCreatePollModal()", "create-poll-modal", "closeCreatePollModal()"),
            ("openChangePasswordModal(false)", "change-password-modal", "closeChangePasswordModal()"),
            (f"openAgentUnreadModal('bot_test', {self.agent_id})", "modal-agent-unread", "closeModal('modal-agent-unread')"),
        ]

        for open_call, modal_id, close_call in chat_modals:
            page.evaluate(open_call)
            self.assertTrue(
                page.is_visible(f"#{modal_id}"),
                f"Chat modal #{modal_id} should be visible after {open_call}"
            )
            page.evaluate(close_call)
            self.assertFalse(
                page.is_visible(f"#{modal_id}"),
                f"Chat modal #{modal_id} should be hidden after {close_call}"
            )

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

    def test_03_anonymous_visitor_login(self):
        """Verifies that an unauthenticated visitor sees #auth-modal, can fill credentials, and log in."""
        console_errors = []
        page_errors = []

        context = self.browser.new_context()  # No session cookie
        page = context.new_page()

        page.on("console", lambda msg: (
            console_errors.append(f"[{msg.type}] {msg.text}")
            if msg.type == "error" and "favicon.ico" not in msg.text
            else None
        ))
        page.on("pageerror", lambda err: page_errors.append(str(err)))

        resp = page.goto(f"{self.base_url}/", wait_until="networkidle")
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status, 200)

        # Anonymous visitor must be prompted with auth modal
        page.wait_for_selector("#auth-modal", state="visible", timeout=3000)
        self.assertTrue(page.is_visible("#auth-modal"), "Anonymous visitor must see #auth-modal visible")

        # Fill credentials for user_test
        page.fill("#human-auth-username-input", "user_test")
        page.fill("#human-auth-token-input", "UserPass123!")

        # Click submit button
        page.click("#auth-modal button[onclick*='submitAuthLogin']")

        # Wait for auth modal to become hidden after successful login
        page.wait_for_selector("#auth-modal", state="hidden", timeout=5000)
        self.assertFalse(page.is_visible("#auth-modal"), "#auth-modal should close after successful login")

        # Verify user is authenticated in the UI
        page.wait_for_selector("#my-user-status", timeout=3000)
        user_status_text = page.text_content("#my-user-status")
        self.assertIn("user_test", user_status_text)

        context.close()

        self.assertEqual(page_errors, [])
        self.assertEqual(console_errors, [])

    def test_04_must_change_password_forced_dialog(self):
        """Verifies that a user with must_change_password=1 has #change-password-modal forced open, cannot close it, and updates password successfully."""
        console_errors = []
        page_errors = []

        forced_user_id = hub.storage.v3.create_human(
            "forced_user", "OldPass123!", display_name="Forced User", access_role="user", must_change_password=1
        )
        hub.storage.v3.grant_room_access(self.room_id, forced_user_id, can_write=1)
        forced_session = hub.storage.v3.create_human_session(forced_user_id)

        context = self.browser.new_context()
        context.add_cookies([{
            "name": "human_session",
            "value": forced_session,
            "domain": "127.0.0.1",
            "path": "/"
        }])
        page = context.new_page()

        failed_responses = []
        page.on("console", lambda msg: (
            console_errors.append(f"[{msg.type}] {msg.text}")
            if msg.type == "error" and "favicon.ico" not in msg.text and "favicon.ico" not in str(getattr(msg, "location", ""))
            else None
        ))
        page.on("pageerror", lambda err: page_errors.append(str(err)))
        page.on("response", lambda r: failed_responses.append(f"{r.status} {r.url}") if r.status >= 400 and "favicon.ico" not in r.url else None)

        resp = page.goto(f"{self.base_url}/", wait_until="networkidle")
        self.assertIsNotNone(resp)
        self.assertEqual(resp.status, 200)

        # change-password-modal must be forced visible
        page.wait_for_selector("#change-password-modal", state="visible", timeout=3000)
        self.assertTrue(page.is_visible("#change-password-modal"), "#change-password-modal must be visible for mandatory change")

        # Close / cancel buttons should be hidden when mandatory
        self.assertFalse(page.is_visible("#change-pwd-close-btn"), "Close button should be hidden during mandatory password change")
        self.assertFalse(page.is_visible("#change-pwd-cancel-btn"), "Cancel button should be hidden during mandatory password change")

        # Attempting to call closeChangePasswordModal() should do nothing
        page.evaluate("closeChangePasswordModal()")
        self.assertTrue(page.is_visible("#change-password-modal"), "Modal must remain open after closeChangePasswordModal() when mandatory")

        # Fill new password
        page.fill("#new-password-input", "BrandNewPass456!")
        page.fill("#confirm-password-input", "BrandNewPass456!")

        # Submit password update
        page.click("#change-pwd-submit-btn")

        # Wait for modal to become hidden after successful change
        page.wait_for_selector("#change-password-modal", state="hidden", timeout=5000)
        self.assertFalse(page.is_visible("#change-password-modal"), "Modal should close after password is changed")

        context.close()

        self.assertEqual(page_errors, [])
        self.assertEqual(console_errors, [], f"Console errors: {console_errors}, Failed responses: {failed_responses}")


if __name__ == "__main__":
    unittest.main()
