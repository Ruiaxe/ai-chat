import os
os.environ["AICHAT_TESTING"] = "1"
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from starlette.testclient import TestClient

from aichat.config import BASE_DIR
from aichat.crypto import verify_password
from aichat.storage import ChatStorage
from aichat.web_app import create_app
from aichat.mcp_server import hub


class TestV3Phase2QoL(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.db_path = Path(cls.tmp) / "chat_v3.db"
        cls.logs_dir = Path(cls.tmp) / "logs"
        cls.test_storage = ChatStorage(db_path=cls.db_path, logs_dir=cls.logs_dir, schema_version=3)
        cls.orig_storage = hub.storage
        hub.storage = cls.test_storage

        # Setup roles
        cls.role_pm = hub.storage.v3.create_role("pm", "Project Manager", "Gerir o projeto")
        cls.role_dev = hub.storage.v3.create_role("dev", "Developer", "Escrever código")

        # Setup admin human
        cls.admin_human_id = hub.storage.v3.create_human(
            "admin_rui", "Admin123Pass!", display_name="Rui Admin", access_role="admin", must_change_password=0
        )
        cls.admin_token = hub.storage.v3.create_human_session(cls.admin_human_id)

        # Setup regular human
        cls.user_human_id = hub.storage.v3.create_human(
            "user_joao", "User123Pass!", display_name="Joao User", access_role="user", must_change_password=0
        )
        cls.user_token = hub.storage.v3.create_human_session(cls.user_human_id)

        # Setup agents
        cls.agent_id, cls.agent_token = hub.storage.v3.create_agent(
            "agent_phase2", "Agente Phase 2", default_role_id=cls.role_dev["id"]
        )

        # Setup rooms
        cls.room1 = hub.storage.v3.create_room("geral", topic="Sala Geral")
        cls.room2 = hub.storage.v3.create_room("dev", topic="Sala de Dev")
        cls.room_archived = hub.storage.v3.create_room("antiga", topic="Sala Antiga Arquivada")
        hub.storage.v3.archive_room(cls.room_archived["id"])

        # Grant room1 access to agent
        hub.storage.v3.grant_room_access(cls.room1["id"], cls.agent_id, role_id=cls.role_dev["id"], can_write=1)

        # Post a message in room1
        hub.storage.v3.add_message(
            room_id=cls.room1["id"],
            sender=cls.admin_human_id,
            content="Olá a todos!",
        )

        cls.app = create_app()
        cls.client = TestClient(cls.app)

    @classmethod
    def tearDownClass(cls):
        hub.storage = cls.orig_storage
        cls.test_storage.close()

    def setUp(self):
        self.admin_headers = {"Cookie": f"human_session={self.admin_token}"}
        self.user_headers = {"Cookie": f"human_session={self.user_token}"}

    # --- 1. System Diagnostics Endpoint (/api/admin/system) ---

    def test_01_system_endpoint_admin_success(self):
        """Admin can access /api/admin/system and receives all diagnostic fields."""
        resp = self.client.get("/api/admin/system", headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200, resp.text)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["version"], "v3.1")
        self.assertIn("commit", data)
        self.assertIn("db_path", data)
        self.assertIn("expected_db_path", data)
        self.assertIn("is_unexpected_db", data)
        self.assertEqual(data["schema_version"], 3)
        self.assertGreaterEqual(data["uptime_seconds"], 0)
        self.assertIn("started_at", data)
        self.assertIsInstance(data["connected_agents"], list)
        self.assertIsInstance(data["connected_agents_count"], int)
        self.assertIn("trust_proxy", data)

    def test_02_system_endpoint_forbidden_for_user(self):
        """Non-admin human cannot access /api/admin/system (returns 403)."""
        resp = self.client.get("/api/admin/system", headers=self.user_headers)
        self.assertEqual(resp.status_code, 403)

    def test_03_system_endpoint_unauthorized_without_session(self):
        """Unauthenticated request to /api/admin/system returns 401."""
        resp = self.client.get("/api/admin/system")
        self.assertEqual(resp.status_code, 401)

    # --- 2. Agent-Centric Rooms Endpoint (/api/admin/agents/{id}/rooms) ---

    def test_04_agent_rooms_view(self):
        """Admin can get all rooms for an agent, available rooms, and catalog roles."""
        resp = self.client.get(f"/api/admin/agents/{self.agent_id}/rooms", headers=self.admin_headers)
        self.assertEqual(resp.status_code, 200, resp.text)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("agent", data)
        self.assertEqual(data["agent"]["id"], self.agent_id)

        # Agent is in room1
        member_rooms = data["rooms"]
        self.assertTrue(any(r["id"] == self.room1["id"] for r in member_rooms))

        # room2 is available (not yet granted)
        available = data["available_rooms"]
        self.assertTrue(any(r["id"] == self.room2["id"] for r in available))
        self.assertFalse(any(r["id"] == self.room1["id"] for r in available))

        # Roles catalog is returned
        roles = data["roles"]
        self.assertTrue(len(roles) >= 2)

    def test_05_agent_rooms_not_found(self):
        """Requesting rooms for non-existent agent returns 404."""
        resp = self.client.get("/api/admin/agents/999999/rooms", headers=self.admin_headers)
        self.assertEqual(resp.status_code, 404)

    # --- 3. CLI Tests ---

    def test_06_cli_status(self):
        """CLI status command reports database details and counts."""
        res = subprocess.run(
            [sys.executable, "-m", "aichat.cli", "--db", str(self.db_path), "status"],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("ESTADO DO SISTEMA & BASE DE DADOS", res.stdout)
        self.assertIn("Versão do esquema:    v3", res.stdout)
        self.assertIn("Utilizadores Humanos:", res.stdout)
        self.assertIn("Agentes Registados:", res.stdout)
        self.assertIn("Salas:", res.stdout)
        self.assertIn("Mensagens Totais:", res.stdout)

    def test_07_cli_list_rooms(self):
        """CLI list-rooms command lists rooms with member and message counts."""
        res = subprocess.run(
            [sys.executable, "-m", "aichat.cli", "--db", str(self.db_path), "list-rooms", "-a"],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("geral", res.stdout)
        self.assertIn("dev", res.stdout)
        self.assertIn("antiga", res.stdout)
        self.assertIn("arquivada", res.stdout)

    def test_08_cli_reset_password(self):
        """CLI reset-password command resets human password, clears locks, and sets must-change."""
        # Reset user_joao's password
        new_pwd = "NovoPassword123!"
        res = subprocess.run(
            [
                sys.executable,
                "-m",
                "aichat.cli",
                "--db",
                str(self.db_path),
                "reset-password",
                "-u",
                "user_joao",
                "-p",
                new_pwd,
                "--must-change",
            ],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("Sucesso: Palavra-passe de 'user_joao' redefinida", res.stdout)

        # Verify password and must_change_password via authenticate_human
        user, err = hub.storage.v3.authenticate_human("user_joao", new_pwd)
        self.assertIsNone(err)
        self.assertIsNotNone(user)
        self.assertEqual(user["must_change_password"], 1)
        self.assertEqual(user["failed_logins"], 0)
        self.assertIsNone(user["locked_until"])

    def test_09_cli_refuses_non_existent_db(self):
        """CLI strictly refuses to operate on non-existent database file."""
        fake_db = Path(self.tmp) / "does_not_exist.db"
        res = subprocess.run(
            [sys.executable, "-m", "aichat.cli", "--db", str(fake_db), "status"],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("Erro: A base de dados não existe", res.stderr)

    # --- 4. run_server.py Guard Tests ---

    def test_10_run_server_refuses_testing_env(self):
        """run_server.py immediately refuses to start if AICHAT_TESTING=1 is active."""
        env = os.environ.copy()
        env["AICHAT_TESTING"] = "1"
        res = subprocess.run(
            [sys.executable, "run_server.py", "--no-browser"],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("AICHAT_TESTING=1 está ativa", res.stderr)

    def test_11_run_server_refuses_silent_db_creation(self):
        """run_server.py refuses to silently create a new DB if file does not exist without --init-db."""
        env = os.environ.copy()
        env.pop("AICHAT_TESTING", None)
        fake_db = Path(self.tmp) / "uncreated.db"
        res = subprocess.run(
            [sys.executable, "run_server.py", "--db", str(fake_db)],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("A base de dados não existe", res.stderr)
        self.assertIn("--init-db", res.stderr)

    # --- 5. UI Elements Presence in admin.html ---

    def test_12_admin_html_elements_present(self):
        """admin.html contains all requested Phase 2 UI elements and discard logic."""
        admin_path = BASE_DIR / "aichat" / "static" / "admin.html"
        html = admin_path.read_text(encoding="utf-8")

        # 1. Rooms search and hide archived toggle
        self.assertIn('id="rooms-search-input"', html)
        self.assertIn('id="rooms-hide-archived"', html)
        self.assertIn('id="rooms-count-badge"', html)

        # 2. Sistema tab & elements
        self.assertIn('id="tab-btn-system"', html)
        self.assertIn('id="tab-system"', html)
        self.assertIn('id="sys-unexpected-db-banner"', html)
        self.assertIn('id="sys-db-path"', html)
        self.assertIn('id="sys-schema-version"', html)
        self.assertIn('id="sys-uptime"', html)
        self.assertIn('id="sys-connected-agents-list"', html)

        # 3. Agent rooms modal (Vista por Agente)
        self.assertIn('id="modal-agent-rooms"', html)
        self.assertIn('id="ar-agent-name"', html)
        self.assertIn('id="ar-add-room-select"', html)
        self.assertIn('id="agent-rooms-table-body"', html)

        # 4. Token Snippets and secure discard
        self.assertIn('id="ts-tab-claude"', html)
        self.assertIn('id="ts-tab-cline"', html)
        self.assertIn('id="ts-tab-cli"', html)
        self.assertIn('closeTokenModal()', html)


if __name__ == "__main__":
    unittest.main()
