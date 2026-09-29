"""
Tests for migrate_v2_to_v3.py.

The v2 source database is produced by the real v2.8 storage layer (aichat.storage), so the
test tracks whatever schema the current code writes. Run from the repository root:

    python -m unittest migrations/v3/test_migrate_v2_to_v3.py -v
"""
import hashlib
import shutil
import sqlite3
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from aichat.storage import ChatStorage  # noqa: E402
import migrate_v2_to_v3 as mig  # noqa: E402

ROOM_CLEAR_PASSWORD = "PWD-XYZ-123-clear"


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TestMigrateV2ToV3(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.src_path = cls.tmp / "chat_v2.db"
        st = ChatStorage(db_path=cls.src_path, logs_dir=cls.tmp / "logs")
        cls.v2_tokens = {}

        st.create_room("geral", topic="sala aberta")
        st.create_room("controlo", password_hash="h", salt="s", is_protected=True, clear_password=ROOM_CLEAR_PASSWORD)

        for name, kwargs in [("Claude-Dev", {}), ("Codex", {}), ("Sentinel", {"is_system": True}),
                             ("Novato", {"status": "pending"})]:
            cls.v2_tokens[name] = st.register_agent_admin(callsign=name, **kwargs).get("token", "")
        st.add_or_update_member("geral", "Claude-Dev", "agent")
        st.add_or_update_member("controlo", "Claude-Dev", "agent")
        st.add_or_update_member("geral", "Codex", "agent")
        st.update_agent_status_admin("Codex", "inactive")

        cls.m_rui = st.add_message("geral", "Rui", "human", "olá equipa", is_verified=True)["id"]
        cls.m_human = st.add_message("geral", "Human", "human", "nome por defeito da UI")["id"]
        cls.m_dev = st.add_message("geral", "Claude-Dev", "agent", "feito", is_verified=True)["id"]
        cls.m_sys = st.add_message("geral", "System", "system", "sala criada")["id"]
        cls.m_spoof = st.add_message("geral", "Mallory", "HUMAN", "papel falsificado")["id"]
        cls.m_admin_agent = st.add_message("geral", "admin", "agent", "nome reservado com papel de agente")["id"]
        st.add_message("controlo", "Claude-Dev", "agent", "mensagem da sala protegida", is_verified=True)

        conn = sqlite3.connect(cls.src_path)
        now = datetime.now().isoformat()
        with conn:
            cls.m_orphan = conn.execute(
                "INSERT INTO messages (room_name, sender, role, content, created_at) VALUES ('fantasma', 'Ghost', 'agent', 'sala apagada', ?)",
                (now,)).lastrowid
            conn.execute("INSERT INTO reactions (message_id, room_name, sender, emoji, created_at) VALUES (9999, 'geral', 'Ghost', 'x', ?)", (now,))
            conn.execute("INSERT INTO human_sessions (session_hash, expires_at, created_at) VALUES ('abc', 1e12, 0)")
        conn.close()

        st.toggle_reaction(cls.m_rui, "geral", "Human", "👍")
        st.toggle_reaction(cls.m_rui, "geral", "Rui", "👍")      # same person after alias merge
        st.toggle_reaction(cls.m_dev, "geral", "Claude-Dev", "🚀")

        cls.poll_id = st.create_poll("geral", "Claude-Dev", "Avançar?", ["sim", "não"])["id"]
        st.cast_vote(cls.poll_id, "Human", 0)
        st.cast_vote(cls.poll_id, "Rui", 1)                       # later vote wins after merge
        st.cast_vote(cls.poll_id, "Claude-Dev", 0)

        cls.t1 = st.create_task("geral", "Implementar login", assignee="Claude-Dev", created_by="Rui", message_id=cls.m_dev)["id"]
        cls.t2 = st.create_task("geral", "Planear sprint", priority="urgent", start_at="2026-10-01",
                                due_at="2026-10-05T18:00:00", created_by="System")["id"]
        st.create_calendar_event("geral", "Treino GPU", start_at="2026-09-30T10:00:00", end_at="2026-09-30T11:00:00",
                                 resource="RTX_3080", target_agent="Claude-Dev", created_by="Rui", task_id=cls.t1)
        st.log_audit_event("controlo", "Claude-Dev", "join", "ok", "entrou")
        st.close()

        cls.src_sha = file_sha(cls.src_path)
        cls.out = cls.tmp / "out"
        cls.dst_path = cls.tmp / "chat_v3.db"
        cls.rc = mig.main(["--source", str(cls.src_path), "--target", str(cls.dst_path),
                           "--admin-username", "Rui", "--out-dir", str(cls.out)])
        cls.db = sqlite3.connect(cls.dst_path)
        cls.db.row_factory = sqlite3.Row
        cls.creds = next(cls.out.glob("credentials_*.txt")).read_text(encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def q(self, sql, *args):
        return self.db.execute(sql, args).fetchall()

    def pid(self, name):
        return self.q("SELECT id FROM principals WHERE name = ? COLLATE NOCASE", name)[0]["id"]

    # ---------------------------------------------------------- safety

    def test_success_and_source_untouched(self):
        self.assertEqual(self.rc, 0)
        self.assertEqual(file_sha(self.src_path), self.src_sha)
        self.assertTrue(list(self.out.glob("chat_v2_backup_*.db")))

    def test_refuses_existing_target(self):
        rc = mig.main(["--source", str(self.src_path), "--target", str(self.dst_path),
                       "--admin-username", "Rui", "--out-dir", str(self.tmp / "out2")])
        self.assertEqual(rc, 2)

    def test_integrity_and_foreign_keys(self):
        self.assertEqual(self.q("PRAGMA integrity_check")[0][0], "ok")
        self.assertEqual(self.q("PRAGMA foreign_key_check"), [])
        self.assertEqual(self.q("SELECT version FROM schema_version")[0][0], 3)

    def test_no_v2_secret_survives(self):
        blob = self.dst_path.read_bytes()
        for name, token in self.v2_tokens.items():
            if token:
                self.assertNotIn(token.encode(), blob, f"v2 token of {name} leaked into v3")
        self.assertNotIn(ROOM_CLEAR_PASSWORD.encode(), blob)
        self.assertEqual(self.q("SELECT COUNT(*) FROM human_sessions")[0][0], 0)

    # ---------------------------------------------------------- identities & credentials

    def test_admin_created_with_working_password(self):
        row = self.q("SELECT h.* FROM humans h JOIN principals p ON p.id = h.principal_id WHERE p.name = 'Rui'")[0]
        self.assertEqual(row["access_role"], "admin")
        self.assertEqual(row["must_change_password"], 1)
        password = [l for l in self.creds.splitlines() if l.startswith("Admin initial password:")][0].split()[3]
        self.assertTrue(mig.verify_password(password, row["password_hash"]))
        self.assertFalse(mig.verify_password(password + "x", row["password_hash"]))

    def test_agent_status_and_new_tokens(self):
        status = {r["name"]: (r["status"], r["is_system"]) for r in self.q("SELECT name, status, is_system FROM principals WHERE kind='agent' AND is_legacy=0")}
        self.assertEqual(status["Claude-Dev"], ("active", 0))
        self.assertEqual(status["Codex"], ("inactive", 0))
        self.assertEqual(status["Sentinel"], ("active", 1))
        self.assertEqual(status["Novato"], ("pending", 0))
        with_creds = {r[0] for r in self.q("SELECT p.name FROM credentials c JOIN principals p ON p.id = c.principal_id")}
        self.assertEqual(with_creds, {"Claude-Dev", "Sentinel"})
        token = [l.split()[1] for l in self.creds.splitlines() if l.strip().startswith("Claude-Dev")][0]
        self.assertEqual(self.q("SELECT principal_id FROM credentials WHERE token_hash = ?", mig.hash_token(token))[0][0], self.pid("Claude-Dev"))

    def test_legacy_names_become_inactive_principals(self):
        rows = {r["name"]: r for r in self.q("SELECT * FROM principals WHERE is_legacy = 1")}
        self.assertIn("Mallory", rows)
        self.assertIn("Ghost", rows)
        self.assertTrue(all(r["status"] == "inactive" for r in rows.values()))
        self.assertEqual(self.q("SELECT COUNT(*) FROM credentials c JOIN principals p ON p.id=c.principal_id WHERE p.is_legacy=1")[0][0], 0)

    # ---------------------------------------------------------- rooms & access

    def test_access_from_membership_only(self):
        grants = {(r["room"], r["agent"]) for r in self.q(
            "SELECT r.name room, p.name agent FROM room_access ra JOIN rooms r ON r.id=ra.room_id JOIN principals p ON p.id=ra.principal_id")}
        self.assertEqual(grants, {("geral", "Claude-Dev"), ("controlo", "Claude-Dev"), ("geral", "Codex")})

    def test_read_cursors_start_at_room_end(self):
        geral = self.q("SELECT id FROM rooms WHERE name='geral'")[0][0]
        cursor = self.q("SELECT last_message_id FROM read_cursors WHERE principal_id=? AND room_id=?", self.pid("Claude-Dev"), geral)[0][0]
        self.assertEqual(cursor, self.q("SELECT MAX(id) FROM messages WHERE room_id=?", geral)[0][0])

    def test_orphan_room_recreated_archived(self):
        row = self.q("SELECT r.name, r.is_archived FROM messages m JOIN rooms r ON r.id = m.room_id WHERE m.id = ?", self.m_orphan)[0]
        self.assertEqual((row["name"], row["is_archived"]), ("fantasma", 1))

    # ---------------------------------------------------------- messages

    def test_message_ids_and_attribution(self):
        m = {r["id"]: r for r in self.q("SELECT * FROM messages")}
        admin = self.pid("Rui")
        self.assertEqual((m[self.m_rui]["sender_kind"], m[self.m_rui]["sender_id"]), ("human", admin))
        self.assertEqual((m[self.m_human]["sender_kind"], m[self.m_human]["sender_id"]), ("human", admin))
        self.assertEqual(m[self.m_human]["sender_name"], "Human")   # display snapshot kept
        self.assertEqual((m[self.m_dev]["sender_id"], m[self.m_dev]["is_verified"]), (self.pid("Claude-Dev"), 1))
        self.assertEqual((m[self.m_sys]["sender_kind"], m[self.m_sys]["sender_id"]), ("system", None))
        # a forged 'HUMAN' role must never become a human message
        self.assertEqual((m[self.m_spoof]["sender_kind"], m[self.m_spoof]["sender_id"]), ("agent", self.pid("Mallory")))
        # an agent-role message under a reserved name must not be attributed to the admin
        self.assertEqual((m[self.m_admin_agent]["sender_kind"], m[self.m_admin_agent]["sender_id"]), ("agent", None))
        self.assertTrue(all(r["created_at"].endswith("Z") for r in m.values()))

    # ---------------------------------------------------------- reactions & polls

    def test_reactions_merged_and_orphans_dropped(self):
        on_rui = self.q("SELECT principal_id, emoji FROM reactions WHERE message_id=?", self.m_rui)
        self.assertEqual([tuple(r) for r in on_rui], [(self.pid("Rui"), "👍")])
        report = json_report(self.out)
        self.assertEqual(report["dropped"]["reactions_on_missing_message"], 1)
        self.assertEqual(report["dropped"]["reactions_duplicate_after_alias_merge"], 1)

    def test_poll_votes_merged_latest_wins(self):
        votes = {r["voter_id"]: r["option_index"] for r in self.q("SELECT * FROM poll_votes WHERE poll_id=?", self.poll_id)}
        self.assertEqual(votes, {self.pid("Rui"): 1, self.pid("Claude-Dev"): 0})

    # ---------------------------------------------------------- tasks & calendar

    def test_tasks_mapped(self):
        t = {r["id"]: r for r in self.q("SELECT * FROM tasks")}
        self.assertEqual(t[self.t1]["assignee_id"], self.pid("Claude-Dev"))
        self.assertEqual(t[self.t1]["created_by"], self.pid("Rui"))
        self.assertEqual(t[self.t1]["message_id"], self.m_dev)
        self.assertIsNone(t[self.t2]["created_by"])                  # 'System' -> NULL
        self.assertEqual(t[self.t2]["priority"], "urgent")
        self.assertEqual(t[self.t2]["start_at"], "2026-10-01")      # date-only kept
        self.assertEqual(t[self.t2]["due_at"], "2026-10-05T17:00:00Z")  # Lisbon WEST (UTC+1) -> UTC

    def test_calendar_mapped(self):
        ev = self.q("SELECT * FROM calendar_events WHERE title = 'Treino GPU'")[0]
        self.assertEqual(ev["target_id"], self.pid("Claude-Dev"))
        self.assertEqual(ev["task_id"], self.t1)
        self.assertEqual(ev["start_at"], "2026-09-30T09:00:00Z")
        self.assertEqual(ev["resource"], "RTX_3080")

    def test_audit_migrated(self):
        actions = [r["action"] for r in self.q("SELECT action FROM audit_log ORDER BY id")]
        self.assertIn("join", actions)
        self.assertEqual(actions[-1], "migration_v2_to_v3")

    # ---------------------------------------------------------- options

    def test_grant_public_rooms_option(self):
        target = self.tmp / "chat_v3_public.db"
        rc = mig.main(["--source", str(self.src_path), "--target", str(target), "--admin-username", "Rui",
                       "--out-dir", str(self.tmp / "out3"), "--grant-public-rooms"])
        self.assertEqual(rc, 0)
        db = sqlite3.connect(target)
        grants = {r for r in db.execute(
            "SELECT r.name, p.name FROM room_access ra JOIN rooms r ON r.id=ra.room_id JOIN principals p ON p.id=ra.principal_id")}
        db.close()
        self.assertIn(("geral", "Novato"), grants)
        self.assertIn(("geral", "Sentinel"), grants)
        self.assertNotIn(("controlo", "Novato"), grants)             # protected rooms are never widened


def json_report(out_dir: Path) -> dict:
    import json
    return json.loads(next(out_dir.glob("migration_report_*.json")).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
