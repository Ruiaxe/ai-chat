import contextlib
import io
import shutil
import tempfile
import unittest
from pathlib import Path

from aichat.storage import ChatStorage
from migrations.v3 import migrate_v2_to_v3 as mig


class TestV3IntegrationRegression(unittest.TestCase):
    """
    Regression test suite verifying Phase 1 data layer integration
    derived from the reviewer's v3_integration.py scratchpad script.
    """

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.v2_db = self.tmp / "chat.db"
        self.migrated_db = self.tmp / "migrated.db"
        self.logs_dir = self.tmp / "logs"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_migration_and_storage_delegation_flow(self):
        # 1. Create a real v2 database
        v2 = ChatStorage(db_path=self.v2_db, logs_dir=self.logs_dir)
        v2.create_room("geral")
        v2.add_message("geral", "Rui", "human", "olá")
        v2.close()

        # 2. Run non-destructive migration
        with contextlib.redirect_stdout(io.StringIO()):
            mig.main([
                "--source", str(self.v2_db),
                "--target", str(self.migrated_db),
                "--admin-username", "Rui",
                "--out-dir", str(self.tmp / "out"),
            ])

        # 3. Open migrated database with ChatStorage
        st = ChatStorage(db_path=self.migrated_db, logs_dir=self.logs_dir)
        self.assertTrue(st.is_v3())

        # 4. Verify list_rooms()
        rooms = st.list_rooms()
        self.assertGreaterEqual(len(rooms), 1)
        self.assertEqual(rooms[0]["name"], "geral")

        # 5. Verify get_room('geral')
        room = st.get_room("geral")
        self.assertIsNotNone(room)
        self.assertEqual(room["name"], "geral")

        # 6. Verify get_messages('geral')
        messages = st.get_messages("geral")
        self.assertGreaterEqual(len(messages), 1)
        self.assertEqual(messages[0]["content"], "olá")

        # 7. Verify add_message(...)
        new_msg = st.add_message("geral", "Rui", "human", "teste")
        self.assertIsNotNone(new_msg)
        self.assertGreater(new_msg["id"], messages[0]["id"])
        self.assertEqual(new_msg["content"], "teste")

        # 8. Verify list_rooms_for_principal(admin)
        admin = st.get_principal_by_name("Rui")
        self.assertIsNotNone(admin)
        admin_rooms = [r["name"] for r in st.list_rooms_for_principal(admin)]
        self.assertIn("geral", admin_rooms)
        st.close()

    def test_v2_db_named_v3_does_not_trigger_v3_mode(self):
        # A v2 database whose name happens to contain 'v3' should not be detected as v3
        v2 = ChatStorage(db_path=self.v2_db, logs_dir=self.logs_dir)
        v2.create_room("geral")
        v2.close()

        v3_named_copy = self.tmp / "chat_v3_copy.db"
        shutil.copy(self.v2_db, v3_named_copy)

        opened_st = ChatStorage(db_path=v3_named_copy, logs_dir=self.logs_dir)
        self.assertFalse(opened_st.is_v3())
        rooms = opened_st.list_rooms()
        self.assertEqual(len(rooms), 1)
        self.assertEqual(rooms[0]["name"], "geral")
        opened_st.close()
