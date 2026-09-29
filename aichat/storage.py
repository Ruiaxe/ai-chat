import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from aichat.config import DATA_DIR, LOGS_DIR

DB_PATH = DATA_DIR / os.environ.get("AICHAT_DB_NAME", "chat.db")


def check_schema_version(db_path: Path) -> int | None:
    """Returns the schema version from database, or None if no schema_version table exists."""
    path = Path(db_path)
    if not path.exists() or path.stat().st_size == 0:
        return None
    conn = None
    try:
        conn = sqlite3.connect(path)
        cur = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version';")
        if not cur.fetchone():
            return None
        cur = conn.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1;")
        row = cur.fetchone()
        return int(row[0]) if row else None
    except Exception:
        return None
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def get_storage(db_path: Path = DB_PATH, logs_dir: Path = LOGS_DIR) -> Any:
    """
    Returns StorageV3 for v3 databases or empty/new databases.
    Fails fast if the database has tables but is not on schema_version=3.
    """
    path = Path(db_path)
    if path.exists() and path.stat().st_size > 0:
        v = check_schema_version(path)
        if v == 3:
            from aichat.storage_v3 import StorageV3
            return StorageV3(path, logs_dir)
        # Check if it has any tables
        conn = None
        try:
            conn = sqlite3.connect(path)
            tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence';").fetchall()
            if tables:
                raise RuntimeError(
                    f"Base de dados incompatível em '{path}': esperada schema_version=3. "
                    "Execute primeiro a migração: python migrations/v3/migrate_v2_to_v3.py"
                )
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    from aichat.storage_v3 import StorageV3
    return StorageV3(path, logs_dir)


class ChatStorage:
    """Manages SQLite storage and file-based transcripts for chat rooms (supports v2 and v3 schemas)."""

    _local = threading.local()

    def __init__(self, db_path: Path = DB_PATH, logs_dir: Path = LOGS_DIR, schema_version: int | None = None):
        self.db_path = Path(db_path)
        self.logs_dir = Path(logs_dir)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self._v3_storage: Any = None
        self._init_db(schema_version=schema_version)

    def is_v3(self) -> bool:
        """Returns True if the current database uses the v3 schema."""
        if self._v3_storage is not None:
            return True
        conn = self._get_connection()
        row = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version';").fetchone()
        return row is not None

    @property
    def v3(self) -> Any:
        """Returns the underlying StorageV3 instance for v3 operations."""
        if self._v3_storage is None:
            from aichat.storage_v3 import StorageV3
            self._v3_storage = StorageV3(self.db_path, self.logs_dir)
        return self._v3_storage

    @v3.setter
    def v3(self, val: Any) -> None:
        self._v3_storage = val

    # -------------------------------------------------------------- v3 delegation methods
    def create_principal(self, *args, **kwargs):
        return self.v3.create_principal(*args, **kwargs)

    def get_principal_by_id(self, *args, **kwargs):
        return self.v3.get_principal_by_id(*args, **kwargs)

    def get_principal_by_name(self, *args, **kwargs):
        return self.v3.get_principal_by_name(*args, **kwargs)

    def list_principals(self, *args, **kwargs):
        return self.v3.list_principals(*args, **kwargs)

    def update_principal_status(self, *args, **kwargs):
        return self.v3.update_principal_status(*args, **kwargs)

    def create_human(self, *args, **kwargs):
        return self.v3.create_human(*args, **kwargs)

    def authenticate_human(self, *args, **kwargs):
        return self.v3.authenticate_human(*args, **kwargs)

    def change_human_password(self, *args, **kwargs):
        return self.v3.change_human_password(*args, **kwargs)

    def create_human_session(self, *args, **kwargs):
        return self.v3.create_human_session(*args, **kwargs)

    def authenticate_human_session(self, *args, **kwargs):
        return self.v3.authenticate_human_session(*args, **kwargs)

    def revoke_human_session(self, *args, **kwargs):
        return self.v3.revoke_human_session(*args, **kwargs)

    def create_agent(self, *args, **kwargs):
        return self.v3.create_agent(*args, **kwargs)

    def authenticate_agent_token(self, *args, **kwargs):
        return self.v3.authenticate_agent_token(*args, **kwargs)

    def rotate_agent_token(self, *args, **kwargs):
        return self.v3.rotate_agent_token(*args, **kwargs)

    def revoke_credential_by_hint(self, *args, **kwargs):
        return self.v3.revoke_credential_by_hint(*args, **kwargs)

    def list_agent_credentials(self, *args, **kwargs):
        return self.v3.list_agent_credentials(*args, **kwargs)

    def get_role_by_id(self, *args, **kwargs):
        return self.v3.get_role_by_id(*args, **kwargs)

    def get_role_by_key(self, *args, **kwargs):
        return self.v3.get_role_by_key(*args, **kwargs)

    def list_roles(self, *args, **kwargs):
        return self.v3.list_roles(*args, **kwargs)

    def update_role_reminder(self, *args, **kwargs):
        return self.v3.update_role_reminder(*args, **kwargs)

    def grant_room_access(self, *args, **kwargs):
        return self.v3.grant_room_access(*args, **kwargs)

    def revoke_room_access(self, *args, **kwargs):
        return self.v3.revoke_room_access(*args, **kwargs)

    def get_room_access(self, *args, **kwargs):
        return self.v3.get_room_access(*args, **kwargs)

    def list_room_members(self, *args, **kwargs):
        return self.v3.list_room_members(*args, **kwargs)

    def list_rooms_for_principal(self, *args, **kwargs):
        return self.v3.list_rooms_for_principal(*args, **kwargs)

    def authorize(self, *args, **kwargs):
        return self.v3.authorize(*args, **kwargs)

    def get_read_cursor(self, *args, **kwargs):
        return self.v3.get_read_cursor(*args, **kwargs)

    def has_read_cursor(self, *args, **kwargs):
        return self.v3.has_read_cursor(*args, **kwargs)

    def update_read_cursor(self, *args, **kwargs):
        return self.v3.update_read_cursor(*args, **kwargs)

    def _get_connection(self) -> sqlite3.Connection:
        """Returns a thread-local SQLite connection with row_factory enabled."""
        if not hasattr(self._local, "conns"):
            self._local.conns = {}
        path_key = str(self.db_path.resolve())
        if path_key not in self._local.conns:
            conn = sqlite3.connect(
                self.db_path,
                timeout=30.0,
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA foreign_keys = ON;")
            self._local.conns[path_key] = conn
        return self._local.conns[path_key]

    def close(self) -> None:
        """Closes the connection for this database path on current thread."""
        if hasattr(self._local, "conns"):
            path_key = str(self.db_path.resolve())
            conn = self._local.conns.pop(path_key, None)
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def _init_db(self, schema_version: int | None = None) -> None:
        """Initializes database schema with tables and indexes."""
        # Explicit or detected v3 via schema_version
        if schema_version == 3:
            from aichat.storage_v3 import StorageV3
            self._v3_storage = StorageV3(self.db_path, self.logs_dir)
            return

        conn = self._get_connection()
        has_v3 = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version';").fetchone()
        if has_v3:
            from aichat.storage_v3 import StorageV3
            self._v3_storage = StorageV3(self.db_path, self.logs_dir)
            return

        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rooms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL COLLATE NOCASE,
                    topic TEXT DEFAULT '',
                    password_hash TEXT DEFAULT '',
                    salt TEXT DEFAULT '',
                    is_protected INTEGER DEFAULT 0,
                    clear_password TEXT DEFAULT '',
                    created_at TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    room_name TEXT NOT NULL COLLATE NOCASE,
                    sender TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS members (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    room_name TEXT NOT NULL COLLATE NOCASE,
                    member_name TEXT NOT NULL COLLATE NOCASE,
                    role TEXT NOT NULL,
                    token TEXT DEFAULT '',
                    joined_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    UNIQUE(room_name, member_name)
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_messages_room_id 
                ON messages(room_name, id);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_members_room 
                ON members(room_name);
            """)

            # Reactions table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id INTEGER NOT NULL,
                    room_name TEXT NOT NULL COLLATE NOCASE,
                    sender TEXT NOT NULL,
                    emoji TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(message_id, sender, emoji)
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_reactions_msg 
                ON reactions(message_id);
            """)

            # Persistent Member Identities table for global anti-impersonation
            conn.execute("""
                CREATE TABLE IF NOT EXISTS member_identities (
                    member_name TEXT PRIMARY KEY COLLATE NOCASE,
                    token TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'agent',
                    created_at TEXT NOT NULL
                );
            """)

            # Polls table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS polls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    room_name TEXT NOT NULL COLLATE NOCASE,
                    creator TEXT NOT NULL,
                    question TEXT NOT NULL,
                    options TEXT NOT NULL,
                    is_closed INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    closed_at TEXT DEFAULT ''
                );
            """)
            # Poll votes table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS poll_votes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    poll_id INTEGER NOT NULL,
                    voter TEXT NOT NULL,
                    option_index INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(poll_id, voter)
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_poll_votes_poll 
                ON poll_votes(poll_id);
            """)

            # Tasks table (v2.5)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    room_name TEXT NOT NULL COLLATE NOCASE,
                    title TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'planned',
                    assignee TEXT DEFAULT '',
                    waiting_for_agent TEXT DEFAULT '',
                    priority TEXT NOT NULL DEFAULT 'medium',
                    order_index INTEGER NOT NULL DEFAULT 0,
                    message_id INTEGER,
                    uses_gpu INTEGER NOT NULL DEFAULT 0,
                    gpu_est_min INTEGER NOT NULL DEFAULT 0,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_tasks_room_status 
                ON tasks(room_name, status);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_tasks_room_order 
                ON tasks(room_name, order_index);
            """)

            # Task History table (v2.5)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS task_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    from_status TEXT DEFAULT '',
                    to_status TEXT DEFAULT '',
                    details TEXT DEFAULT '',
                    created_at TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_task_history_task 
                ON task_history(task_id);
            """)

            # Room Audit Log table (v2.6)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS room_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    room_name TEXT NOT NULL COLLATE NOCASE,
                    member_name TEXT NOT NULL COLLATE NOCASE,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    details TEXT DEFAULT '',
                    created_at TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_room 
                ON room_audit_log(room_name, created_at);
            """)

            # Human Sessions table (v2.7)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS human_sessions (
                    session_hash TEXT PRIMARY KEY,
                    expires_at REAL NOT NULL,
                    created_at REAL NOT NULL
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_expires 
                ON human_sessions(expires_at);
            """)
            try:
                conn.execute("DELETE FROM human_sessions WHERE expires_at <= ?;", (time.time(),))
            except Exception:
                pass

            # Calendar Events table (v2.8)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS calendar_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    room_name TEXT NOT NULL COLLATE NOCASE,
                    title TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    start_at TEXT NOT NULL,
                    end_at TEXT DEFAULT '',
                    event_type TEXT NOT NULL DEFAULT 'event',
                    task_id INTEGER,
                    resource TEXT DEFAULT '',
                    target_agent TEXT DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'scheduled',
                    wake_on_start INTEGER DEFAULT 1,
                    wake_on_end INTEGER DEFAULT 0,
                    notified_start INTEGER DEFAULT 0,
                    notified_end INTEGER DEFAULT 0,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES tasks(id) ON DELETE SET NULL
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_calendar_room_start 
                ON calendar_events(room_name, start_at);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_calendar_resource 
                ON calendar_events(resource, start_at, end_at);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_calendar_status 
                ON calendar_events(status, notified_start, start_at);
            """)

            # Auto-migrations for new features
            try:
                conn.execute("ALTER TABLE messages ADD COLUMN is_verified INTEGER DEFAULT 0;")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE members ADD COLUMN token TEXT DEFAULT '';")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE rooms ADD COLUMN is_archived INTEGER DEFAULT 0;")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE messages ADD COLUMN message_type TEXT DEFAULT 'text';")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE messages ADD COLUMN metadata TEXT DEFAULT '{}';")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE tasks ADD COLUMN waiting_for_agent TEXT DEFAULT '';")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE tasks ADD COLUMN uses_gpu INTEGER DEFAULT 0;")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE tasks ADD COLUMN gpu_est_min INTEGER DEFAULT 0;")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE tasks ADD COLUMN start_at TEXT DEFAULT '';")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE tasks ADD COLUMN due_at TEXT DEFAULT '';")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE tasks ADD COLUMN resource TEXT DEFAULT '';")
            except sqlite3.OperationalError:
                pass

            # Backfill existing member tokens into member_identities
            try:
                conn.execute("""
                    INSERT OR IGNORE INTO member_identities (member_name, token, role, created_at)
                    SELECT member_name, token, role, joined_at FROM members WHERE token != '';
                """)
            except sqlite3.OperationalError:
                pass

            # Schema upgrades for v2.7: Closed Registry and Status
            try:
                conn.execute("ALTER TABLE member_identities ADD COLUMN status TEXT NOT NULL DEFAULT 'active';")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE member_identities ADD COLUMN is_system INTEGER NOT NULL DEFAULT 0;")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_member_identities_token ON member_identities(token);")
            except sqlite3.OperationalError:
                pass

            # Mark system identities
            try:
                conn.execute("UPDATE member_identities SET is_system = 1 WHERE member_name IN ('Antigravity-Hub', 'SentinelSupport');")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE rooms ADD COLUMN clear_password TEXT DEFAULT '';")
            except sqlite3.OperationalError:
                pass
            # Purge stale/rotated tokens from members table and synchronize with member_identities
            try:
                conn.execute("""
                    UPDATE members 
                    SET token = '' 
                    WHERE member_name IN (SELECT member_name FROM member_identities WHERE status = 'inactive');
                """)
                conn.execute("""
                    UPDATE members
                    SET token = (
                        SELECT mi.token FROM member_identities mi
                        WHERE mi.member_name = members.member_name COLLATE NOCASE AND mi.status = 'active'
                    )
                    WHERE EXISTS (
                        SELECT 1 FROM member_identities mi
                        WHERE mi.member_name = members.member_name COLLATE NOCASE AND mi.status = 'active'
                    );
                """)
                conn.execute("""
                    UPDATE members
                    SET token = ''
                    WHERE token != '' AND token NOT IN (SELECT token FROM member_identities WHERE status = 'active');
                """)
            except sqlite3.OperationalError:
                pass

    def create_room(
        self,
        name: str,
        topic: str = "",
        password_hash: str = "",
        salt: str = "",
        is_protected: bool = False,
        clear_password: str = "",
    ) -> dict[str, Any]:
        """Creates a new room in SQLite and prepares its log files."""
        if self.is_v3():
            return self.v3.create_room(name=name, topic=topic)
        now = datetime.now().isoformat()
        conn = self._get_connection()
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO rooms (name, topic, password_hash, salt, is_protected, clear_password, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (name, topic, password_hash, salt, 1 if is_protected else 0, clear_password if is_protected else "", now),
            )
            room_id = cursor.lastrowid

        # Initialize text log file header if it doesn't exist
        log_file = self.get_room_log_file(name)
        if not log_file.exists():
            with open(log_file, "w", encoding="utf-8") as f:
                f.write(f"=== Chat Room: {name} ===\n")
                f.write(f"Created: {now}\n")
                if topic:
                    f.write(f"Topic: {topic}\n")
                f.write(f"Password Protected: {'Yes' if is_protected else 'No'}\n")
                f.write("=" * 60 + "\n\n")

        return {
            "id": room_id,
            "name": name,
            "topic": topic,
            "is_protected": is_protected,
            "is_archived": False,
            "created_at": now,
        }

    def get_room(self, name: str, include_password: bool = False) -> dict[str, Any] | None:
        """Fetches room information by name."""
        if self.is_v3():
            return self.v3.get_room(name)
        conn = self._get_connection()
        cursor = conn.execute(
            """
            SELECT id, name, topic, password_hash, salt, is_protected, clear_password, COALESCE(is_archived, 0) as is_archived, created_at
            FROM rooms WHERE name = ? COLLATE NOCASE
            """,
            (name,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        res = dict(row)
        res["is_archived"] = bool(res.get("is_archived", 0))
        if include_password:
            res["password"] = res.get("clear_password", "")
        else:
            res.pop("clear_password", None)
        return res

    def update_room_password(
        self,
        room_name: str,
        password_hash: str,
        salt: str,
        is_protected: bool = True,
        clear_password: str = "",
    ) -> None:
        """Updates room password hash, salt, and clear_password for supervisor access."""
        conn = self._get_connection()
        with conn:
            conn.execute(
                """
                UPDATE rooms 
                SET password_hash = ?, salt = ?, is_protected = ?, clear_password = ?
                WHERE name = ? COLLATE NOCASE
                """,
                (password_hash, salt, 1 if is_protected else 0, clear_password if is_protected else "", room_name.strip()),
            )

    def list_rooms(self, include_archived: bool = True, include_passwords: bool = False) -> list[dict[str, Any]]:
        """Lists all rooms with member count, message count, and archived status."""
        if self.is_v3():
            return self.v3.list_rooms(include_archived=include_archived)
        conn = self._get_connection()
        pwd_col = ", r.clear_password as password" if include_passwords else ""
        query = f"""
            SELECT 
                r.id,
                r.name,
                r.topic,
                r.is_protected,
                COALESCE(r.is_archived, 0) as is_archived,
                r.created_at{pwd_col},
                (SELECT COUNT(*) FROM messages m WHERE m.room_name = r.name) as message_count,
                (SELECT COUNT(*) FROM members mb WHERE mb.room_name = r.name) as member_count
            FROM rooms r
        """
        if not include_archived:
            query += " WHERE COALESCE(r.is_archived, 0) = 0"
        query += " ORDER BY r.id ASC"
        cursor = conn.execute(query)
        result = []
        for row in cursor.fetchall():
            d = dict(row)
            d["is_archived"] = bool(d.get("is_archived", 0))
            result.append(d)
        return result

    def archive_room(self, name: str) -> bool:
        """Marks a room as archived (read-only)."""
        if self.is_v3():
            return self.v3.archive_room(name)
        conn = self._get_connection()
        with conn:
            cursor = conn.execute("UPDATE rooms SET is_archived = 1 WHERE name = ? COLLATE NOCASE", (name.strip(),))
            return cursor.rowcount > 0

    def unarchive_room(self, name: str) -> bool:
        """Restores an archived room to active state."""
        if self.is_v3():
            return self.v3.unarchive_room(name)
        conn = self._get_connection()
        with conn:
            cursor = conn.execute("UPDATE rooms SET is_archived = 0 WHERE name = ? COLLATE NOCASE", (name.strip(),))
            return cursor.rowcount > 0

    def add_or_update_member(
        self,
        room_name: str,
        member_name: str,
        role: str,
        token: str | None = None,
        generate_token: bool = False,
    ) -> str:
        """Registers or refreshes a member in the room, assigning or preserving their authentication token."""
        import secrets
        now = datetime.now().isoformat()
        conn = self._get_connection()
        clean_room = room_name.strip()
        clean_member = member_name.strip()
        clean_role = (role or "agent").strip().lower()

        # 1. Check existing member token in this room
        cursor = conn.execute(
            "SELECT token FROM members WHERE room_name = ? COLLATE NOCASE AND member_name = ? COLLATE NOCASE",
            (clean_room, clean_member),
        )
        m_row = cursor.fetchone()
        existing_token = m_row[0] if m_row and m_row[0] else ""

        # 2. Check global member identity in member_identities table
        id_cur = conn.execute(
            "SELECT token, status FROM member_identities WHERE member_name = ? COLLATE NOCASE",
            (clean_member,),
        )
        id_row = id_cur.fetchone()

        clean_token = (token or "").strip()

        # If agent is deactivated globally, block joining any room
        if id_row and id_row["status"] == "inactive":
            raise PermissionError(f"Acesso negado: O agente '{clean_member}' está desativado pelo supervisor (status='inactive').")

        if existing_token:
            if clean_token:
                if not secrets.compare_digest(clean_token, existing_token):
                    raise PermissionError(f"Acesso negado: O membro '{clean_member}' já está registado com outro token.")
                final_token = existing_token
            else:
                # Member exists in this room with a token, but caller provided NO token!
                # Do NOT return the token! Block token theft (C4).
                if generate_token:
                    raise PermissionError(f"Acesso negado: O membro '{clean_member}' já está registado nesta sala. É obrigatório fornecer o respetivo member_token.")
                final_token = ""
        elif id_row:
            # Member exists globally in member_identities
            if clean_token and not secrets.compare_digest(clean_token, id_row["token"]):
                raise PermissionError(f"Acesso negado: O membro '{clean_member}' já está registado com outro token.")
            final_token = id_row["token"]
        elif clean_token:
            final_token = clean_token
            with conn:
                conn.execute(
                    "INSERT OR IGNORE INTO member_identities (member_name, token, role, status, is_system, created_at) VALUES (?, ?, ?, 'active', 0, ?)",
                    (clean_member, final_token, clean_role, now),
                )
        elif clean_role == "agent" and generate_token:
            final_token = secrets.token_hex(16)
            with conn:
                conn.execute(
                    "INSERT OR IGNORE INTO member_identities (member_name, token, role, status, is_system, created_at) VALUES (?, ?, ?, 'active', 0, ?)",
                    (clean_member, final_token, clean_role, now),
                )
        else:
            final_token = ""

        with conn:
            conn.execute(
                """
                INSERT INTO members (room_name, member_name, role, token, joined_at, last_seen_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(room_name, member_name) DO UPDATE SET
                    role = excluded.role,
                    token = CASE WHEN excluded.token != '' THEN excluded.token ELSE members.token END,
                    last_seen_at = excluded.last_seen_at
                """,
                (clean_room, clean_member, clean_role, final_token, now, now),
            )
        return final_token

    def verify_member_token(self, room_name: str, member_name: str, token: str) -> tuple[bool, str]:
        """
        Validates the member's authentication token.
        Enforces closed registry and callsign uniqueness:
        Unregistered senders cannot send messages.
        Returns (is_valid, error_msg).
        """
        import secrets
        conn = self._get_connection()
        clean_room = room_name.strip()
        clean_member = member_name.strip()

        # Check global identity token
        cursor = conn.execute(
            "SELECT token, status FROM member_identities WHERE member_name = ? COLLATE NOCASE",
            (clean_member,),
        )
        id_row = cursor.fetchone()
        if not id_row:
            # Check room-specific token fallback for test rooms or backward compatibility
            cursor = conn.execute(
                "SELECT token FROM members WHERE room_name = ? COLLATE NOCASE AND member_name = ? COLLATE NOCASE",
                (clean_room, clean_member),
            )
            r_row = cursor.fetchone()
            if not r_row or not r_row[0]:
                return False, f"Acesso negado: Remetente '{clean_member}' não está registado no servidor. Registo fechado, duplicados não são permitidos."
            global_token = r_row[0]
            status = "active"
        else:
            global_token = id_row["token"] if isinstance(id_row, sqlite3.Row) else id_row[0]
            status = (id_row["status"] if isinstance(id_row, sqlite3.Row) else (id_row[1] if len(id_row) > 1 else "active")) or "active"

        if status != "active":
            return False, f"Acesso negado: O registo do agente '{clean_member}' está desativado pelo supervisor (status='{status}')."

        clean_token = (token or "").strip()
        if clean_token and secrets.compare_digest(clean_token, global_token):
            return True, ""
        return False, f"Impersonation blocked: Remetente '{clean_member}' é uma identidade protegida. Token fornecido é inválido ou está em falta."

    def get_member_rooms(self, member_name: str) -> list[str]:
        """Returns the list of room names a member has joined."""
        if self.is_v3():
            p = self.v3.get_principal_by_name(member_name)
            if not p:
                return []
            rooms = self.v3.list_rooms_for_principal(p)
            return [r["name"] for r in rooms]
        conn = self._get_connection()
        cursor = conn.execute(
            """
            SELECT DISTINCT room_name FROM members 
            WHERE member_name = ? COLLATE NOCASE
            ORDER BY room_name ASC
            """,
            (member_name.strip(),),
        )
        return [row[0] for row in cursor.fetchall()]

    def remove_member(self, room_name: str, member_name: str) -> None:
        """Removes a member from the room."""
        conn = self._get_connection()
        with conn:
            conn.execute(
                "DELETE FROM members WHERE room_name = ? AND member_name = ?",
                (room_name, member_name),
            )

    def rotate_member_token(self, room_name: str, member_name: str) -> str:
        """Generates a new secure token for a member, updating members and member_identities across all rooms."""
        import secrets
        conn = self._get_connection()
        clean_member = member_name.strip()
        new_token = secrets.token_hex(16)
        now = datetime.now().isoformat()

        with conn:
            cursor = conn.execute(
                """
                UPDATE members
                SET token = ?, last_seen_at = ?
                WHERE member_name = ? COLLATE NOCASE
                """,
                (new_token, now, clean_member),
            )
            id_cur = conn.execute(
                "SELECT member_name FROM member_identities WHERE member_name = ? COLLATE NOCASE",
                (clean_member,),
            )
            if cursor.rowcount == 0 and not id_cur.fetchone():
                raise ValueError(f"Membro '{clean_member}' não está registado no servidor.")

            conn.execute(
                """
                UPDATE member_identities
                SET token = ?
                WHERE member_name = ? COLLATE NOCASE
                """,
                (new_token, clean_member),
            )
        return new_token

    def get_agent_identity_by_token(self, token: str, include_inactive: bool = False) -> dict[str, Any] | None:
        """Finds an active registered agent by their secret access token."""
        clean_token = (token or "").strip()
        if not clean_token:
            return None
        if self.is_v3():
            p, err = self.v3.authenticate_agent_token(clean_token)
            if not p:
                return None
            if not include_inactive and p.get("status") != "active":
                return None
            return {
                "callsign": p["name"],
                "token": clean_token,
                "role": p.get("default_role_key") or "agent",
                "status": p.get("status", "active"),
                "is_system": bool(p.get("is_system")),
                "created_at": p.get("created_at", ""),
            }
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT member_name, token, role, status, is_system, created_at FROM member_identities WHERE token = ?",
            (clean_token,),
        )
        row = cursor.fetchone()
        if row:
            if not include_inactive and row["status"] != "active":
                return None
            return {
                "callsign": row["member_name"],
                "token": row["token"],
                "role": row["role"],
                "status": row["status"],
                "is_system": bool(row["is_system"]),
                "created_at": row["created_at"],
            }
        return None

    def get_agent_identity_by_name(self, name: str) -> dict[str, Any] | None:
        """Finds a registered agent by their callsign (case-insensitive)."""
        clean_name = (name or "").strip()
        if not clean_name:
            return None
        if self.is_v3():
            p = self.v3.get_principal_by_name(clean_name)
            if not p or p.get("kind") != "agent":
                return None
            return {
                "callsign": p["name"],
                "token": "",
                "role": p.get("default_role_key") or "agent",
                "status": p.get("status", "active"),
                "is_system": bool(p.get("is_system")),
                "created_at": p.get("created_at", ""),
            }
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT member_name, token, role, status, is_system, created_at FROM member_identities WHERE member_name = ? COLLATE NOCASE",
            (clean_name,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "callsign": row["member_name"],
            "token": row["token"],
            "role": row["role"],
            "status": row["status"],
            "is_system": bool(row["is_system"]),
            "created_at": row["created_at"],
        }

    def list_registered_agents(self, include_tokens: bool = False) -> list[dict[str, Any]]:
        """Lists all registered agents in the closed registry."""
        if self.is_v3():
            principals = self.v3.list_principals(kind="agent")
            agents = []
            for p in principals:
                item = {
                    "callsign": p["name"],
                    "role": p.get("default_role_key") or "agent",
                    "status": p.get("status", "active"),
                    "is_system": bool(p.get("is_system")),
                    "created_at": p.get("created_at", ""),
                }
                if include_tokens:
                    item["token"] = ""
                else:
                    creds = self.v3.list_agent_credentials(p["id"])
                    hint = creds[0]["token_hint"] if creds else ""
                    item["token_hint"] = f"...{hint}" if hint else ""
                agents.append(item)
            return agents
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT member_name, token, role, status, is_system, created_at FROM member_identities ORDER BY is_system DESC, member_name ASC"
        )
        agents = []
        for row in cursor.fetchall():
            item = {
                "callsign": row["member_name"],
                "role": row["role"],
                "status": row["status"],
                "is_system": bool(row["is_system"]),
                "created_at": row["created_at"],
            }
            if include_tokens:
                item["token"] = row["token"]
            else:
                item["token_hint"] = (row["token"][:6] + "...") if row["token"] else ""
            agents.append(item)
        return agents

    def register_agent_admin(
        self,
        callsign: str,
        token: str | None = None,
        role: str = "agent",
        is_system: bool = False,
        status: str = "active",
        is_self_registration: bool = False,
    ) -> dict[str, Any]:
        """Provisions or activates a unique agent in the closed registry. Fails on duplicate callsigns."""
        import secrets
        clean_callsign = (callsign or "").strip()
        if not clean_callsign:
            raise ValueError("Callsign do agente não pode estar vazio.")
        if len(clean_callsign) > 40:
            raise ValueError("Callsign do agente não pode exceder 40 caracteres.")

        if self.is_v3():
            existing = self.v3.get_principal_by_name(clean_callsign)
            if existing:
                if existing["status"] == "inactive":
                    raise PermissionError(f"Acesso negado: O agente '{clean_callsign}' está desativado pelo supervisor. Apenas um administrador pode reativar.")
                raise ValueError(f"Callsign '{clean_callsign}' já está em uso no servidor. Duplicados não são permitidos.")
            role_id = None
            if role:
                r_obj = self.v3.get_role_by_key(role)
                if r_obj:
                    role_id = r_obj["id"]
            agent_obj, raw_token = self.v3.create_agent(
                name=clean_callsign,
                default_role_id=role_id,
                is_system=1 if is_system else 0,
                token=token,
            )
            return {
                "callsign": agent_obj["name"],
                "token": raw_token,
                "role": agent_obj.get("default_role_key") or role or "agent",
                "status": agent_obj.get("status", "active"),
                "is_system": bool(agent_obj.get("is_system", False)),
                "created_at": agent_obj.get("created_at"),
            }

        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT member_name, token, status FROM member_identities WHERE member_name = ? COLLATE NOCASE",
            (clean_callsign,),
        )
        row = cursor.fetchone()
        if row:
            if row["status"] == "inactive":
                raise PermissionError(f"Acesso negado: O agente '{clean_callsign}' está desativado pelo supervisor Rui. Apenas o supervisor pode reativar.")
            if is_self_registration or row["status"] == "active":
                raise ValueError(f"Callsign '{clean_callsign}' já está em uso no servidor. Duplicados não são permitidos.")
            final_token = token.strip() if token else row["token"]
            now = datetime.now().isoformat()
            with conn:
                conn.execute(
                    "UPDATE member_identities SET token = ?, status = ?, role = ? WHERE member_name = ? COLLATE NOCASE",
                    (final_token, status, role, clean_callsign),
                )
            return {
                "callsign": clean_callsign,
                "token": final_token,
                "role": role,
                "status": status,
                "is_system": is_system,
                "created_at": now,
            }

        final_token = token.strip() if token else secrets.token_hex(16)
        now = datetime.now().isoformat()
        with conn:
            conn.execute(
                """
                INSERT INTO member_identities (member_name, token, role, status, is_system, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (clean_callsign, final_token, role, status, 1 if is_system else 0, now),
            )
        return {
            "callsign": clean_callsign,
            "token": final_token,
            "role": role,
            "status": status,
            "is_system": is_system,
            "created_at": now,
        }

    def rotate_agent_token_admin(self, callsign: str, new_token: str | None = None) -> str:
        """Rotates an agent's secret token in the closed registry."""
        import secrets
        clean_callsign = (callsign or "").strip()
        if self.is_v3():
            p = self.v3.get_principal_by_name(clean_callsign)
            if not p:
                raise ValueError(f"Agente com callsign '{clean_callsign}' não encontrado no registo.")
            raw_token, _ = self.v3.rotate_agent_token(p["id"], raw_token=new_token)
            return raw_token

        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT member_name FROM member_identities WHERE member_name = ? COLLATE NOCASE",
            (clean_callsign,),
        )
        if not cursor.fetchone():
            raise ValueError(f"Agente com callsign '{clean_callsign}' não encontrado no registo.")
        final_token = new_token.strip() if new_token else secrets.token_hex(16)
        with conn:
            conn.execute(
                "UPDATE member_identities SET token = ? WHERE member_name = ? COLLATE NOCASE",
                (final_token, clean_callsign),
            )
            conn.execute(
                "UPDATE members SET token = ? WHERE member_name = ? COLLATE NOCASE",
                (final_token, clean_callsign),
            )
        return final_token

    def update_agent_status_admin(self, callsign: str, status: str) -> None:
        """Updates agent status (e.g. 'active', 'inactive', 'pending')."""
        clean_callsign = (callsign or "").strip()
        target_status = status.strip()
        if self.is_v3():
            p = self.v3.get_principal_by_name(clean_callsign)
            if not p:
                raise ValueError(f"Agente com callsign '{clean_callsign}' não encontrado no registo.")
            self.v3.update_principal_status(p["id"], target_status)
            return

        conn = self._get_connection()
        with conn:
            cursor = conn.execute(
                "UPDATE member_identities SET status = ? WHERE member_name = ? COLLATE NOCASE",
                (target_status, clean_callsign),
            )
            if cursor.rowcount == 0:
                raise ValueError(f"Agente com callsign '{clean_callsign}' não encontrado no registo.")
            if target_status == "inactive":
                conn.execute(
                    "UPDATE members SET token = '' WHERE member_name = ? COLLATE NOCASE",
                    (clean_callsign,),
                )
            elif target_status == "active":
                id_cur = conn.execute("SELECT token FROM member_identities WHERE member_name = ? COLLATE NOCASE", (clean_callsign,))
                id_row = id_cur.fetchone()
                if id_row and id_row["token"]:
                    conn.execute("UPDATE members SET token = ? WHERE member_name = ? COLLATE NOCASE", (id_row["token"], clean_callsign))

    def delete_agent_admin(self, callsign: str) -> None:
        """Deletes an agent from member_identities and room memberships."""
        clean_callsign = (callsign or "").strip()
        if self.is_v3():
            p = self.v3.get_principal_by_name(clean_callsign)
            if not p:
                raise ValueError(f"Agente com callsign '{clean_callsign}' não encontrado no registo.")
            self.v3.delete_principal(p["id"])
            return

        conn = self._get_connection()
        with conn:
            cursor = conn.execute(
                "DELETE FROM member_identities WHERE member_name = ? COLLATE NOCASE",
                (clean_callsign,),
            )
            if cursor.rowcount == 0:
                raise ValueError(f"Agente com callsign '{clean_callsign}' não encontrado no registo.")
            conn.execute(
                "DELETE FROM members WHERE member_name = ? COLLATE NOCASE",
                (clean_callsign,),
            )

    def mask_tokens_in_text(self, text: str, human_token: str = "") -> str:
        """
        Data Loss Prevention (DLP):
        Scans message text for any active secret tokens and redacts them with [REDACTED_TOKEN].
        """
        if not text:
            return text
        if self.is_v3():
            masked = text
            if human_token and len(human_token) >= 16:
                masked = masked.replace(human_token, "[REDACTED_TOKEN]")
            return masked
        conn = self._get_connection()
        cursor = conn.execute("SELECT token FROM member_identities WHERE status = 'active'")
        tokens = {row[0] for row in cursor.fetchall() if row[0] and len(row[0]) >= 16}
        if human_token and len(human_token) >= 16:
            tokens.add(human_token.strip())

        masked = text
        for tok in tokens:
            if tok in masked:
                masked = masked.replace(tok, "[REDACTED_TOKEN]")
        return masked

    def log_audit_event(
        self,
        room_name: str,
        member_name: str,
        action: str,
        status: str,
        details: str = "",
    ) -> dict[str, Any]:
        """Logs a room security or membership event."""
        if self.is_v3():
            room = self.v3._resolve_room(room_name)
            rid = room["id"] if room else None
            p = self.v3.get_principal_by_name(member_name)
            pid = p["id"] if p else None
            self.v3.log_audit(
                actor_id=pid,
                actor_name=member_name,
                action=action,
                target_type="room",
                target_id=rid,
                room_id=rid,
                status=status,
                details=details,
            )
            return {
                "id": 0,
                "room_name": room_name,
                "member_name": member_name,
                "action": action,
                "status": status,
                "details": details,
                "created_at": datetime.now().isoformat(),
            }
        now = datetime.now().isoformat()
        conn = self._get_connection()
        clean_room = room_name.strip()
        clean_member = member_name.strip()
        clean_action = action.strip()
        clean_status = status.strip()
        clean_details = details.strip()
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO room_audit_log (room_name, member_name, action, status, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (clean_room, clean_member, clean_action, clean_status, clean_details, now),
            )
            audit_id = cursor.lastrowid
        return {
            "id": audit_id,
            "room_name": clean_room,
            "member_name": clean_member,
            "action": clean_action,
            "status": clean_status,
            "details": clean_details,
            "created_at": now,
        }

    def get_room_audit_log(self, room_name: str, limit: int = 50) -> list[dict[str, Any]]:
        """Fetches recent audit log entries for a room."""
        if self.is_v3():
            return self.v3.get_room_audit_log(room_name, limit)
        conn = self._get_connection()
        cursor = conn.execute(
            """
            SELECT id, room_name, member_name, action, status, details, created_at
            FROM room_audit_log
            WHERE room_name = ? COLLATE NOCASE
            ORDER BY id DESC
            LIMIT ?
            """,
            (room_name.strip(), limit),
        )
        return [dict(row) for row in cursor.fetchall()]

    def get_member(self, room_name: str, member_name: str) -> dict[str, Any] | None:
        """Retrieves member info (token, role, etc.) by room and name."""
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT room_name, member_name, role, token, last_seen_at FROM members WHERE room_name = ? COLLATE NOCASE AND member_name = ? COLLATE NOCASE",
            (room_name.strip(), member_name.strip()),
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def list_members(self, room_name: str) -> list[dict[str, Any]]:
        """Returns all members in a given room."""
        conn = self._get_connection()
        cursor = conn.execute(
            """
            SELECT member_name, role, joined_at, last_seen_at
            FROM members WHERE room_name = ?
            ORDER BY last_seen_at DESC
            """,
            (room_name,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def add_message(
        self,
        room_name: str,
        sender: str,
        role: str,
        content: str,
        is_verified: bool = False,
        message_type: str = "text",
        metadata: dict[str, Any] | None = None,
        to: str | list[Any] | None = None,
        recipients: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Saves a message to SQLite and appends to .log and .jsonl files."""
        if self.is_v3():
            return self.v3.add_message(
                room_name_or_id=room_name,
                sender=sender,
                role=role,
                content=content,
                is_verified=is_verified,
                message_type=message_type,
                metadata=metadata,
                to=to,
                recipients=recipients,
            )
        now = datetime.now().isoformat()
        conn = self._get_connection()
        clean_room = room_name.strip()
        meta_dict = metadata or {}
        meta_json = json.dumps(meta_dict)
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO messages (room_name, sender, role, content, is_verified, message_type, metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (clean_room, sender, role, content, 1 if is_verified else 0, message_type, meta_json, now),
            )
            msg_id = cursor.lastrowid

        msg_data = {
            "id": msg_id,
            "room_name": clean_room,
            "sender": sender,
            "role": role,
            "content": content,
            "is_verified": bool(is_verified),
            "message_type": message_type,
            "metadata": meta_dict,
            "reactions": [],
            "recipients": [{"target_kind": "all", "target_id": None, "target_name": "all"}],
            "to": ["all"],
            "created_at": now,
        }

        # Append to human-readable .log
        self._append_to_text_log(clean_room, msg_data)

        # Append to structured .jsonl
        self._append_to_jsonl_log(clean_room, msg_data)

        # Update member last_seen
        conn = self._get_connection()
        with conn:
            cursor = conn.execute(
                "UPDATE members SET last_seen_at = ? WHERE room_name = ? COLLATE NOCASE AND member_name = ? COLLATE NOCASE",
                (now, clean_room, sender.strip()),
            )
            if cursor.rowcount == 0:
                conn.execute(
                    """
                    INSERT INTO members (room_name, member_name, role, token, joined_at, last_seen_at)
                    VALUES (?, ?, ?, '', ?, ?)
                    ON CONFLICT(room_name, member_name) DO UPDATE SET
                        last_seen_at = excluded.last_seen_at
                    """,
                    (clean_room, sender.strip(), role, now, now),
                )

        return msg_data

    def get_max_message_id(self, room_name: str) -> int:
        """Returns the highest message ID in the room, or 0 if empty."""
        if self.is_v3():
            return self.v3.get_max_message_id(room_name)
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT COALESCE(MAX(id), 0) FROM messages WHERE room_name = ? COLLATE NOCASE",
            (room_name.strip(),),
        )
        row = cursor.fetchone()
        return row[0] if row else 0

    def _get_reactions_map(self, message_ids: list[int]) -> dict[int, list[dict[str, Any]]]:
        if not message_ids:
            return {}
        conn = self._get_connection()
        placeholders = ",".join("?" for _ in message_ids)
        cursor = conn.execute(
            f"SELECT message_id, emoji, sender FROM reactions WHERE message_id IN ({placeholders}) ORDER BY id ASC",
            message_ids,
        )
        msg_tally: dict[int, dict[str, list[str]]] = {}
        for row in cursor.fetchall():
            mid = row["message_id"]
            em = row["emoji"]
            snd = row["sender"]
            if mid not in msg_tally:
                msg_tally[mid] = {}
            if em not in msg_tally[mid]:
                msg_tally[mid][em] = []
            msg_tally[mid][em].append(snd)

        result: dict[int, list[dict[str, Any]]] = {}
        for mid, tallies in msg_tally.items():
            result[mid] = [
                {"emoji": em, "count": len(users), "users": users}
                for em, users in tallies.items()
            ]
        return result

    def get_message_reactions(self, message_id: int) -> list[dict[str, Any]]:
        """Returns aggregated reactions for a single message."""
        if self.is_v3():
            return self.v3.get_message_reactions(message_id)
        res_map = self._get_reactions_map([message_id])
        return res_map.get(message_id, [])

    def toggle_reaction(
        self,
        message_id: int,
        room_name: str,
        sender: str,
        emoji: str,
    ) -> dict[str, Any]:
        """Toggles an emoji reaction from a sender on a message."""
        if self.is_v3():
            return self.v3.toggle_reaction(
                message_id=message_id,
                room_name_or_id=room_name,
                sender_name_or_id=sender,
                emoji=emoji,
            )
        conn = self._get_connection()
        clean_room = room_name.strip()
        clean_sender = sender.strip()
        clean_emoji = emoji.strip()
        with conn:
            cursor = conn.execute(
                "SELECT id FROM reactions WHERE message_id = ? AND sender = ? AND emoji = ?",
                (message_id, clean_sender, clean_emoji),
            )
            row = cursor.fetchone()
            if row:
                conn.execute("DELETE FROM reactions WHERE id = ?", (row["id"],))
                action = "removed"
            else:
                now = datetime.now().isoformat()
                conn.execute(
                    "INSERT INTO reactions (message_id, room_name, sender, emoji, created_at) VALUES (?, ?, ?, ?, ?)",
                    (message_id, clean_room, clean_sender, clean_emoji, now),
                )
                action = "added"
        reactions = self.get_message_reactions(message_id)
        return {
            "action": action,
            "message_id": message_id,
            "room_name": clean_room,
            "sender": clean_sender,
            "emoji": clean_emoji,
            "reactions": reactions,
        }

    def resolve_decision(
        self,
        message_id: int,
        decision: str,
        decider: str = "Rui",
    ) -> dict[str, Any] | None:
        """Resolves a pending human decision request."""
        if self.is_v3():
            return self.v3.resolve_decision(message_id=message_id, status=decision)
        conn = self._get_connection()
        cursor = conn.execute("SELECT metadata FROM messages WHERE id = ?", (message_id,))
        row = cursor.fetchone()
        if not row:
            return None
        meta = json.loads(row["metadata"] or "{}")
        meta["status"] = "resolved"
        meta["decision"] = decision
        meta["decided_by"] = decider
        meta["decided_at"] = datetime.now().isoformat()
        with conn:
            conn.execute(
                "UPDATE messages SET metadata = ? WHERE id = ?",
                (json.dumps(meta), message_id),
            )
        return meta

    def create_poll(
        self,
        room_name: str,
        creator: str,
        question: str,
        options: list[str],
    ) -> dict[str, Any]:
        """Creates a new poll in a room."""
        if self.is_v3():
            return self.v3.create_poll(
                room_name_or_id=room_name,
                creator_name_or_id=creator,
                question=question,
                options=options,
            )
        now = datetime.now().isoformat()
        conn = self._get_connection()
        clean_options = [opt.strip() for opt in options if opt.strip()]
        if len(clean_options) < 2:
            raise ValueError("Uma votação necessita de pelo menos 2 opções.")
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO polls (room_name, creator, question, options, is_closed, created_at)
                VALUES (?, ?, ?, ?, 0, ?)
                """,
                (room_name.strip(), creator.strip(), question.strip(), json.dumps(clean_options), now),
            )
            poll_id = cursor.lastrowid
        return self.get_poll(poll_id)

    def cast_vote(
        self,
        poll_id: int,
        voter: str,
        option_index: int,
    ) -> dict[str, Any]:
        """Casts or updates a vote on an active poll."""
        if self.is_v3():
            return self.v3.cast_vote(poll_id=poll_id, voter_name_or_id=voter, option_index=option_index)
        conn = self._get_connection()
        cursor = conn.execute("SELECT is_closed, options FROM polls WHERE id = ?", (poll_id,))
        row = cursor.fetchone()
        if not row:
            raise ValueError(f"Poll #{poll_id} não existe.")
        if row["is_closed"]:
            raise ValueError(f"Poll #{poll_id} já se encontra encerrada.")
        opts = json.loads(row["options"])
        if option_index < 0 or option_index >= len(opts):
            raise ValueError(f"Opção inválida ({option_index}). As opções vão de 0 a {len(opts)-1}.")
        now = datetime.now().isoformat()
        with conn:
            conn.execute(
                """
                INSERT INTO poll_votes (poll_id, voter, option_index, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(poll_id, voter) DO UPDATE SET
                    option_index = excluded.option_index,
                    created_at = excluded.created_at
                """,
                (poll_id, voter.strip(), option_index, now),
            )
        return self.get_poll(poll_id)

    def close_poll(self, poll_id: int) -> dict[str, Any]:
        """Closes a poll to prevent further votes."""
        if self.is_v3():
            return self.v3.close_poll(poll_id=poll_id)
        conn = self._get_connection()
        now = datetime.now().isoformat()
        with conn:
            conn.execute(
                "UPDATE polls SET is_closed = 1, closed_at = ? WHERE id = ?",
                (now, poll_id),
            )
        return self.get_poll(poll_id)

    def get_poll(self, poll_id: int) -> dict[str, Any] | None:
        """Retrieves poll details with vote tallies and percentages."""
        if self.is_v3():
            return self.v3.get_poll(poll_id)
        conn = self._get_connection()
        cursor = conn.execute(
            """
            SELECT id, room_name, creator, question, options, is_closed, created_at, closed_at
            FROM polls WHERE id = ?
            """,
            (poll_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        options = json.loads(row["options"])
        votes_cursor = conn.execute(
            "SELECT voter, option_index FROM poll_votes WHERE poll_id = ? ORDER BY id ASC",
            (poll_id,),
        )
        all_votes = votes_cursor.fetchall()
        total_votes = len(all_votes)

        tally = {i: [] for i in range(len(options))}
        for v in all_votes:
            idx = v["option_index"]
            if idx in tally:
                tally[idx].append(v["voter"])

        options_data = []
        for i, opt_text in enumerate(options):
            voters = tally[i]
            pct = round((len(voters) / total_votes * 100), 1) if total_votes > 0 else 0.0
            options_data.append({
                "index": i,
                "text": opt_text,
                "votes": len(voters),
                "percentage": pct,
                "voters": voters,
            })

        return {
            "id": row["id"],
            "room_name": row["room_name"],
            "creator": row["creator"],
            "question": row["question"],
            "options": options_data,
            "total_votes": total_votes,
            "is_closed": bool(row["is_closed"]),
            "created_at": row["created_at"],
            "closed_at": row["closed_at"],
        }

    def get_messages(
        self,
        room_name: str,
        since_id: int = 0,
        before_id: int = 0,
        limit: int = 50,
        from_beginning: bool = False,
    ) -> list[dict[str, Any]]:
        """
        Retrieves messages for a room.
        - If since_id > 0 and before_id > 0: returns messages strictly between since_id and before_id (ascending).
        - If before_id > 0 (and since_id == 0): returns up to `limit` messages strictly older than before_id (ascending).
        - If since_id > 0 (or since_id == 0 with from_beginning=True): returns messages strictly newer than since_id (ascending).
        - If both == 0 (without from_beginning): returns the most recent `limit` messages in chronological order (ascending).
        """
        if self.is_v3():
            return self.v3.get_messages(
                room_name_or_id=room_name,
                since_id=since_id,
                before_id=before_id,
                limit=limit,
                from_beginning=from_beginning,
            )
        conn = self._get_connection()
        clean_room = room_name.strip()
        if since_id > 0 and before_id > 0:
            cursor = conn.execute(
                """
                SELECT id, room_name, sender, role, content, is_verified, 
                       COALESCE(message_type, 'text') as message_type, 
                       COALESCE(metadata, '{}') as metadata, created_at
                FROM messages
                WHERE room_name = ? COLLATE NOCASE AND id > ? AND id < ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (clean_room, since_id, before_id, limit),
            )
        elif before_id > 0:
            # Fetch the most recent `limit` messages strictly older than before_id, ordered chronologically
            cursor = conn.execute(
                """
                SELECT id, room_name, sender, role, content, is_verified, 
                       COALESCE(message_type, 'text') as message_type, 
                       COALESCE(metadata, '{}') as metadata, created_at
                FROM (
                    SELECT id, room_name, sender, role, content, is_verified, message_type, metadata, created_at
                    FROM messages
                    WHERE room_name = ? COLLATE NOCASE AND id < ?
                    ORDER BY id DESC
                    LIMIT ?
                )
                ORDER BY id ASC
                """,
                (clean_room, before_id, limit),
            )
        elif since_id > 0 or (since_id == 0 and from_beginning):
            cursor = conn.execute(
                """
                SELECT id, room_name, sender, role, content, is_verified, 
                       COALESCE(message_type, 'text') as message_type, 
                       COALESCE(metadata, '{}') as metadata, created_at
                FROM messages
                WHERE room_name = ? COLLATE NOCASE AND id > ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (clean_room, since_id, limit),
            )
        else:
            # Fetch the most recent `limit` messages, ordered chronologically
            cursor = conn.execute(
                """
                SELECT id, room_name, sender, role, content, is_verified, 
                       COALESCE(message_type, 'text') as message_type, 
                       COALESCE(metadata, '{}') as metadata, created_at
                FROM (
                    SELECT id, room_name, sender, role, content, is_verified, message_type, metadata, created_at
                    FROM messages
                    WHERE room_name = ? COLLATE NOCASE
                    ORDER BY id DESC
                    LIMIT ?
                )
                ORDER BY id ASC
                """,
                (clean_room, limit),
            )
        rows = [dict(row) for row in cursor.fetchall()]
        if not rows:
            return []

        # Batch load reactions
        msg_ids = [r["id"] for r in rows]
        reactions_map = self._get_reactions_map(msg_ids)

        for r in rows:
            r["is_verified"] = bool(r.get("is_verified", False))
            r["message_type"] = r.get("message_type") or "text"
            meta = r.get("metadata")
            if isinstance(meta, str) and meta:
                try:
                    r["metadata"] = json.loads(meta)
                except Exception:
                    r["metadata"] = {}
            elif not isinstance(meta, dict):
                r["metadata"] = {}
            r["reactions"] = reactions_map.get(r["id"], [])

        return rows

    def get_message_by_id(self, message_id: int) -> dict[str, Any] | None:
        """Retrieves a single message by ID, including its parsed metadata and reactions."""
        conn = self._get_connection()
        cursor = conn.execute(
            """
            SELECT id, room_name, sender, role, content, is_verified, 
                   COALESCE(message_type, 'text') as message_type, 
                   COALESCE(metadata, '{}') as metadata, created_at
            FROM messages
            WHERE id = ?
            """,
            (message_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        r = dict(row)
        r["is_verified"] = bool(r.get("is_verified", False))
        r["message_type"] = r.get("message_type") or "text"
        meta = r.get("metadata")
        if isinstance(meta, str) and meta:
            try:
                r["metadata"] = json.loads(meta)
            except Exception:
                r["metadata"] = {}
        elif not isinstance(meta, dict):
            r["metadata"] = {}
        r["reactions"] = self.get_message_reactions(message_id)
        return r

    # -------------------------------------------------------------
    # Task Planner Operations (v2.5)
    # -------------------------------------------------------------
    def create_task(
        self,
        room_name: str,
        title: str,
        description: str = "",
        assignee: str = "",
        waiting_for_agent: str = "",
        priority: str = "medium",
        status: str = "planned",
        order_index: int | None = None,
        message_id: int | None = None,
        uses_gpu: bool = False,
        gpu_est_min: int = 0,
        start_at: str = "",
        due_at: str = "",
        resource: str = "",
        created_by: str = "System",
    ) -> dict[str, Any]:
        """Creates a new task in a room."""
        clean_room = room_name.strip()
        clean_title = title.strip()
        if not clean_title:
            raise ValueError("O título da tarefa não pode estar vazio.")

        if self.is_v3():
            return self.v3.create_task(
                room_name_or_id=clean_room,
                title=clean_title,
                description=description,
                status=status,
                assignee=assignee,
                waiting_for_agent=waiting_for_agent,
                priority=priority,
                order_index=order_index,
                message_id=message_id,
                uses_gpu=uses_gpu,
                gpu_est_min=gpu_est_min,
                resource=resource,
                start_at=start_at,
                due_at=due_at,
                created_by=created_by,
            )

        valid_priorities = ("urgent", "high", "medium", "low")
        clean_priority = priority.strip().lower() if priority else "medium"
        if clean_priority not in valid_priorities:
            clean_priority = "medium"

        valid_statuses = ("planned", "in_progress", "waiting_human", "waiting_agent", "done", "cancelled")
        clean_status = status.strip().lower() if status else "planned"
        if clean_status not in valid_statuses:
            clean_status = "planned"

        conn = self._get_connection()
        now = datetime.now().isoformat()

        if order_index is None or order_index == 0:
            cursor = conn.execute(
                "SELECT COALESCE(MAX(order_index), 0) + 1 FROM tasks WHERE room_name = ? COLLATE NOCASE",
                (clean_room,),
            )
            calc_order = cursor.fetchone()[0]
        else:
            calc_order = int(order_index)

        clean_start = (start_at or "").strip()
        clean_due = (due_at or "").strip()
        clean_resource = (resource or "").strip()

        with conn:
            cursor = conn.execute(
                """
                INSERT INTO tasks (
                    room_name, title, description, status, assignee, waiting_for_agent,
                    priority, order_index, message_id, uses_gpu, gpu_est_min,
                    start_at, due_at, resource,
                    created_by, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    clean_room,
                    clean_title,
                    description.strip() if description else "",
                    clean_status,
                    assignee.strip() if assignee else "",
                    waiting_for_agent.strip() if waiting_for_agent else "",
                    clean_priority,
                    calc_order,
                    message_id if message_id and message_id > 0 else None,
                    1 if uses_gpu else 0,
                    max(0, int(gpu_est_min or 0)),
                    clean_start,
                    clean_due,
                    clean_resource,
                    created_by.strip() or "System",
                    now,
                    now,
                ),
            )
            task_id = cursor.lastrowid
            conn.execute(
                """
                INSERT INTO task_history (task_id, action, actor, to_status, details, created_at)
                VALUES (?, 'created', ?, ?, ?, ?)
                """,
                (task_id, created_by.strip() or "System", clean_status, clean_title, now),
            )

        if clean_start:
            try:
                self.create_calendar_event(
                    room_name=clean_room,
                    title=clean_title,
                    start_at=clean_start,
                    end_at=clean_due,
                    description=description.strip() if description else "",
                    task_id=task_id,
                    resource=clean_resource,
                    target_agent=assignee.strip() if assignee else "",
                    status="scheduled",
                    created_by=created_by.strip() or "System",
                )
            except Exception:
                pass

        task = self.get_task_by_id(task_id)
        if not task:
            raise RuntimeError(f"Falha ao carregar tarefa recém-criada #{task_id}")
        return task

    def update_task(
        self,
        task_id: int,
        actor: str = "System",
        title: str | None = None,
        description: str | None = None,
        status: str | None = None,
        assignee: str | None = None,
        waiting_for_agent: str | None = None,
        priority: str | None = None,
        order_index: int | None = None,
        message_id: int | None = None,
        uses_gpu: bool | None = None,
        gpu_est_min: int | None = None,
        start_at: str | None = None,
        due_at: str | None = None,
        resource: str | None = None,
    ) -> dict[str, Any]:
        """Updates fields of an existing task."""
        if self.is_v3():
            return self.v3.update_task(
                task_id=task_id,
                actor=actor,
                title=title,
                description=description,
                status=status,
                assignee=assignee,
                waiting_for_agent=waiting_for_agent,
                priority=priority,
                order_index=order_index,
                message_id=message_id,
                uses_gpu=uses_gpu,
                gpu_est_min=gpu_est_min,
                start_at=start_at,
                due_at=due_at,
                resource=resource,
            )

        conn = self._get_connection()
        task = self.get_task_by_id(task_id)
        if not task:
            raise ValueError(f"Tarefa #{task_id} não encontrada.")

        now = datetime.now().isoformat()
        updates = []
        params = []
        old_status = task["status"]

        if title is not None and title.strip():
            updates.append("title = ?")
            params.append(title.strip())

        if description is not None:
            updates.append("description = ?")
            params.append(description.strip())

        new_status = None
        if status is not None and status.strip():
            clean_status = status.strip().lower()
            valid_statuses = ("planned", "in_progress", "waiting_human", "waiting_agent", "done", "cancelled")
            if clean_status in valid_statuses:
                updates.append("status = ?")
                params.append(clean_status)
                new_status = clean_status

        if assignee is not None:
            updates.append("assignee = ?")
            params.append(assignee.strip())

        if waiting_for_agent is not None:
            updates.append("waiting_for_agent = ?")
            params.append(waiting_for_agent.strip())

        if priority is not None and priority.strip():
            clean_priority = priority.strip().lower()
            if clean_priority in ("urgent", "high", "medium", "low"):
                updates.append("priority = ?")
                params.append(clean_priority)

        if order_index is not None:
            updates.append("order_index = ?")
            params.append(int(order_index))

        if message_id is not None:
            updates.append("message_id = ?")
            params.append(message_id if message_id > 0 else None)

        if uses_gpu is not None:
            updates.append("uses_gpu = ?")
            params.append(1 if uses_gpu else 0)

        if gpu_est_min is not None:
            updates.append("gpu_est_min = ?")
            params.append(max(0, int(gpu_est_min)))

        if start_at is not None:
            updates.append("start_at = ?")
            params.append(start_at.strip())

        if due_at is not None:
            updates.append("due_at = ?")
            params.append(due_at.strip())

        if resource is not None:
            updates.append("resource = ?")
            params.append(resource.strip())

        if not updates:
            return task

        updates.append("updated_at = ?")
        params.append(now)
        params.append(task_id)

        with conn:
            conn.execute(
                f"UPDATE tasks SET {', '.join(updates)} WHERE id = ?",
                params,
            )
            if new_status and new_status != old_status:
                conn.execute(
                    """
                    INSERT INTO task_history (task_id, action, actor, from_status, to_status, details, created_at)
                    VALUES (?, 'status_changed', ?, ?, ?, ?, ?)
                    """,
                    (task_id, actor, old_status, new_status, f"Status updated to {new_status}", now),
                )
                if new_status in ("done", "cancelled"):
                    cal_status = "completed" if new_status == "done" else "cancelled"
                    conn.execute(
                        "UPDATE calendar_events SET status = ?, updated_at = ? WHERE task_id = ?",
                        (cal_status, now, task_id),
                    )
                elif new_status in ("planned", "in_progress"):
                    cal_status = "scheduled" if new_status == "planned" else "active"
                    conn.execute(
                        "UPDATE calendar_events SET status = ?, updated_at = ? WHERE task_id = ?",
                        (cal_status, now, task_id),
                    )
            else:
                conn.execute(
                    """
                    INSERT INTO task_history (task_id, action, actor, details, created_at)
                    VALUES (?, 'updated', ?, ?, ?)
                    """,
                    (task_id, actor, "Fields updated", now),
                )

        updated_task = self.get_task_by_id(task_id)
        if not updated_task:
            raise RuntimeError(f"Falha ao carregar tarefa atualizada #{task_id}")
        return updated_task

    def delete_task(self, task_id: int) -> bool:
        """Deletes a task and its history."""
        if self.is_v3():
            return self.v3.delete_task(task_id)
        conn = self._get_connection()
        with conn:
            cursor = conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
            conn.execute("DELETE FROM task_history WHERE task_id = ?", (task_id,))
            return cursor.rowcount > 0

    def get_task_by_id(self, task_id: int) -> dict[str, Any] | None:
        """Retrieves a single task by ID with staleness computation and history."""
        if self.is_v3():
            return self.v3.get_task_by_id(task_id)
        conn = self._get_connection()
        cursor = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
        row = cursor.fetchone()
        if not row:
            return None
        t = dict(row)
        t["uses_gpu"] = bool(t.get("uses_gpu", 0))
        t["is_stale"] = False
        t["stale_minutes"] = 0
        if t["status"] == "in_progress" and t.get("updated_at"):
            try:
                updated_dt = datetime.fromisoformat(t["updated_at"])
                elapsed = (datetime.now() - updated_dt).total_seconds()
                if elapsed > 900:  # 15 minutes
                    t["is_stale"] = True
                    t["stale_minutes"] = int(elapsed / 60)
            except Exception:
                pass
        t["history"] = self.get_task_history(task_id)
        return t

    def get_task_history(self, task_id: int) -> list[dict[str, Any]]:
        """Returns the chronological history of changes for a task."""
        if self.is_v3():
            return self.v3.get_task_history(task_id)
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT id, task_id, action, actor, from_status, to_status, details, created_at FROM task_history WHERE task_id = ? ORDER BY id ASC",
            (task_id,),
        )
        return [dict(r) for r in cursor.fetchall()]

    def list_tasks(
        self,
        room_name: str,
        status: str | None = None,
        assignee: str | None = None,
        hide_completed: bool = False,
    ) -> list[dict[str, Any]]:
        """Lists tasks for a room, optionally filtered by status, assignee, or hiding completed."""
        if self.is_v3():
            return self.v3.list_tasks(room_name_or_id=room_name, status=status)
        conn = self._get_connection()
        query = "SELECT * FROM tasks WHERE room_name = ? COLLATE NOCASE"
        params: list[Any] = [room_name.strip()]

        if status:
            query += " AND status = ? COLLATE NOCASE"
            params.append(status.strip().lower())
        elif hide_completed:
            query += " AND status NOT IN ('done', 'cancelled')"

        if assignee:
            query += " AND assignee = ? COLLATE NOCASE"
            params.append(assignee.strip())

        query += """
            ORDER BY 
                order_index ASC,
                id ASC
        """
        cursor = conn.execute(query, params)
        rows = [dict(r) for r in cursor.fetchall()]
        now = datetime.now()
        for t in rows:
            t["uses_gpu"] = bool(t.get("uses_gpu", 0))
            t["is_stale"] = False
            t["stale_minutes"] = 0
            if t["status"] == "in_progress" and t.get("updated_at"):
                try:
                    updated_dt = datetime.fromisoformat(t["updated_at"])
                    elapsed = (now - updated_dt).total_seconds()
                    if elapsed > 900:
                        t["is_stale"] = True
                        t["stale_minutes"] = int(elapsed / 60)
                except Exception:
                    pass
        return rows

    def reorder_tasks(self, room_name: str, task_ids: list[int]) -> list[dict[str, Any]]:
        """Sets new order_index for given task IDs in the room."""
        if self.is_v3():
            return self.v3.reorder_tasks(room_name_or_id=room_name, task_ids=task_ids)
        conn = self._get_connection()
        now = datetime.now().isoformat()
        with conn:
            for idx, tid in enumerate(task_ids):
                conn.execute(
                    "UPDATE tasks SET order_index = ?, updated_at = ? WHERE id = ? AND room_name = ? COLLATE NOCASE",
                    (idx + 1, now, tid, room_name.strip()),
                )
        return self.list_tasks(room_name)

    def update_member_last_seen(self, room_name: str, member_name: str) -> None:
        """Updates last_seen_at timestamp for a room member."""
        conn = self._get_connection()
        now = datetime.now().isoformat()
        with conn:
            conn.execute(
                "UPDATE members SET last_seen_at = ? WHERE room_name = ? COLLATE NOCASE AND member_name = ? COLLATE NOCASE",
                (now, room_name.strip(), member_name.strip()),
            )

    def get_room_log_file(self, room_name: str) -> Path:
        """Returns path to the text log file for the room, indexed by room ID to prevent collisions."""
        room = self.get_room(room_name)
        safe_name = "".join(c for c in room_name if c.isalnum() or c in ("-", "_")).rstrip() or "chat"
        if room and room.get("id"):
            room_id = room["id"]
            new_path = self.logs_dir / f"room_{room_id}_{safe_name}.log"
            legacy_path = self.logs_dir / f"{safe_name}.log"
            if legacy_path.exists() and not new_path.exists():
                try:
                    import shutil
                    shutil.move(legacy_path, new_path)
                except Exception:
                    pass
            return new_path
        return self.logs_dir / f"{safe_name}.log"

    def get_room_jsonl_file(self, room_name: str) -> Path:
        """Returns path to the JSONL log file for the room, indexed by room ID to prevent collisions."""
        room = self.get_room(room_name)
        safe_name = "".join(c for c in room_name if c.isalnum() or c in ("-", "_")).rstrip() or "chat"
        if room and room.get("id"):
            room_id = room["id"]
            new_path = self.logs_dir / f"room_{room_id}_{safe_name}.jsonl"
            legacy_path = self.logs_dir / f"{safe_name}.jsonl"
            if legacy_path.exists() and not new_path.exists():
                try:
                    import shutil
                    shutil.move(legacy_path, new_path)
                except Exception:
                    pass
            return new_path
        return self.logs_dir / f"{safe_name}.jsonl"

    def _append_to_text_log(self, room_name: str, msg: dict[str, Any]) -> None:
        """Appends formatted message to room text transcript."""
        log_path = self.get_room_log_file(room_name)
        role_label = msg["role"].capitalize()
        timestamp = msg["created_at"].replace("T", " ")[:19]
        entry = (
            f"[{timestamp}] [{role_label}] {msg['sender']} (msg #{msg['id']}):\n"
            f"{msg['content']}\n"
            f"{'-' * 60}\n"
        )
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(entry)
        except Exception:
            pass

    def _append_to_jsonl_log(self, room_name: str, msg: dict[str, Any]) -> None:
        """Appends JSON record to room .jsonl file."""
        jsonl_path = self.get_room_jsonl_file(room_name)
        try:
            with open(jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(msg, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def read_text_transcript(self, room_name: str) -> str:
        """Reads the full human-readable transcript file."""
        log_path = self.get_room_log_file(room_name)
        if log_path.exists():
            try:
                return log_path.read_text(encoding="utf-8")
            except Exception:
                pass
        return f"No transcript available for room '{room_name}'."

    def save_human_session(self, session_hash: str, expires_at: float, created_at: float) -> None:
        """Stores or replaces a hashed human session in SQLite."""
        conn = self._get_connection()
        with conn:
            conn.execute(
                "INSERT OR REPLACE INTO human_sessions (session_hash, expires_at, created_at) VALUES (?, ?, ?)",
                (session_hash, expires_at, created_at),
            )

    def verify_human_session(self, session_hash: str) -> bool:
        """Checks if a session hash exists and has not expired."""
        conn = self._get_connection()
        now = time.time()
        cur = conn.execute("SELECT expires_at FROM human_sessions WHERE session_hash = ?", (session_hash,))
        row = cur.fetchone()
        if row is None:
            return False
        if row["expires_at"] > now:
            return True
        # Expired: clean up
        with conn:
            conn.execute("DELETE FROM human_sessions WHERE session_hash = ?", (session_hash,))
        return False

    def delete_human_session(self, session_hash: str) -> None:
        """Deletes a human session upon logout."""
        conn = self._get_connection()
        with conn:
            conn.execute("DELETE FROM human_sessions WHERE session_hash = ?", (session_hash,))

    def cleanup_expired_sessions(self) -> None:
        """Removes all expired sessions from database."""
        conn = self._get_connection()
        now = time.time()
        with conn:
            conn.execute("DELETE FROM human_sessions WHERE expires_at <= ?", (now,))

    # -------------------------------------------------------------
    # Calendar Events & Hardware Reservation Operations (v2.8)
    # -------------------------------------------------------------
    def check_resource_conflicts(
        self,
        resource: str,
        start_at: str,
        end_at: str = "",
        exclude_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Detects if a specified hardware resource (e.g. 'RTX_3080') has overlapping reservations.
        Overlap condition: new_start < existing_end AND new_end > existing_start.
        """
        clean_resource = (resource or "").strip().upper()
        if not clean_resource:
            return []

        clean_start = (start_at or "").strip()
        clean_end = (end_at or "").strip()
        if not clean_start:
            return []

        if self.is_v3():
            eff_end = clean_end or (datetime.fromisoformat(clean_start) + timedelta(hours=1)).isoformat()
            res = self.v3.check_resource_availability(clean_resource, clean_start, eff_end, exclude_event_id=exclude_id)
            return res.get("conflicts", [])

        try:
            start_dt = datetime.fromisoformat(clean_start)
        except Exception:
            return []

        if clean_end:
            try:
                end_dt = datetime.fromisoformat(clean_end)
            except Exception:
                end_dt = start_dt + timedelta(hours=1)
        else:
            end_dt = start_dt + timedelta(hours=1)

        conn = self._get_connection()
        query = """
            SELECT * FROM calendar_events 
            WHERE UPPER(resource) = ? 
            AND status NOT IN ('completed', 'cancelled')
        """
        params: list[Any] = [clean_resource]
        if exclude_id is not None:
            query += " AND id != ?"
            params.append(exclude_id)

        rows = conn.execute(query, params).fetchall()
        conflicts = []
        for r in rows:
            ev = dict(r)
            ex_start_str = ev.get("start_at", "")
            ex_end_str = ev.get("end_at", "")
            try:
                ex_start = datetime.fromisoformat(ex_start_str)
            except Exception:
                continue

            if ex_end_str:
                try:
                    ex_end = datetime.fromisoformat(ex_end_str)
                except Exception:
                    ex_end = ex_start + timedelta(hours=1)
            else:
                ex_end = ex_start + timedelta(hours=1)

            if start_dt < ex_end and end_dt > ex_start:
                conflicts.append(ev)

        return conflicts

    def create_calendar_event(
        self,
        room_name: str,
        title: str,
        start_at: str,
        end_at: str = "",
        description: str = "",
        event_type: str = "event",
        task_id: int | None = None,
        resource: str = "",
        target_agent: str = "",
        status: str = "scheduled",
        wake_on_start: bool = True,
        wake_on_end: bool = False,
        created_by: str = "System",
        force: bool = False,
    ) -> dict[str, Any]:
        """Creates a new calendar event, checking for resource collisions."""
        clean_room = (room_name or "").strip()
        clean_title = (title or "").strip()
        if not clean_title:
            raise ValueError("O título do evento não pode estar vazio.")
        clean_start = (start_at or "").strip()
        if not clean_start:
            raise ValueError("A data de início ('start_at') é obrigatória.")

        try:
            datetime.fromisoformat(clean_start)
        except Exception as e:
            raise ValueError(f"Formato de data 'start_at' inválido ('{clean_start}'). Use ISO 8601 (YYYY-MM-DDTHH:MM:SS): {e}")

        clean_end = (end_at or "").strip()
        if clean_end:
            try:
                datetime.fromisoformat(clean_end)
            except Exception as e:
                raise ValueError(f"Formato de data 'end_at' inválido ('{clean_end}'). Use ISO 8601: {e}")

        clean_resource = (resource or "").strip()
        if self.is_v3():
            if clean_resource and not force:
                conflicts = self.check_resource_conflicts(clean_resource, clean_start, clean_end)
                if conflicts:
                    c = conflicts[0]
                    ex_by = c.get("created_by", "outro agente")
                    ex_title = c.get("title", "")
                    ex_s = c.get("start_at", "")
                    ex_e = c.get("end_at", "") or "indeterminado"
                    raise ValueError(
                        f"Conflito de recurso: '{clean_resource}' já está reservado por @{ex_by} ('{ex_title}') das {ex_s} às {ex_e}. Use force=True com autorização para sobrepor."
                    )
            return self.v3.create_calendar_event(
                room_name_or_id=clean_room,
                title=clean_title,
                start_at=clean_start,
                end_at=clean_end or None,
                description=description,
                event_type=event_type,
                task_id=task_id,
                resource=clean_resource or None,
                target_id_or_name=target_agent or None,
                status=status,
                wake_on_start=1 if wake_on_start else 0,
                wake_on_end=1 if wake_on_end else 0,
                created_by_id_or_name=created_by,
            )

        if clean_resource and not force:
            conflicts = self.check_resource_conflicts(clean_resource, clean_start, clean_end)
            if conflicts:
                c = conflicts[0]
                ex_by = c.get("created_by", "outro agente")
                ex_title = c.get("title", "")
                ex_s = c.get("start_at", "")
                ex_e = c.get("end_at", "") or "indeterminado"
                raise ValueError(
                    f"Conflito de recurso: '{clean_resource}' já está reservado por @{ex_by} ('{ex_title}') das {ex_s} às {ex_e}. Use force=True com autorização para sobrepor."
                )

        clean_type = (event_type or "event").strip().lower()
        clean_status = (status or "scheduled").strip().lower()
        now = datetime.now().isoformat()

        conn = self._get_connection()
        with conn:
            cur = conn.execute(
                """
                INSERT INTO calendar_events (
                    room_name, title, description, start_at, end_at,
                    event_type, task_id, resource, target_agent, status,
                    wake_on_start, wake_on_end, notified_start, notified_end,
                    created_by, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?)
                """,
                (
                    clean_room,
                    clean_title,
                    description.strip() if description else "",
                    clean_start,
                    clean_end,
                    clean_type,
                    task_id if task_id and task_id > 0 else None,
                    clean_resource,
                    target_agent.strip() if target_agent else "",
                    clean_status,
                    1 if wake_on_start else 0,
                    1 if wake_on_end else 0,
                    created_by.strip() or "System",
                    now,
                    now,
                ),
            )
            event_id = cur.lastrowid

        ev = self.get_calendar_event_by_id(event_id)
        if not ev:
            raise RuntimeError(f"Falha ao recuperar evento #{event_id}")
        return ev

    def get_calendar_event_by_id(self, event_id: int) -> dict[str, Any] | None:
        """Retrieves a single calendar event by ID."""
        if self.is_v3():
            return self.v3.get_calendar_event_by_id(event_id)
        conn = self._get_connection()
        cur = conn.execute("SELECT * FROM calendar_events WHERE id = ?", (event_id,))
        row = cur.fetchone()
        if not row:
            return None
        ev = dict(row)
        ev["wake_on_start"] = bool(ev.get("wake_on_start", 1))
        ev["wake_on_end"] = bool(ev.get("wake_on_end", 0))
        ev["notified_start"] = bool(ev.get("notified_start", 0))
        ev["notified_end"] = bool(ev.get("notified_end", 0))
        return ev

    def list_calendar_events(
        self,
        room_name: str = "all",
        start_from: str = "",
        start_to: str = "",
        resource: str = "",
        status: str = "",
        include_completed: bool = True,
    ) -> list[dict[str, Any]]:
        """Lists calendar events with optional filtering."""
        clean_room = (room_name or "").strip().lower()
        if self.is_v3():
            room_filter = None if (not clean_room or clean_room in ("all", "*")) else clean_room
            return self.v3.list_calendar_events(
                room_name_or_id=room_filter,
                resource=resource or None,
                start_after=start_from or None,
                end_before=start_to or None,
                hide_completed=not include_completed,
            )

        conn = self._get_connection()
        query = "SELECT * FROM calendar_events WHERE 1=1"
        params: list[Any] = []

        if clean_room and clean_room not in ("all", "*"):
            query += " AND room_name = ? COLLATE NOCASE"
            params.append(clean_room)

        if start_from:
            query += " AND (start_at >= ? OR (end_at != '' AND end_at >= ?))"
            params.extend([start_from, start_from])

        if start_to:
            query += " AND start_at <= ?"
            params.append(start_to)

        if resource:
            query += " AND UPPER(resource) = ?"
            params.append(resource.strip().upper())

        if status:
            query += " AND status = ? COLLATE NOCASE"
            params.append(status.strip().lower())
        elif not include_completed:
            query += " AND status NOT IN ('completed', 'cancelled')"

        query += " ORDER BY start_at ASC"
        cur = conn.execute(query, params)
        events = []
        for r in cur.fetchall():
            ev = dict(r)
            ev["wake_on_start"] = bool(ev.get("wake_on_start", 1))
            ev["wake_on_end"] = bool(ev.get("wake_on_end", 0))
            ev["notified_start"] = bool(ev.get("notified_start", 0))
            ev["notified_end"] = bool(ev.get("notified_end", 0))
            events.append(ev)
        return events

    def update_calendar_event(
        self,
        event_id: int,
        title: str | None = None,
        description: str | None = None,
        start_at: str | None = None,
        end_at: str | None = None,
        event_type: str | None = None,
        task_id: int | None = None,
        resource: str | None = None,
        target_agent: str | None = None,
        status: str | None = None,
        wake_on_start: bool | None = None,
        wake_on_end: bool | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        """Updates a calendar event, checking for resource collisions if timing/resource changes."""
        if self.is_v3():
            return self.v3.update_calendar_event(
                event_id=event_id,
                title=title,
                description=description,
                start_at=start_at,
                end_at=end_at,
                status=status,
                resource=resource,
            )

        ev = self.get_calendar_event_by_id(event_id)
        if not ev:
            raise ValueError(f"Evento #{event_id} não encontrado.")

        new_resource = resource.strip() if resource is not None else ev.get("resource", "")
        new_start = start_at.strip() if start_at is not None else ev.get("start_at", "")
        new_end = end_at.strip() if end_at is not None else ev.get("end_at", "")

        if (start_at is not None or end_at is not None or resource is not None) and new_resource and not force:
            conflicts = self.check_resource_conflicts(new_resource, new_start, new_end, exclude_id=event_id)
            if conflicts:
                c = conflicts[0]
                raise ValueError(
                    f"Conflito de recurso: '{new_resource}' já está reservado por @{c.get('created_by')} ('{c.get('title')}') das {c.get('start_at')} às {c.get('end_at') or 'indeterminado'}."
                )

        now = datetime.now().isoformat()
        updates = ["updated_at = ?"]
        params: list[Any] = [now]

        if title is not None and title.strip():
            updates.append("title = ?")
            params.append(title.strip())
        if description is not None:
            updates.append("description = ?")
            params.append(description.strip())
        if start_at is not None and start_at.strip():
            updates.append("start_at = ?")
            params.append(start_at.strip())
            updates.append("notified_start = 0")
        if end_at is not None:
            updates.append("end_at = ?")
            params.append(end_at.strip())
            updates.append("notified_end = 0")
        if event_type is not None:
            updates.append("event_type = ?")
            params.append(event_type.strip().lower())
        if task_id is not None:
            updates.append("task_id = ?")
            params.append(task_id if task_id > 0 else None)
        if resource is not None:
            updates.append("resource = ?")
            params.append(new_resource)
        if target_agent is not None:
            updates.append("target_agent = ?")
            params.append(target_agent.strip())
        if status is not None:
            updates.append("status = ?")
            params.append(status.strip().lower())
        if wake_on_start is not None:
            updates.append("wake_on_start = ?")
            params.append(1 if wake_on_start else 0)
        if wake_on_end is not None:
            updates.append("wake_on_end = ?")
            params.append(1 if wake_on_end else 0)

        params.append(event_id)
        conn = self._get_connection()
        with conn:
            conn.execute(f"UPDATE calendar_events SET {', '.join(updates)} WHERE id = ?", params)

        updated = self.get_calendar_event_by_id(event_id)
        if not updated:
            raise RuntimeError(f"Falha ao carregar evento atualizado #{event_id}")
        return updated

    def delete_calendar_event(self, event_id: int) -> bool:
        """Deletes a calendar event by ID."""
        if self.is_v3():
            return self.v3.delete_calendar_event(event_id)
        conn = self._get_connection()
        with conn:
            cur = conn.execute("DELETE FROM calendar_events WHERE id = ?", (event_id,))
            return cur.rowcount > 0

    def get_due_calendar_events(self, now_iso: str) -> list[dict[str, Any]]:
        """Returns scheduled events whose start_at has arrived and hasn't been notified yet."""
        conn = self._get_connection()
        cur = conn.execute(
            """
            SELECT * FROM calendar_events 
            WHERE status = 'scheduled' 
              AND notified_start = 0 
              AND start_at <= ?
            ORDER BY start_at ASC
            """,
            (now_iso,),
        )
        return [dict(r) for r in cur.fetchall()]

    def mark_event_start_notified(self, event_id: int) -> None:
        """Marks event start as notified and updates status to 'active'."""
        conn = self._get_connection()
        now = datetime.now().isoformat()
        with conn:
            conn.execute(
                "UPDATE calendar_events SET notified_start = 1, status = 'active', updated_at = ? WHERE id = ?",
                (now, event_id),
            )

    def get_ending_calendar_events(self, now_iso: str) -> list[dict[str, Any]]:
        """Returns active events whose end_at has passed and wake_on_end is requested."""
        conn = self._get_connection()
        cur = conn.execute(
            """
            SELECT * FROM calendar_events 
            WHERE status IN ('active', 'in_progress') 
              AND end_at != '' 
              AND end_at <= ? 
              AND notified_end = 0
            ORDER BY end_at ASC
            """,
            (now_iso,),
        )
        return [dict(r) for r in cur.fetchall()]

    def mark_event_end_notified(self, event_id: int) -> None:
        """Marks event end as notified and marks it completed."""
        conn = self._get_connection()
        now = datetime.now().isoformat()
        with conn:
            conn.execute(
                "UPDATE calendar_events SET notified_end = 1, status = 'completed', updated_at = ? WHERE id = ?",
                (now, event_id),
            )

    def get_resource_status(self, resources: list[str] | None = None) -> list[dict[str, Any]]:
        """Returns the current busy/free status of hardware resources."""
        known_resources = resources or ["RTX_3080", "RTX_5070TI"]
        conn = self._get_connection()
        now = datetime.now().isoformat()
        result = []

        for res in known_resources:
            clean_res = res.strip().upper()
            cur = conn.execute(
                """
                SELECT * FROM calendar_events 
                WHERE UPPER(resource) = ? 
                  AND status NOT IN ('completed', 'cancelled')
                  AND start_at <= ? 
                  AND (end_at = '' OR end_at > ?)
                ORDER BY start_at ASC LIMIT 1
                """,
                (clean_res, now, now),
            )
            active_row = cur.fetchone()

            cur_next = conn.execute(
                """
                SELECT * FROM calendar_events 
                WHERE UPPER(resource) = ? 
                  AND status NOT IN ('completed', 'cancelled') 
                  AND start_at > ?
                ORDER BY start_at ASC LIMIT 1
                """,
                (clean_res, now),
            )
            next_row = cur_next.fetchone()

            if active_row:
                ev = dict(active_row)
                ev_data = {
                    "id": ev["id"],
                    "title": ev["title"],
                    "room_name": ev["room_name"],
                    "created_by": ev["created_by"],
                    "start_at": ev["start_at"],
                    "end_at": ev["end_at"],
                }
                result.append({
                    "resource": clean_res,
                    "available": False,
                    "is_busy": True,
                    "current_event": ev_data,
                    "active_event": ev_data,
                    "next_event": dict(next_row) if next_row else None,
                })
            else:
                result.append({
                    "resource": clean_res,
                    "available": True,
                    "is_busy": False,
                    "current_event": None,
                    "active_event": None,
                    "next_event": dict(next_row) if next_row else None,
                })
        return result

