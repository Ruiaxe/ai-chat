import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from aichat.config import DATA_DIR, LOGS_DIR

DB_PATH = DATA_DIR / "chat.db"


class ChatStorage:
    """Manages SQLite storage and file-based transcripts for chat rooms."""

    _local = threading.local()

    def __init__(self, db_path: Path = DB_PATH, logs_dir: Path = LOGS_DIR):
        self.db_path = Path(db_path)
        self.logs_dir = Path(logs_dir)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self._init_db()

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

    def _init_db(self) -> None:
        """Initializes database schema with tables and indexes."""
        conn = self._get_connection()
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS rooms (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL COLLATE NOCASE,
                    topic TEXT DEFAULT '',
                    password_hash TEXT DEFAULT '',
                    salt TEXT DEFAULT '',
                    is_protected INTEGER DEFAULT 0,
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

            # Auto-migrations for new features
            try:
                conn.execute("ALTER TABLE messages ADD COLUMN is_verified INTEGER DEFAULT 0;")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("ALTER TABLE members ADD COLUMN token TEXT DEFAULT '';")
            except sqlite3.OperationalError:
                pass

    def create_room(
        self,
        name: str,
        topic: str = "",
        password_hash: str = "",
        salt: str = "",
        is_protected: bool = False,
    ) -> dict[str, Any]:
        """Creates a new room in SQLite and prepares its log files."""
        now = datetime.now().isoformat()
        conn = self._get_connection()
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO rooms (name, topic, password_hash, salt, is_protected, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (name, topic, password_hash, salt, 1 if is_protected else 0, now),
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
            "created_at": now,
        }

    def get_room(self, name: str) -> dict[str, Any] | None:
        """Fetches room information by name."""
        conn = self._get_connection()
        cursor = conn.execute(
            """
            SELECT id, name, topic, password_hash, salt, is_protected, created_at
            FROM rooms WHERE name = ?
            """,
            (name,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return dict(row)

    def list_rooms(self) -> list[dict[str, Any]]:
        """Lists all rooms with member count and message count."""
        conn = self._get_connection()
        cursor = conn.execute("""
            SELECT 
                r.id,
                r.name,
                r.topic,
                r.is_protected,
                r.created_at,
                (SELECT COUNT(*) FROM messages m WHERE m.room_name = r.name) as message_count,
                (SELECT COUNT(*) FROM members mb WHERE mb.room_name = r.name) as member_count
            FROM rooms r
            ORDER BY r.id ASC
        """)
        return [dict(row) for row in cursor.fetchall()]

    def add_or_update_member(
        self,
        room_name: str,
        member_name: str,
        role: str,
        token: str | None = None,
        generate_token: bool = False,
    ) -> str:
        """Registers or refreshes a member in the room, assigning or preserving their authentication token."""
        now = datetime.now().isoformat()
        conn = self._get_connection()
        clean_room = room_name.strip()
        clean_member = member_name.strip()

        # Check existing member token
        cursor = conn.execute(
            "SELECT token FROM members WHERE room_name = ? COLLATE NOCASE AND member_name = ? COLLATE NOCASE",
            (clean_room, clean_member),
        )
        row = cursor.fetchone()
        existing_token = row[0] if row and row[0] else ""

        if token:
            final_token = token
        elif existing_token:
            final_token = existing_token
        elif role == "agent" and generate_token:
            import secrets
            final_token = secrets.token_hex(16)
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
                (clean_room, clean_member, role, final_token, now, now),
            )
        return final_token

    def verify_member_token(self, room_name: str, member_name: str, token: str) -> tuple[bool, str]:
        """
        Validates the member's authentication token.
        Returns (is_valid, error_msg).
        """
        import secrets
        conn = self._get_connection()
        clean_room = room_name.strip()
        clean_member = member_name.strip()
        cursor = conn.execute(
            "SELECT token, role FROM members WHERE room_name = ? COLLATE NOCASE AND member_name = ? COLLATE NOCASE",
            (clean_room, clean_member),
        )
        row = cursor.fetchone()
        if not row:
            # Member not explicitly registered yet
            return True, ""
        stored_token = row[0] or ""
        if not stored_token:
            # Legacy member without token
            return True, ""
        clean_token = (token or "").strip()
        if clean_token and secrets.compare_digest(clean_token, stored_token):
            return True, ""
        return False, f"Impersonation blocked: Remetente '{clean_member}' tem registo protegido nesta sala. Token fornecido é inválido ou está em falta."

    def get_member_rooms(self, member_name: str) -> list[str]:
        """Returns the list of room names a member has joined."""
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
    ) -> dict[str, Any]:
        """Saves a message to SQLite and appends to .log and .jsonl files."""
        now = datetime.now().isoformat()
        conn = self._get_connection()
        clean_room = room_name.strip()
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO messages (room_name, sender, role, content, is_verified, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (clean_room, sender, role, content, 1 if is_verified else 0, now),
            )
            msg_id = cursor.lastrowid

        msg_data = {
            "id": msg_id,
            "room_name": clean_room,
            "sender": sender,
            "role": role,
            "content": content,
            "is_verified": bool(is_verified),
            "created_at": now,
        }

        # Append to human-readable .log
        self._append_to_text_log(clean_room, msg_data)

        # Append to structured .jsonl
        self._append_to_jsonl_log(clean_room, msg_data)

        # Update member last_seen
        self.add_or_update_member(clean_room, sender, role)

        return msg_data

    def get_max_message_id(self, room_name: str) -> int:
        """Returns the highest message ID in the room, or 0 if empty."""
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT COALESCE(MAX(id), 0) FROM messages WHERE room_name = ? COLLATE NOCASE",
            (room_name.strip(),),
        )
        row = cursor.fetchone()
        return row[0] if row else 0

    def get_messages(
        self,
        room_name: str,
        since_id: int = 0,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """
        Retrieves messages for a room.
        If since_id > 0: returns messages strictly newer than since_id (ascending).
        If since_id == 0: returns the most recent `limit` messages in chronological order (ascending).
        """
        conn = self._get_connection()
        clean_room = room_name.strip()
        if since_id > 0:
            cursor = conn.execute(
                """
                SELECT id, room_name, sender, role, content, is_verified, created_at
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
                SELECT id, room_name, sender, role, content, is_verified, created_at
                FROM (
                    SELECT id, room_name, sender, role, content, is_verified, created_at
                    FROM messages
                    WHERE room_name = ? COLLATE NOCASE
                    ORDER BY id DESC
                    LIMIT ?
                )
                ORDER BY id ASC
                """,
                (clean_room, limit),
            )
        return [dict(row) for row in cursor.fetchall()]

    def get_room_log_file(self, room_name: str) -> Path:
        """Returns path to the text log file for the room."""
        # Sanitize filename
        safe_name = "".join(c for c in room_name if c.isalnum() or c in ("-", "_")).rstrip()
        return self.logs_dir / f"{safe_name or 'chat'}.log"

    def get_room_jsonl_file(self, room_name: str) -> Path:
        """Returns path to the JSONL log file for the room."""
        safe_name = "".join(c for c in room_name if c.isalnum() or c in ("-", "_")).rstrip()
        return self.logs_dir / f"{safe_name or 'chat'}.jsonl"

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
