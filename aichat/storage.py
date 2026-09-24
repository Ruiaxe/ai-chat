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

            # Backfill existing member tokens into member_identities
            try:
                conn.execute("""
                    INSERT OR IGNORE INTO member_identities (member_name, token, role, created_at)
                    SELECT member_name, token, role, joined_at FROM members WHERE token != '';
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
            "is_archived": False,
            "created_at": now,
        }

    def get_room(self, name: str) -> dict[str, Any] | None:
        """Fetches room information by name."""
        conn = self._get_connection()
        cursor = conn.execute(
            """
            SELECT id, name, topic, password_hash, salt, is_protected, COALESCE(is_archived, 0) as is_archived, created_at
            FROM rooms WHERE name = ? COLLATE NOCASE
            """,
            (name,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        res = dict(row)
        res["is_archived"] = bool(res.get("is_archived", 0))
        return res

    def update_room_password(
        self,
        room_name: str,
        password_hash: str,
        salt: str,
        is_protected: bool = True,
    ) -> None:
        """Updates room password hash and salt."""
        conn = self._get_connection()
        with conn:
            conn.execute(
                """
                UPDATE rooms 
                SET password_hash = ?, salt = ?, is_protected = ?
                WHERE name = ? COLLATE NOCASE
                """,
                (password_hash, salt, 1 if is_protected else 0, room_name.strip()),
            )

    def list_rooms(self, include_archived: bool = True) -> list[dict[str, Any]]:
        """Lists all rooms with member count, message count, and archived status."""
        conn = self._get_connection()
        query = """
            SELECT 
                r.id,
                r.name,
                r.topic,
                r.is_protected,
                COALESCE(r.is_archived, 0) as is_archived,
                r.created_at,
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
        conn = self._get_connection()
        with conn:
            cursor = conn.execute("UPDATE rooms SET is_archived = 1 WHERE name = ? COLLATE NOCASE", (name.strip(),))
            return cursor.rowcount > 0

    def unarchive_room(self, name: str) -> bool:
        """Restores an archived room to active state."""
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

        # 1. Check global member identity in member_identities table
        # Check existing member token in this room
        cursor = conn.execute(
            "SELECT token FROM members WHERE room_name = ? COLLATE NOCASE AND member_name = ? COLLATE NOCASE",
            (clean_room, clean_member),
        )
        row = cursor.fetchone()
        existing_token = row[0] if row and row[0] else ""

        clean_token = (token or "").strip()
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
        elif clean_token:
            final_token = clean_token
        elif clean_role == "agent" and generate_token:
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
                (clean_room, clean_member, clean_role, final_token, now, now),
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

        # Check global identity token
        cursor = conn.execute(
            "SELECT token FROM member_identities WHERE member_name = ? COLLATE NOCASE",
            (clean_member,),
        )
        id_row = cursor.fetchone()
        global_token = id_row[0] if id_row and id_row[0] else ""

        # Check room-specific token
        cursor = conn.execute(
            "SELECT token FROM members WHERE room_name = ? COLLATE NOCASE AND member_name = ? COLLATE NOCASE",
            (clean_room, clean_member),
        )
        row = cursor.fetchone()
        room_token = row[0] if row and row[0] else ""

        valid_tokens = [t for t in (global_token, room_token) if t]
        if not valid_tokens:
            # Unregistered sender without a registered token in the system
            return True, ""

        clean_token = (token or "").strip()
        if clean_token and any(secrets.compare_digest(clean_token, t) for t in valid_tokens):
            return True, ""
        return False, f"Impersonation blocked: Remetente '{clean_member}' é uma identidade protegida. Token fornecido é inválido ou está em falta."

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

    def rotate_member_token(self, room_name: str, member_name: str) -> str:
        """Generates a new secure token for a member, updating members and member_identities."""
        import secrets
        conn = self._get_connection()
        clean_room = room_name.strip()
        clean_member = member_name.strip()
        new_token = secrets.token_hex(16)
        now = datetime.now().isoformat()

        with conn:
            cursor = conn.execute(
                """
                UPDATE members
                SET token = ?, last_seen_at = ?
                WHERE room_name = ? COLLATE NOCASE AND member_name = ? COLLATE NOCASE
                """,
                (new_token, now, clean_room, clean_member),
            )
            if cursor.rowcount == 0:
                raise ValueError(f"Membro '{clean_member}' não está registado na sala '{clean_room}'.")

            conn.execute(
                """
                UPDATE member_identities
                SET token = ?
                WHERE member_name = ? COLLATE NOCASE
                """,
                (new_token, clean_member),
            )
        return new_token

    def log_audit_event(
        self,
        room_name: str,
        member_name: str,
        action: str,
        status: str,
        details: str = "",
    ) -> dict[str, Any]:
        """Logs a room security or membership event."""
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
    ) -> dict[str, Any]:
        """Saves a message to SQLite and appends to .log and .jsonl files."""
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
        created_by: str = "System",
    ) -> dict[str, Any]:
        """Creates a new task in a room."""
        clean_room = room_name.strip()
        clean_title = title.strip()
        if not clean_title:
            raise ValueError("O título da tarefa não pode estar vazio.")

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

        with conn:
            cursor = conn.execute(
                """
                INSERT INTO tasks (
                    room_name, title, description, status, assignee, waiting_for_agent,
                    priority, order_index, message_id, uses_gpu, gpu_est_min,
                    created_by, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    ) -> dict[str, Any]:
        """Updates fields of an existing task."""
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
        conn = self._get_connection()
        with conn:
            cursor = conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
            conn.execute("DELETE FROM task_history WHERE task_id = ?", (task_id,))
            return cursor.rowcount > 0

    def get_task_by_id(self, task_id: int) -> dict[str, Any] | None:
        """Retrieves a single task by ID with staleness computation and history."""
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
