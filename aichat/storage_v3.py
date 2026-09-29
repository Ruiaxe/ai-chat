"""
ai-chat v3 storage implementation.
Implements the contract defined in schema_v3.sql:
- Relational ID references everywhere (principals, rooms, messages, roles).
- Hashed secrets only (SHA-256 for agent tokens, scrypt for human passwords).
- Server-side room access control (room_access) and central authorization arbiter.
- Server-side read positions per principal and room (read_cursors).
- Structured message addressing (message_recipients).
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import threading
from typing import Any

from aichat.config import DATA_DIR, LOGS_DIR
from aichat.crypto import (
    hash_password,
    verify_password,
    new_agent_token,
    hash_token,
    token_hint,
    new_session_token,
    utc_now,
)

SCHEMA_FILE = Path(__file__).resolve().parent.parent / "migrations" / "v3" / "schema_v3.sql"
DEFAULT_V3_DB = DATA_DIR / "chat_v3.db"


class StorageV3:
    """Manages SQLite storage for ai-chat v3 according to schema_v3.sql."""

    _local = threading.local()

    def __init__(self, db_path: Path = DEFAULT_V3_DB, logs_dir: Path = LOGS_DIR):
        self.db_path = Path(db_path)
        self.logs_dir = Path(logs_dir)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Returns a thread-local SQLite connection with row_factory enabled and PRAGMAs set."""
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
        """Initializes database schema from schema_v3.sql if not already initialized."""
        conn = self._get_connection()
        has_schema = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version';"
        ).fetchone()
        if not has_schema:
            if not SCHEMA_FILE.exists():
                raise FileNotFoundError(f"schema_v3.sql not found at {SCHEMA_FILE}")
            schema_sql = SCHEMA_FILE.read_text(encoding="utf-8")
            with conn:
                conn.executescript(schema_sql)
                conn.execute(
                    "INSERT OR REPLACE INTO schema_version (version, applied_at, notes) VALUES (3, ?, 'ai-chat v3 schema');",
                    (utc_now(),),
                )

    # ------------------------------------------------------------------ Principals
    def create_principal(
        self,
        kind: str,
        name: str,
        display_name: str = "",
        status: str = "active",
        is_system: int = 0,
        is_legacy: int = 0,
    ) -> int:
        """Creates a new principal (human or agent). Returns principal id."""
        conn = self._get_connection()
        now = utc_now()
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO principals (kind, name, display_name, status, is_system, is_legacy, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (kind, name.strip(), display_name.strip() or name.strip(), status, is_system, is_legacy, now),
            )
            return cursor.lastrowid

    def get_principal_by_id(self, principal_id: int) -> dict[str, Any] | None:
        """Retrieves principal by ID, including human or agent details."""
        conn = self._get_connection()
        row = conn.execute(
            """
            SELECT p.*, 
                   h.access_role, h.must_change_password, h.failed_logins, h.locked_until, h.last_login_at,
                   a.default_role_id
            FROM principals p
            LEFT JOIN humans h ON p.id = h.principal_id
            LEFT JOIN agents a ON p.id = a.principal_id
            WHERE p.id = ?;
            """,
            (principal_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_principal_by_name(self, name: str) -> dict[str, Any] | None:
        """Retrieves principal by case-insensitive name."""
        conn = self._get_connection()
        row = conn.execute(
            """
            SELECT p.*, 
                   h.access_role, h.must_change_password, h.failed_logins, h.locked_until, h.last_login_at,
                   a.default_role_id
            FROM principals p
            LEFT JOIN humans h ON p.id = h.principal_id
            LEFT JOIN agents a ON p.id = a.principal_id
            WHERE p.name = ? COLLATE NOCASE;
            """,
            (name.strip(),),
        ).fetchone()
        return dict(row) if row else None

    def list_principals(self, kind: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
        """Lists principals with optional kind and status filters."""
        conn = self._get_connection()
        query = """
            SELECT p.*, 
                   h.access_role, h.must_change_password, h.failed_logins, h.locked_until, h.last_login_at,
                   a.default_role_id
            FROM principals p
            LEFT JOIN humans h ON p.id = h.principal_id
            LEFT JOIN agents a ON p.id = a.principal_id
            WHERE 1=1
        """
        params: list[Any] = []
        if kind:
            query += " AND p.kind = ?"
            params.append(kind)
        if status:
            query += " AND p.status = ?"
            params.append(status)
        query += " ORDER BY p.id ASC;"
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def update_principal_status(self, principal_id: int, status: str) -> bool:
        """Updates status of a principal ('active', 'inactive', 'pending')."""
        conn = self._get_connection()
        with conn:
            cursor = conn.execute(
                "UPDATE principals SET status = ? WHERE id = ?;",
                (status, principal_id),
            )
            return cursor.rowcount > 0

    # ------------------------------------------------------------------ Humans & Passwords
    def create_human(
        self,
        username: str,
        password: str,
        display_name: str = "",
        access_role: str = "user",
        must_change_password: int = 0,
    ) -> int:
        """Creates a new human principal and record in humans table. Returns principal id."""
        conn = self._get_connection()
        pwd_hash = hash_password(password) if password else ""
        with conn:
            pid = self.create_principal(
                kind="human",
                name=username,
                display_name=display_name or username,
                status="active",
            )
            conn.execute(
                """
                INSERT INTO humans (principal_id, access_role, password_hash, must_change_password)
                VALUES (?, ?, ?, ?);
                """,
                (pid, access_role, pwd_hash, must_change_password),
            )
            return pid

    def authenticate_human(self, username: str, password: str) -> tuple[dict[str, Any] | None, str | None]:
        """
        Authenticates a human user with username and scrypt password.
        Handles failed_logins count, locked_until lockout (15 min after 5 failures).
        Returns (principal_dict, error_message).
        """
        principal = self.get_principal_by_name(username)
        if not principal or principal["kind"] != "human":
            return None, "Utilizador ou palavra-passe incorretos"

        if principal["is_legacy"]:
            return None, "Utilizador legado não autorizado a iniciar sessão"

        if principal["status"] != "active":
            return None, f"Conta não ativa ({principal['status']})"

        conn = self._get_connection()
        human_row = conn.execute(
            "SELECT * FROM humans WHERE principal_id = ?;", (principal["id"],)
        ).fetchone()
        if not human_row:
            return None, "Registo de utilizador não encontrado"

        now_str = utc_now()

        # Check temporary lock
        if human_row["locked_until"]:
            if now_str < human_row["locked_until"]:
                return None, f"Conta temporariamente bloqueada até {human_row['locked_until']}"
            else:
                # Lock expired, reset
                with conn:
                    conn.execute(
                        "UPDATE humans SET locked_until = NULL, failed_logins = 0 WHERE principal_id = ?;",
                        (principal["id"],),
                    )

        # Check password
        stored_hash = human_row["password_hash"]
        if not stored_hash or not verify_password(password, stored_hash):
            failed = (human_row["failed_logins"] or 0) + 1
            locked_until_val = None
            if failed >= 5:
                # Lockout for 15 minutes
                lock_time = datetime.now(timezone.utc) + timedelta(minutes=15)
                locked_until_val = lock_time.strftime("%Y-%m-%dT%H:%M:%SZ")

            with conn:
                conn.execute(
                    "UPDATE humans SET failed_logins = ?, locked_until = ? WHERE principal_id = ?;",
                    (failed, locked_until_val, principal["id"]),
                )

            if locked_until_val:
                return None, "Demasiadas tentativas falhadas. Conta bloqueada por 15 minutos."
            return None, "Utilizador ou palavra-passe incorretos"

        # Password verified! Reset failed attempts and update last_login_at
        with conn:
            conn.execute(
                """
                UPDATE humans 
                SET failed_logins = 0, locked_until = NULL, last_login_at = ? 
                WHERE principal_id = ?;
                """,
                (now_str, principal["id"]),
            )

        # Refresh principal details
        return self.get_principal_by_id(principal["id"]), None

    def change_human_password(self, principal_id: int, new_password: str) -> bool:
        """Changes password for a human user and resets must_change_password to 0."""
        new_hash = hash_password(new_password)
        conn = self._get_connection()
        with conn:
            cursor = conn.execute(
                """
                UPDATE humans 
                SET password_hash = ?, must_change_password = 0 
                WHERE principal_id = ?;
                """,
                (new_hash, principal_id),
            )
            return cursor.rowcount > 0

    # ------------------------------------------------------------------ Human Sessions
    def create_human_session(self, principal_id: int, expires_hours: int = 24) -> str:
        """Creates a session for a human user and returns the raw session cookie value."""
        raw_token = new_session_token()
        s_hash = hash_token(raw_token)
        now = datetime.now(timezone.utc)
        created_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        expires_at = (now + timedelta(hours=expires_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

        conn = self._get_connection()
        with conn:
            conn.execute(
                """
                INSERT INTO human_sessions (session_hash, principal_id, created_at, expires_at, last_seen_at)
                VALUES (?, ?, ?, ?, ?);
                """,
                (s_hash, principal_id, created_at, expires_at, created_at),
            )
        return raw_token

    def authenticate_human_session(self, raw_token: str) -> dict[str, Any] | None:
        """Validates a raw session token, updates last_seen_at, and returns the principal dict."""
        if not raw_token:
            return None
        s_hash = hash_token(raw_token)
        now_str = utc_now()
        conn = self._get_connection()

        row = conn.execute(
            """
            SELECT s.*, p.kind, p.name, p.display_name, p.status, p.is_system, p.is_legacy,
                   h.access_role, h.must_change_password, h.locked_until
            FROM human_sessions s
            JOIN principals p ON s.principal_id = p.id
            JOIN humans h ON p.id = h.principal_id
            WHERE s.session_hash = ? AND s.expires_at > ?;
            """,
            (s_hash, now_str),
        ).fetchone()

        if not row:
            return None

        p = dict(row)
        if p["status"] != "active" or p["is_legacy"]:
            return None

        # Update last_seen_at
        with conn:
            conn.execute(
                "UPDATE human_sessions SET last_seen_at = ? WHERE session_hash = ?;",
                (now_str, s_hash),
            )

        return p

    def revoke_human_session(self, raw_token: str) -> bool:
        """Revokes a session by deleting it from human_sessions."""
        if not raw_token:
            return False
        s_hash = hash_token(raw_token)
        conn = self._get_connection()
        with conn:
            cursor = conn.execute("DELETE FROM human_sessions WHERE session_hash = ?;", (s_hash,))
            return cursor.rowcount > 0

    # ------------------------------------------------------------------ Agents & Credentials
    def create_agent(
        self,
        callsign: str,
        display_name: str = "",
        default_role_id: int | None = None,
        is_system: int = 0,
    ) -> tuple[int, str]:
        """
        Creates a new agent principal, record in agents table, and initial credential.
        Returns (principal_id, raw_agent_token).
        """
        conn = self._get_connection()
        token = new_agent_token()
        t_hash = hash_token(token)
        t_hint = token_hint(token)
        now_str = utc_now()

        with conn:
            pid = self.create_principal(
                kind="agent",
                name=callsign,
                display_name=display_name or callsign,
                status="active",
                is_system=is_system,
            )
            conn.execute(
                "INSERT INTO agents (principal_id, default_role_id) VALUES (?, ?);",
                (pid, default_role_id),
            )
            conn.execute(
                """
                INSERT INTO credentials (principal_id, token_hash, token_hint, created_at)
                VALUES (?, ?, ?, ?);
                """,
                (pid, t_hash, t_hint, now_str),
            )
            return pid, token

    def authenticate_agent_token(self, token: str) -> tuple[dict[str, Any] | None, str | None]:
        """
        Authenticates an agent by its raw token.
        Checks sha256 hash, non-revoked credential, active principal.
        Updates credentials.last_used_at.
        Returns (principal_dict, error_message).
        """
        if not token or not token.strip():
            return None, "Token de agente em falta"

        t_hash = hash_token(token.strip())
        conn = self._get_connection()
        row = conn.execute(
            """
            SELECT c.id as credential_id, c.token_hint, c.revoked_at,
                   p.id, p.kind, p.name, p.display_name, p.status, p.is_system, p.is_legacy,
                   a.default_role_id,
                   r.role_key as default_role_key, r.display_name as default_role_display
            FROM credentials c
            JOIN principals p ON c.principal_id = p.id
            LEFT JOIN agents a ON p.id = a.principal_id
            LEFT JOIN agent_roles r ON a.default_role_id = r.id
            WHERE c.token_hash = ?;
            """,
            (t_hash,),
        ).fetchone()

        if not row:
            return None, "Token de agente inválido ou não registado"

        cred = dict(row)
        if cred["revoked_at"]:
            return None, "Token de agente foi revogado"

        if cred["status"] != "active":
            return None, f"Agente não está ativo (status: {cred['status']})"

        if cred["is_legacy"]:
            return None, "Identidade legada não autorizada a operar"

        # Update last_used_at
        now_str = utc_now()
        with conn:
            conn.execute(
                "UPDATE credentials SET last_used_at = ? WHERE id = ?;",
                (now_str, cred["credential_id"]),
            )

        return cred, None

    def rotate_agent_token(self, principal_id: int, revoke_old: bool = True) -> tuple[str, str]:
        """
        Issues a new token for an agent.
        If revoke_old is True, marks existing credentials as revoked.
        Returns (new_raw_token, token_hint).
        """
        conn = self._get_connection()
        token = new_agent_token()
        t_hash = hash_token(token)
        t_hint = token_hint(token)
        now_str = utc_now()

        with conn:
            if revoke_old:
                conn.execute(
                    "UPDATE credentials SET revoked_at = ? WHERE principal_id = ? AND revoked_at IS NULL;",
                    (now_str, principal_id),
                )
            conn.execute(
                """
                INSERT INTO credentials (principal_id, token_hash, token_hint, created_at)
                VALUES (?, ?, ?, ?);
                """,
                (principal_id, t_hash, t_hint, now_str),
            )
            return token, t_hint

    def revoke_credential_by_hint(self, principal_id: int, hint: str) -> bool:
        """Revokes a credential identified by its 4-character hint."""
        conn = self._get_connection()
        now_str = utc_now()
        with conn:
            cursor = conn.execute(
                """
                UPDATE credentials 
                SET revoked_at = ? 
                WHERE principal_id = ? AND token_hint = ? AND revoked_at IS NULL;
                """,
                (now_str, principal_id, hint.strip()),
            )
            return cursor.rowcount > 0

    def list_agent_credentials(self, principal_id: int) -> list[dict[str, Any]]:
        """Lists credentials metadata for an agent (hints, dates, revoked status)."""
        conn = self._get_connection()
        rows = conn.execute(
            """
            SELECT id, token_hint, created_at, last_used_at, revoked_at
            FROM credentials
            WHERE principal_id = ?
            ORDER BY id DESC;
            """,
            (principal_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ Agent Roles
    def get_role_by_id(self, role_id: int) -> dict[str, Any] | None:
        """Gets an agent role by numeric ID."""
        conn = self._get_connection()
        row = conn.execute("SELECT * FROM agent_roles WHERE id = ?;", (role_id,)).fetchone()
        return dict(row) if row else None

    def get_role_by_key(self, role_key: str) -> dict[str, Any] | None:
        """Gets an agent role by key (e.g. 'developer')."""
        conn = self._get_connection()
        row = conn.execute("SELECT * FROM agent_roles WHERE role_key = ? COLLATE NOCASE;", (role_key.strip(),)).fetchone()
        return dict(row) if row else None

    def list_roles(self) -> list[dict[str, Any]]:
        """Lists all agent roles."""
        conn = self._get_connection()
        rows = conn.execute("SELECT * FROM agent_roles ORDER BY id ASC;").fetchall()
        return [dict(r) for r in rows]

    def update_role_reminder(self, role_id: int, reminder_text: str, updated_by_id: int | None = None) -> bool:
        """Updates reminder text for an agent role. Only admins should call this."""
        conn = self._get_connection()
        now_str = utc_now()
        with conn:
            cursor = conn.execute(
                """
                UPDATE agent_roles 
                SET reminder_text = ?, updated_at = ?, updated_by = ?
                WHERE id = ?;
                """,
                (reminder_text.strip(), now_str, updated_by_id, role_id),
            )
            return cursor.rowcount > 0

    # ------------------------------------------------------------------ Rooms & Room Access
    def create_room(self, name: str, topic: str = "", created_by_id: int | None = None) -> dict[str, Any]:
        """Creates a new room. Access is strictly controlled via room_access."""
        conn = self._get_connection()
        now_str = utc_now()
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO rooms (name, topic, is_archived, created_at, created_by)
                VALUES (?, ?, 0, ?, ?);
                """,
                (name.strip(), topic.strip(), now_str, created_by_id),
            )
            room_id = cursor.lastrowid

            # If created by a principal, grant that creator access automatically
            if created_by_id:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO room_access (room_id, principal_id, role_id, can_write, granted_by, granted_at)
                    VALUES (?, ?, NULL, 1, ?, ?);
                    """,
                    (room_id, created_by_id, created_by_id, now_str),
                )

        return self.get_room_by_id(room_id)  # type: ignore

    def get_room_by_id(self, room_id: int) -> dict[str, Any] | None:
        """Gets room by numeric ID."""
        conn = self._get_connection()
        row = conn.execute("SELECT * FROM rooms WHERE id = ?;", (room_id,)).fetchone()
        return dict(row) if row else None

    def get_room_by_name(self, name: str) -> dict[str, Any] | None:
        """Gets room by case-insensitive name."""
        conn = self._get_connection()
        row = conn.execute("SELECT * FROM rooms WHERE name = ? COLLATE NOCASE;", (name.strip(),)).fetchone()
        return dict(row) if row else None

    def list_rooms(self, include_archived: bool = False) -> list[dict[str, Any]]:
        """Lists all rooms (admin view)."""
        conn = self._get_connection()
        query = "SELECT * FROM rooms WHERE 1=1"
        if not include_archived:
            query += " AND is_archived = 0"
        query += " ORDER BY id ASC;"
        rows = conn.execute(query).fetchall()
        return [dict(r) for r in rows]

    def archive_room(self, room_id: int) -> bool:
        """Marks a room as archived."""
        conn = self._get_connection()
        with conn:
            cursor = conn.execute("UPDATE rooms SET is_archived = 1 WHERE id = ?;", (room_id,))
            return cursor.rowcount > 0

    def grant_room_access(
        self,
        room_id: int,
        principal_id: int,
        role_id: int | None = None,
        can_write: int = 1,
        granted_by_id: int | None = None,
    ) -> None:
        """Grants or updates room access for a principal with specific role and write permission."""
        conn = self._get_connection()
        now_str = utc_now()
        with conn:
            conn.execute(
                """
                INSERT INTO room_access (room_id, principal_id, role_id, can_write, granted_by, granted_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(room_id, principal_id) DO UPDATE SET
                    role_id = excluded.role_id,
                    can_write = excluded.can_write,
                    granted_by = excluded.granted_by,
                    granted_at = excluded.granted_at;
                """,
                (room_id, principal_id, role_id, can_write, granted_by_id, now_str),
            )

    def revoke_room_access(self, room_id: int, principal_id: int) -> bool:
        """Revokes a principal's access to a room."""
        conn = self._get_connection()
        with conn:
            cursor = conn.execute(
                "DELETE FROM room_access WHERE room_id = ? AND principal_id = ?;",
                (room_id, principal_id),
            )
            return cursor.rowcount > 0

    def get_room_access(self, room_id: int, principal_id: int) -> dict[str, Any] | None:
        """Retrieves access details for a principal in a room."""
        conn = self._get_connection()
        row = conn.execute(
            """
            SELECT ra.*, r.role_key, r.display_name as role_display_name, r.reminder_text
            FROM room_access ra
            LEFT JOIN agent_roles r ON ra.role_id = r.id
            WHERE ra.room_id = ? AND ra.principal_id = ?;
            """,
            (room_id, principal_id),
        ).fetchone()
        return dict(row) if row else None

    def list_room_members(self, room_id: int) -> list[dict[str, Any]]:
        """Lists all principals granted access to a room with their roles and write permissions."""
        conn = self._get_connection()
        rows = conn.execute(
            """
            SELECT ra.*, p.kind, p.name, p.display_name, p.status, p.is_system,
                   r.role_key, r.display_name as role_display_name, r.reminder_text
            FROM room_access ra
            JOIN principals p ON ra.principal_id = p.id
            LEFT JOIN agent_roles r ON ra.role_id = r.id
            WHERE ra.room_id = ?
            ORDER BY p.name ASC;
            """,
            (room_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def list_rooms_for_principal(self, principal: dict[str, Any], include_archived: bool = False) -> list[dict[str, Any]]:
        """
        Lists rooms accessible to a principal.
        Admins see all non-archived rooms.
        Regular users and agents only see rooms present in room_access.
        """
        conn = self._get_connection()
        pid = principal["id"]
        is_admin = principal.get("kind") == "human" and principal.get("access_role") == "admin"

        if is_admin:
            query = """
                SELECT r.*, 1 as can_write, NULL as role_id, NULL as role_key, NULL as role_display_name
                FROM rooms r
                WHERE 1=1
            """
            if not include_archived:
                query += " AND r.is_archived = 0"
            query += " ORDER BY r.name ASC;"
            rows = conn.execute(query).fetchall()
            return [dict(row) for row in rows]

        # Regular user or agent
        query = """
            SELECT r.*, ra.can_write, ra.role_id, ar.role_key, ar.display_name as role_display_name
            FROM rooms r
            JOIN room_access ra ON r.id = ra.room_id
            LEFT JOIN agent_roles ar ON ra.role_id = ar.id
            WHERE ra.principal_id = ?
        """
        if not include_archived:
            query += " AND r.is_archived = 0"
        query += " ORDER BY r.name ASC;"
        rows = conn.execute(query, (pid,)).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------------ Central Authorization
    def authorize(self, principal: dict[str, Any] | None, action: str, resource: dict[str, Any] | None = None) -> bool:
        """
        Central authorization arbiter across MCP, REST, and WebSockets.
        Actions:
          - 'admin': requires active human admin.
          - 'read_room': requires room access or admin.
          - 'write_room': requires room access with can_write=1 or admin.
          - 'manage_room': requires admin or room creator.
          - 'manage_poll': requires admin or poll creator.
        """
        if not principal:
            return False

        if principal.get("status") != "active" or principal.get("is_legacy"):
            return False

        is_admin = principal.get("kind") == "human" and principal.get("access_role") == "admin"

        if action == "admin":
            return is_admin

        if is_admin:
            return True

        if action in ("read_room", "write_room"):
            if not resource or "room_id" not in resource:
                return False
            access = self.get_room_access(resource["room_id"], principal["id"])
            if not access:
                return False
            if action == "write_room" and not access.get("can_write", 1):
                return False
            return True

        if action == "manage_room":
            if not resource or "room_id" not in resource:
                return False
            room = self.get_room_by_id(resource["room_id"])
            if not room:
                return False
            return room.get("created_by") == principal["id"]

        if action == "manage_poll":
            if not resource or "creator_id" not in resource:
                return False
            return resource.get("creator_id") == principal["id"]

        return False

    # ------------------------------------------------------------------ Read Cursors
    def get_read_cursor(self, principal_id: int, room_id: int) -> int:
        """Gets the last read message ID for a principal in a room."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT last_message_id FROM read_cursors WHERE principal_id = ? AND room_id = ?;",
            (principal_id, room_id),
        ).fetchone()
        return int(row["last_message_id"]) if row else 0

    def update_read_cursor(self, principal_id: int, room_id: int, message_id: int) -> None:
        """Updates the read position for a principal in a room."""
        conn = self._get_connection()
        now_str = utc_now()
        with conn:
            conn.execute(
                """
                INSERT INTO read_cursors (principal_id, room_id, last_message_id, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(principal_id, room_id) DO UPDATE SET
                    last_message_id = MAX(read_cursors.last_message_id, excluded.last_message_id),
                    updated_at = excluded.updated_at;
                """,
                (principal_id, room_id, message_id, now_str),
            )

    # ------------------------------------------------------------------ Messages & Addressing
    def add_message(
        self,
        room_id: int,
        sender: dict[str, Any] | None,
        content: str,
        message_type: str = "text",
        metadata: dict[str, Any] | None = None,
        is_verified: int = 1,
        recipients: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """
        Adds a message to a room.
        recipients is a list of target dicts:
          - [{"target_kind": "all"}]
          - [{"target_kind": "role", "target_id": <role_id>}]
          - [{"target_kind": "principal", "target_id": <principal_id>}]
        If recipients is None or empty, defaults to target_kind='all'.
        """
        conn = self._get_connection()
        now_str = utc_now()
        sender_id = sender["id"] if sender else None
        sender_kind = sender.get("kind", "system") if sender else "system"
        sender_name = sender.get("display_name") or sender.get("name") or "System" if sender else "System"
        meta_json = json.dumps(metadata or {}, ensure_ascii=False)

        with conn:
            cursor = conn.execute(
                """
                INSERT INTO messages (room_id, sender_id, sender_kind, sender_name, content, message_type, metadata, is_verified, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (room_id, sender_id, sender_kind, sender_name, content, message_type, meta_json, is_verified, now_str),
            )
            msg_id = cursor.lastrowid

            # Handle recipients
            target_list = recipients if recipients else [{"target_kind": "all", "target_id": None}]
            for r in target_list:
                t_kind = r.get("target_kind", "all")
                t_id = r.get("target_id") if t_kind != "all" else None
                conn.execute(
                    """
                    INSERT INTO message_recipients (message_id, target_kind, target_id)
                    VALUES (?, ?, ?);
                    """,
                    (msg_id, t_kind, t_id),
                )

            # Auto-advance sender's read cursor
            if sender_id:
                self.update_read_cursor(sender_id, room_id, msg_id)

        return self.get_message_by_id(msg_id)  # type: ignore

    def get_message_by_id(self, message_id: int) -> dict[str, Any] | None:
        """Gets a message by numeric ID with its recipients and reactions."""
        conn = self._get_connection()
        row = conn.execute("SELECT * FROM messages WHERE id = ?;", (message_id,)).fetchone()
        if not row:
            return None
        msg = dict(row)
        msg["metadata"] = json.loads(msg["metadata"]) if msg["metadata"] else {}

        # Fetch recipients
        r_rows = conn.execute("SELECT target_kind, target_id FROM message_recipients WHERE message_id = ?;", (message_id,)).fetchall()
        msg["recipients"] = [dict(r) for r in r_rows]

        # Fetch reactions
        rx_rows = conn.execute("SELECT emoji, principal_id FROM reactions WHERE message_id = ?;", (message_id,)).fetchall()
        rx_dict: dict[str, list[int]] = {}
        for rx in rx_rows:
            rx_dict.setdefault(rx["emoji"], []).append(rx["principal_id"])
        msg["reactions"] = rx_dict
        return msg

    def get_messages(
        self,
        room_id: int,
        since_id: int = 0,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Retrieves messages in a room since a message ID up to limit."""
        conn = self._get_connection()
        rows = conn.execute(
            """
            SELECT * FROM messages
            WHERE room_id = ? AND id > ?
            ORDER BY id ASC
            LIMIT ?;
            """,
            (room_id, since_id, limit),
        ).fetchall()

        result = []
        for r in rows:
            m = dict(r)
            m["metadata"] = json.loads(m["metadata"]) if m["metadata"] else {}
            result.append(m)
        return result

    # ------------------------------------------------------------------ Audit Log
    def log_audit(
        self,
        actor_id: int | None,
        actor_name: str,
        action: str,
        target_type: str = "",
        target_id: int | None = None,
        room_id: int | None = None,
        status: str = "ok",
        details: str = "",
    ) -> None:
        """Records an entry in the v3 audit log."""
        conn = self._get_connection()
        now_str = utc_now()
        with conn:
            conn.execute(
                """
                INSERT INTO audit_log (actor_id, actor_name, action, target_type, target_id, room_id, status, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (actor_id, actor_name, action, target_type, target_id, room_id, status, details, now_str),
            )
