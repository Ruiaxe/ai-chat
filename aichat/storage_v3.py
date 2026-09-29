"""
ai-chat v3 storage implementation.
Implements the contract defined in schema_v3.sql:
- Relational ID references everywhere (principals, rooms, messages, roles).
- Hashed secrets only (SHA-256 for agent tokens, scrypt for human passwords).
- Server-side room access control (room_access) and central authorization arbiter.
- Server-side read positions per principal and room (read_cursors).
- Structured message addressing (message_recipients).
- Full tasks, dependencies, reactions, polls, and calendar events by IDs.
"""
from __future__ import annotations

import json
import time
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
    """Complete SQLite storage layer for ai-chat v3 according to schema_v3.sql."""

    _local = threading.local()
    _failed_ip_attempts: dict[str, list[float]] = {}  # IP -> list of failure timestamps
    _ip_lock = threading.Lock()

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

    # ------------------------------------------------------------------ Resolvers
    def _resolve_room(self, room_id_or_name: int | str | dict[str, Any]) -> dict[str, Any] | None:
        if isinstance(room_id_or_name, dict):
            if "id" in room_id_or_name:
                return room_id_or_name
            room_id_or_name = room_id_or_name.get("name", "")
        if isinstance(room_id_or_name, int) or (isinstance(room_id_or_name, str) and room_id_or_name.isdigit()):
            return self.get_room_by_id(int(room_id_or_name))
        return self.get_room_by_name(str(room_id_or_name))

    def _resolve_principal(self, principal_id_or_name: int | str | dict[str, Any] | None) -> dict[str, Any] | None:
        if principal_id_or_name is None:
            return None
        if isinstance(principal_id_or_name, dict):
            if "id" in principal_id_or_name:
                return principal_id_or_name
            principal_id_or_name = principal_id_or_name.get("name", "")
        if isinstance(principal_id_or_name, int) or (isinstance(principal_id_or_name, str) and principal_id_or_name.isdigit()):
            return self.get_principal_by_id(int(principal_id_or_name))
        return self.get_principal_by_name(str(principal_id_or_name))

    # ------------------------------------------------------------------ Admin Protection Safeguards
    def _is_last_active_admin(self, principal_id: int) -> bool:
        """Checks whether the given principal is the sole active human admin."""
        conn = self._get_connection()
        row = conn.execute(
            """
            SELECT COUNT(*) as cnt
            FROM humans h
            JOIN principals p ON h.principal_id = p.id
            WHERE h.access_role = 'admin' AND p.status = 'active';
            """
        ).fetchone()
        total_active_admins = row["cnt"] if row else 0
        if total_active_admins <= 1:
            target_row = conn.execute(
                """
                SELECT 1 FROM humans h
                JOIN principals p ON h.principal_id = p.id
                WHERE p.id = ? AND h.access_role = 'admin' AND p.status = 'active';
                """,
                (principal_id,),
            ).fetchone()
            if target_row:
                return True
        return False

    def _ensure_not_last_active_admin(self, principal_id: int, action_verb: str = "alterar") -> None:
        if self._is_last_active_admin(principal_id):
            raise ValueError(f"Operação recusada: não é possível {action_verb} o único administrador ativo do sistema.")

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
        now_str = utc_now()
        clean_name = name.strip()
        disp = display_name.strip() if display_name else clean_name
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO principals (kind, name, display_name, status, is_system, is_legacy, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (kind, clean_name, disp, status, is_system, is_legacy, now_str),
            )
            return cursor.lastrowid

    def get_principal_by_id(self, principal_id: int) -> dict[str, Any] | None:
        """Retrieves principal by ID with joined human/agent data."""
        conn = self._get_connection()
        row = conn.execute(
            """
            SELECT p.*, 
                   h.access_role, h.must_change_password, h.failed_logins, h.locked_until, h.last_login_at,
                   a.default_role_id, ar.role_key as default_role_key
            FROM principals p
            LEFT JOIN humans h ON p.id = h.principal_id
            LEFT JOIN agents a ON p.id = a.principal_id
            LEFT JOIN agent_roles ar ON a.default_role_id = ar.id
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
                   a.default_role_id, ar.role_key as default_role_key
            FROM principals p
            LEFT JOIN humans h ON p.id = h.principal_id
            LEFT JOIN agents a ON p.id = a.principal_id
            LEFT JOIN agent_roles ar ON a.default_role_id = ar.id
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
                   a.default_role_id, ar.role_key as default_role_key
            FROM principals p
            LEFT JOIN humans h ON p.id = h.principal_id
            LEFT JOIN agents a ON p.id = a.principal_id
            LEFT JOIN agent_roles ar ON a.default_role_id = ar.id
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
        """Updates status of a principal ('active', 'inactive', 'pending'). Protects last admin."""
        if status != "active":
            self._ensure_not_last_active_admin(principal_id, "desativar")
        conn = self._get_connection()
        with conn:
            cursor = conn.execute(
                "UPDATE principals SET status = ? WHERE id = ?;",
                (status, principal_id),
            )
            return cursor.rowcount > 0

    def delete_principal(self, principal_id: int) -> bool:
        """Deletes a principal. Protects last admin."""
        self._ensure_not_last_active_admin(principal_id, "remover")
        conn = self._get_connection()
        with conn:
            cursor = conn.execute("DELETE FROM principals WHERE id = ?;", (principal_id,))
            return cursor.rowcount > 0

    # ------------------------------------------------------------------ Humans & Passwords
    def create_human(
        self,
        username: str,
        password: str,
        display_name: str = "",
        access_role: str = "user",
        must_change_password: int = 1,
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

    def update_human_role(self, principal_id: int, access_role: str) -> bool:
        """Updates human access role ('admin' or 'user'). Protects last admin."""
        if access_role != "admin":
            self._ensure_not_last_active_admin(principal_id, "despromover")
        conn = self._get_connection()
        with conn:
            cursor = conn.execute(
                "UPDATE humans SET access_role = ? WHERE principal_id = ?;",
                (access_role, principal_id),
            )
            return cursor.rowcount > 0

    def _record_ip_failure(self, client_ip: str | None) -> None:
        if not client_ip:
            return
        now = time.time()
        with self._ip_lock:
            attempts = self._failed_ip_attempts.setdefault(client_ip, [])
            attempts.append(now)
            # Purge older than 15 minutes (900s)
            self._failed_ip_attempts[client_ip] = [t for t in attempts if now - t < 900]

    def _is_ip_locked(self, client_ip: str | None) -> bool:
        if not client_ip:
            return False
        now = time.time()
        with self._ip_lock:
            attempts = [t for t in self._failed_ip_attempts.get(client_ip, []) if now - t < 900]
            self._failed_ip_attempts[client_ip] = attempts
            return len(attempts) >= 5

    def _clear_ip_failures(self, client_ip: str | None) -> None:
        if not client_ip:
            return
        with self._ip_lock:
            self._failed_ip_attempts.pop(client_ip, None)

    def authenticate_human(
        self,
        username: str,
        password: str,
        client_ip: str | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        """
        Authenticates a human user with username and scrypt password.
        Handles failed_logins count, locked_until lockout (15 min after 5 failures),
        and IP rate-limiting. Emits uniform error messages to prevent enumeration.
        """
        # 1. Check IP lockout
        if self._is_ip_locked(client_ip):
            return None, "Conta temporariamente bloqueada por excesso de tentativas falhadas. Tente novamente mais tarde."

        principal = self.get_principal_by_name(username)
        if not principal or principal["kind"] != "human":
            self._record_ip_failure(client_ip)
            return None, "Credenciais inválidas: utilizador ou palavra-passe incorretos."

        if principal.get("is_legacy"):
            return None, "Credenciais inválidas: utilizador legado sem credenciais ativas."

        if principal["status"] != "active":
            return None, "Conta inativa ou suspensa"

        conn = self._get_connection()
        human_row = conn.execute(
            "SELECT * FROM humans WHERE principal_id = ?;", (principal["id"],)
        ).fetchone()
        if not human_row:
            self._record_ip_failure(client_ip)
            return None, "Credenciais inválidas: utilizador ou palavra-passe incorretos."

        now_str = utc_now()

        # Check temporary account lock
        if human_row["locked_until"]:
            if now_str < human_row["locked_until"]:
                return None, "Conta temporariamente bloqueada por excesso de tentativas falhadas. Tente novamente mais tarde."
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
            self._record_ip_failure(client_ip)
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
                return None, "Conta temporariamente bloqueada por excesso de tentativas falhadas. Tente novamente mais tarde."
            return None, "Credenciais inválidas: utilizador ou palavra-passe incorretos."

        # Password verified! Reset failed attempts and update last_login_at
        self._clear_ip_failures(client_ip)
        with conn:
            conn.execute(
                """
                UPDATE humans 
                SET failed_logins = 0, locked_until = NULL, last_login_at = ? 
                WHERE principal_id = ?;
                """,
                (now_str, principal["id"]),
            )

        return self.get_principal_by_id(principal["id"]), None

    def change_human_password(self, principal_id: int, new_password: str) -> bool:
        """Updates human password with a new scrypt hash and clears must_change_password."""
        if not new_password:
            raise ValueError("Password cannot be empty")
        pwd_hash = hash_password(new_password)
        conn = self._get_connection()
        with conn:
            cursor = conn.execute(
                """
                UPDATE humans 
                SET password_hash = ?, must_change_password = 0, failed_logins = 0, locked_until = NULL
                WHERE principal_id = ?;
                """,
                (pwd_hash, principal_id),
            )
            return cursor.rowcount > 0

    def create_human_session(
        self,
        principal_id: int,
        ttl_seconds: int = 86400 * 30,
        expires_hours: int | None = None,
    ) -> str:
        """Creates a new human session and stores session_hash in human_sessions. Returns raw session token."""
        if expires_hours is not None:
            ttl_seconds = int(expires_hours * 3600)
        raw_token = new_session_token()
        sess_hash = hash_token(raw_token)
        now = datetime.now(timezone.utc)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        expires_str = (now + timedelta(seconds=ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

        conn = self._get_connection()
        with conn:
            conn.execute(
                """
                INSERT INTO human_sessions (session_hash, principal_id, created_at, expires_at, last_seen_at)
                VALUES (?, ?, ?, ?, ?);
                """,
                (sess_hash, principal_id, now_str, expires_str, now_str),
            )
        return raw_token

    def authenticate_human_session(self, raw_session_token: str) -> dict[str, Any] | None:
        """Validates a raw session token against human_sessions. Returns principal or None."""
        if not raw_session_token:
            return None
        sess_hash = hash_token(raw_session_token.strip())
        conn = self._get_connection()
        now_str = utc_now()
        row = conn.execute(
            """
            SELECT s.*, p.name, p.display_name, p.status, p.is_legacy,
                   h.access_role, h.must_change_password
            FROM human_sessions s
            JOIN principals p ON s.principal_id = p.id
            JOIN humans h ON p.id = h.principal_id
            WHERE s.session_hash = ? AND s.expires_at > ?;
            """,
            (sess_hash, now_str),
        ).fetchone()

        if not row:
            return None

        # Update last_seen_at
        with conn:
            conn.execute(
                "UPDATE human_sessions SET last_seen_at = ? WHERE session_hash = ?;",
                (now_str, sess_hash),
            )

        return self.get_principal_by_id(row["principal_id"])

    def revoke_human_session(self, raw_session_token: str) -> None:
        """Deletes session from human_sessions."""
        if not raw_session_token:
            return
        sess_hash = hash_token(raw_session_token.strip())
        conn = self._get_connection()
        with conn:
            conn.execute("DELETE FROM human_sessions WHERE session_hash = ?;", (sess_hash,))

    # ------------------------------------------------------------------ Agents & Credentials
    def create_agent(
        self,
        callsign: str,
        display_name: str = "",
        role_key: str | None = None,
        is_system: int = 0,
        status: str = "active",
        default_role_id: int | None = None,
    ) -> tuple[int, str]:
        """
        Creates an agent principal, agents row, and initial credential.
        Returns (principal_id, raw_agent_token).
        """
        conn = self._get_connection()
        now_str = utc_now()
        clean_callsign = callsign.strip()

        target_role_id = default_role_id
        if target_role_id is None and role_key:
            role = self.get_role_by_key(role_key)
            if role:
                target_role_id = role["id"]

        with conn:
            pid = self.create_principal(
                kind="agent",
                name=clean_callsign,
                display_name=display_name or clean_callsign,
                status=status,
                is_system=is_system,
            )
            conn.execute(
                "INSERT INTO agents (principal_id, default_role_id) VALUES (?, ?);",
                (pid, target_role_id),
            )
            raw_token = new_agent_token()
            t_hash = hash_token(raw_token)
            t_hint = token_hint(raw_token)
            conn.execute(
                """
                INSERT INTO credentials (principal_id, token_hash, token_hint, created_at)
                VALUES (?, ?, ?, ?);
                """,
                (pid, t_hash, t_hint, now_str),
            )
            return pid, raw_token

    def authenticate_agent_token(self, token: str) -> tuple[dict[str, Any] | None, str | None]:
        """
        Authenticates an agent token against credentials.
        Returns (principal_dict, error_message).
        """
        clean_token = (token or "").strip()
        if not clean_token:
            return None, "Token não fornecido"

        t_hash = hash_token(clean_token)
        conn = self._get_connection()
        row = conn.execute(
            """
            SELECT c.*, p.id as p_id, p.name, p.display_name, p.status, p.is_system, p.is_legacy,
                   a.default_role_id, ar.role_key as default_role_key
            FROM credentials c
            JOIN principals p ON c.principal_id = p.id
            LEFT JOIN agents a ON p.id = a.principal_id
            LEFT JOIN agent_roles ar ON a.default_role_id = ar.id
            WHERE c.token_hash = ?;
            """,
            (t_hash,),
        ).fetchone()

        if not row:
            return None, "Token de agente inválido"

        if row["revoked_at"]:
            return None, f"Token revogado em {row['revoked_at']}"

        if row["status"] != "active":
            return None, f"Agente '{row['name']}' não está ativo (status='{row['status']}')"

        if row["is_legacy"]:
            return None, "Identidade legada sem credenciais ativas"

        now_str = utc_now()
        with conn:
            conn.execute(
                "UPDATE credentials SET last_used_at = ? WHERE id = ?;",
                (now_str, row["id"]),
            )

        return self.get_principal_by_id(row["p_id"]), None

    def rotate_agent_token(
        self,
        principal_id: int,
        revoke_old: bool = True,
        revoke_previous: bool | None = None,
    ) -> tuple[str, str]:
        """Generates a new token for an agent. Optionally revokes previous active tokens. Returns (token, hint)."""
        should_revoke = revoke_previous if revoke_previous is not None else revoke_old
        raw_token = new_agent_token()
        t_hash = hash_token(raw_token)
        t_hint = token_hint(raw_token)
        now_str = utc_now()

        conn = self._get_connection()
        with conn:
            if should_revoke:
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
        return raw_token, t_hint

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
        """Lists metadata of all credentials for an agent (token_hint, created_at, last_used_at, revoked_at)."""
        conn = self._get_connection()
        rows = conn.execute(
            """
            SELECT id, principal_id, token_hint, created_at, last_used_at, revoked_at
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
    def create_room(self, name: str, topic: str = "", created_by_id: int | None = None, created_by: int | None = None) -> dict[str, Any]:
        """Creates a new room. Access is strictly controlled via room_access."""
        actual_creator = created_by_id if created_by_id is not None else created_by
        conn = self._get_connection()
        now_str = utc_now()
        clean_name = name.strip()
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO rooms (name, topic, is_archived, created_at, created_by)
                VALUES (?, ?, 0, ?, ?);
                """,
                (clean_name, topic.strip(), now_str, actual_creator),
            )
            room_id = cursor.lastrowid

            # If created by a principal, grant that creator access automatically
            if actual_creator:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO room_access (room_id, principal_id, role_id, can_write, granted_by, granted_at)
                    VALUES (?, ?, NULL, 1, ?, ?);
                    """,
                    (room_id, actual_creator, actual_creator, now_str),
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO read_cursors (principal_id, room_id, last_message_id, updated_at)
                    VALUES (?, ?, 0, ?);
                    """,
                    (actual_creator, room_id, now_str),
                )

        return self.get_room_by_id(room_id)  # type: ignore

    def get_room(self, room_id_or_name: int | str) -> dict[str, Any] | None:
        """Gets room by either integer ID or name."""
        return self._resolve_room(room_id_or_name)

    def get_room_by_id(self, room_id: int) -> dict[str, Any] | None:
        """Gets room by numeric ID with member count."""
        conn = self._get_connection()
        row = conn.execute(
            """
            SELECT r.*,
                   (SELECT COUNT(*) FROM room_access ra WHERE ra.room_id = r.id) as member_count
            FROM rooms r WHERE r.id = ?;
            """,
            (room_id,),
        ).fetchone()
        if not row:
            return None
        res = dict(row)
        res["is_protected"] = False
        return res

    def get_room_by_name(self, name: str) -> dict[str, Any] | None:
        """Gets room by case-insensitive name with member count."""
        conn = self._get_connection()
        row = conn.execute(
            """
            SELECT r.*,
                   (SELECT COUNT(*) FROM room_access ra WHERE ra.room_id = r.id) as member_count
            FROM rooms r WHERE r.name = ? COLLATE NOCASE;
            """,
            (name.strip(),),
        ).fetchone()
        if not row:
            return None
        res = dict(row)
        res["is_protected"] = False
        return res

    def list_rooms(self, include_archived: bool = False) -> list[dict[str, Any]]:
        """Lists all rooms (admin view)."""
        conn = self._get_connection()
        query = """
            SELECT r.*,
                   (SELECT COUNT(*) FROM room_access ra WHERE ra.room_id = r.id) as member_count
            FROM rooms r WHERE 1=1
        """
        if not include_archived:
            query += " AND r.is_archived = 0"
        query += " ORDER BY r.name ASC;"
        rows = conn.execute(query).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["is_protected"] = False
            result.append(d)
        return result

    def archive_room(self, room_id_or_name: int | str) -> bool:
        """Marks a room as archived."""
        room = self._resolve_room(room_name_or_id if (room_name_or_id := room_id_or_name) else "")
        if not room:
            return False
        conn = self._get_connection()
        with conn:
            cursor = conn.execute("UPDATE rooms SET is_archived = 1 WHERE id = ?;", (room["id"],))
            return cursor.rowcount > 0

    def unarchive_room(self, room_id_or_name: int | str) -> bool:
        """Unarchives a room."""
        room = self._resolve_room(room_id_or_name)
        if not room:
            return False
        conn = self._get_connection()
        with conn:
            cursor = conn.execute("UPDATE rooms SET is_archived = 0 WHERE id = ?;", (room["id"],))
            return cursor.rowcount > 0

    def grant_room_access(
        self,
        room_id: int | str | dict[str, Any],
        principal_id: int | str | dict[str, Any],
        role_id: int | None = None,
        can_write: int = 1,
        granted_by_id: int | None = None,
    ) -> None:
        """Grants or updates room access for a principal with specific role and write permission."""
        room = self._resolve_room(room_id)
        if not room:
            raise ValueError(f"Sala '{room_id}' não encontrada.")
        principal = self._resolve_principal(principal_id)
        if not principal:
            raise ValueError(f"Principal '{principal_id}' não encontrado.")
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
                (room["id"], principal["id"], role_id, can_write, granted_by_id, now_str),
            )
            max_mid = self.get_max_message_id(room["id"])
            conn.execute(
                """
                INSERT OR IGNORE INTO read_cursors (principal_id, room_id, last_message_id, updated_at)
                VALUES (?, ?, ?, ?);
                """,
                (principal["id"], room["id"], max_mid, now_str),
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

    def get_room_humans(self, room_name_or_id: int | str) -> list[dict[str, Any]]:
        """
        Returns all human principals who have access to this room,
        including principals with explicit room_access and global human admins.
        """
        room = self._resolve_room(room_name_or_id)
        if not room:
            return []
        conn = self._get_connection()
        rows = conn.execute(
            """
            SELECT DISTINCT p.id, p.name, p.display_name
            FROM principals p
            LEFT JOIN room_access ra ON p.id = ra.principal_id AND ra.room_id = ?
            LEFT JOIN humans h ON p.id = h.principal_id
            WHERE p.kind = 'human' AND (ra.room_id IS NOT NULL OR h.access_role = 'admin')
            ORDER BY p.id ASC;
            """,
            (room["id"],),
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
                SELECT r.*, 1 as can_write, NULL as role_id, NULL as role_key, NULL as role_display_name,
                       (SELECT COUNT(*) FROM room_access ra WHERE ra.room_id = r.id) as member_count
                FROM rooms r
                WHERE 1=1
            """
            if not include_archived:
                query += " AND r.is_archived = 0"
            query += " ORDER BY r.name ASC;"
            rows = conn.execute(query).fetchall()
            result = []
            for r in rows:
                d = dict(r)
                d["is_protected"] = False
                result.append(d)
            return result

        # Regular user or agent
        query = """
            SELECT r.*, ra.can_write, ra.role_id, ar.role_key, ar.display_name as role_display_name,
                   (SELECT COUNT(*) FROM room_access ra2 WHERE ra2.room_id = r.id) as member_count
            FROM rooms r
            JOIN room_access ra ON r.id = ra.room_id
            LEFT JOIN agent_roles ar ON ra.role_id = ar.id
            WHERE ra.principal_id = ?
        """
        if not include_archived:
            query += " AND r.is_archived = 0"
        query += " ORDER BY r.name ASC;"
        rows = conn.execute(query, (pid,)).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["is_protected"] = False
            result.append(d)
        return result

    # ------------------------------------------------------------------ Central Authorization
    def authorize(self, principal: dict[str, Any] | None, action: str, resource: dict[str, Any] | None = None) -> bool:
        """
        Central authorization arbiter across MCP, REST, and WebSockets.
        Actions:
          - 'admin': requires active human admin.
          - 'read_room': requires room access or admin.
          - 'write_room': requires room access with can_write=1 or admin, AND room not archived.
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

        if action == "read_room":
            if is_admin:
                return True
            if not resource or "room_id" not in resource:
                return False
            access = self.get_room_access(resource["room_id"], principal["id"])
            return access is not None

        if action == "write_room":
            if not resource or "room_id" not in resource:
                return False
            room = self.get_room_by_id(resource["room_id"])
            if not room or room.get("is_archived"):
                return False
            if is_admin:
                return True
            access = self.get_room_access(resource["room_id"], principal["id"])
            if not access or not access.get("can_write", 1):
                return False
            return True

        if action == "manage_room":
            if is_admin:
                return True
            if not resource or "room_id" not in resource:
                return False
            room = self.get_room_by_id(resource["room_id"])
            if not room:
                return False
            return room.get("created_by") == principal["id"]

        if action == "manage_poll":
            if is_admin:
                return True
            if not resource or "creator_id" not in resource:
                return False
            return resource.get("creator_id") == principal["id"]

        return False

    # ------------------------------------------------------------------ File Transcripts (.log and .jsonl)
    def get_room_log_file(self, room_name: str) -> Path:
        return self.logs_dir / f"{room_name.strip()}.log"

    def get_room_jsonl_file(self, room_name: str) -> Path:
        return self.logs_dir / f"{room_name.strip()}.jsonl"

    def _append_to_text_log(self, room_name: str, msg_data: dict[str, Any]) -> None:
        log_file = self.get_room_log_file(room_name)
        if not log_file.exists():
            log_file.write_text(f"=== Chat Room: {room_name} ===\n\n", encoding="utf-8")
        timestamp = msg_data.get("created_at", utc_now())
        sender = msg_data.get("sender", "System")
        role = str(msg_data.get("role", "system")).capitalize()
        content = msg_data.get("content", "")
        line = f"[{timestamp}] [{role}] {sender}: {content}\n"
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(line)

    def _append_to_jsonl_log(self, room_name: str, msg_data: dict[str, Any]) -> None:
        jsonl_file = self.get_room_jsonl_file(room_name)
        with open(jsonl_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(msg_data, ensure_ascii=False) + "\n")

    # ------------------------------------------------------------------ Messages & Addressing
    def resolve_recipients(self, to_input: str | list[Any] | None = None) -> list[dict[str, Any]]:
        """
        Resolves recipient definitions (e.g. 'all', '@developer', '@Sentinel', or comma-separated list)
        into validated list of target dictionaries:
        [{"target_kind": "all"|"role"|"principal", "target_id": int | None, "target_name": str}]
        """
        if to_input is None or to_input == "" or to_input == "all" or to_input == ["all"]:
            return [{"target_kind": "all", "target_id": None, "target_name": "all"}]

        raw_items: list[Any] = []
        if isinstance(to_input, str):
            raw_items = [s.strip() for s in to_input.split(",") if s.strip()]
        elif isinstance(to_input, (list, tuple, set)):
            for item in to_input:
                if isinstance(item, str):
                    raw_items.extend([s.strip() for s in item.split(",") if s.strip()])
                elif isinstance(item, dict):
                    raw_items.append(item)
                else:
                    raw_items.append(str(item).strip())
        else:
            raw_items = [str(to_input).strip()]

        if not raw_items:
            return [{"target_kind": "all", "target_id": None, "target_name": "all"}]

        conn = self._get_connection()
        resolved: list[dict[str, Any]] = []
        seen = set()

        for item in raw_items:
            if isinstance(item, dict):
                t_kind = item.get("target_kind", "all")
                t_id = item.get("target_id") if t_kind != "all" else None
                t_name = item.get("target_name") or str(t_id or "all")
                key = (t_kind, t_id)
                if key not in seen:
                    seen.add(key)
                    resolved.append({"target_kind": t_kind, "target_id": t_id, "target_name": t_name})
                continue

            clean = str(item).strip()
            if clean.startswith("@"):
                clean = clean[1:].strip()
            if not clean or clean.lower() == "all":
                if ("all", None) not in seen:
                    seen.add(("all", None))
                    resolved.append({"target_kind": "all", "target_id": None, "target_name": "all"})
                continue

            explicit_type = None
            clean_lower = clean.lower()
            if clean_lower.startswith("role:"):
                explicit_type = "role"
                clean = clean[5:].strip()
            elif clean_lower.startswith("agent:"):
                explicit_type = "principal"
                clean = clean[6:].strip()
            elif clean_lower.startswith("user:"):
                explicit_type = "principal"
                clean = clean[5:].strip()
            elif clean_lower.startswith("principal:"):
                explicit_type = "principal"
                clean = clean[10:].strip()

            role_row = None
            princ_row = None

            if explicit_type == "role":
                role_row = conn.execute(
                    "SELECT id, role_key, display_name FROM agent_roles WHERE role_key = ? COLLATE NOCASE;",
                    (clean,),
                ).fetchone()
                if not role_row:
                    raise ValueError(f"Papel '{item}' não encontrado.")
            elif explicit_type == "principal":
                princ_row = conn.execute(
                    "SELECT id, name, display_name FROM principals WHERE name = ? COLLATE NOCASE;",
                    (clean,),
                ).fetchone()
                if not princ_row:
                    raise ValueError(f"Agente/utilizador '{item}' não encontrado.")
            else:
                # Query both to detect collisions/ambiguities
                role_row = conn.execute(
                    "SELECT id, role_key, display_name FROM agent_roles WHERE role_key = ? COLLATE NOCASE;",
                    (clean,),
                ).fetchone()
                princ_row = conn.execute(
                    "SELECT id, name, display_name FROM principals WHERE name = ? COLLATE NOCASE;",
                    (clean,),
                ).fetchone()
                if role_row and princ_row:
                    raise ValueError(
                        f"Destinatário '{item}' é ambíguo: existe como papel e como agente/utilizador. "
                        f"Especifique com prefixo '@role:{clean}' ou '@agent:{clean}'."
                    )

            if role_row:
                key = ("role", role_row["id"])
                if key not in seen:
                    seen.add(key)
                    resolved.append({
                        "target_kind": "role",
                        "target_id": role_row["id"],
                        "target_name": role_row["role_key"],
                    })
                continue

            if princ_row:
                key = ("principal", princ_row["id"])
                if key not in seen:
                    seen.add(key)
                    resolved.append({
                        "target_kind": "principal",
                        "target_id": princ_row["id"],
                        "target_name": princ_row["name"],
                    })
                continue

            raise ValueError(f"Destinatário '{item}' não encontrado como papel ou agente/utilizador.")

        if any(r["target_kind"] == "all" for r in resolved):
            return [{"target_kind": "all", "target_id": None, "target_name": "all"}]

        return resolved

    @staticmethod
    def _format_to_list(recipients: list[dict[str, Any]]) -> list[str]:
        if not recipients:
            return ["all"]
        out = []
        for r in recipients:
            k = r.get("target_kind")
            name = r.get("target_name") or ""
            if k == "all":
                out.append("all")
            elif k in ("role", "principal"):
                out.append(f"@{name}" if not name.startswith("@") else name)
            else:
                out.append(name or "all")
        return out or ["all"]

    def _get_recipients_map(self, message_ids: list[int]) -> dict[int, list[dict[str, Any]]]:
        if not message_ids:
            return {}
        conn = self._get_connection()
        placeholders = ",".join("?" for _ in message_ids)
        rows = conn.execute(
            f"""
            SELECT mr.message_id, mr.target_kind, mr.target_id,
                   ar.role_key as target_role_key,
                   p.name as target_principal_name,
                   p.kind as target_principal_kind
            FROM message_recipients mr
            LEFT JOIN agent_roles ar ON mr.target_kind = 'role' AND mr.target_id = ar.id
            LEFT JOIN principals p ON mr.target_kind = 'principal' AND mr.target_id = p.id
            WHERE mr.message_id IN ({placeholders})
            ORDER BY mr.message_id ASC, mr.target_kind ASC;
            """,
            message_ids,
        ).fetchall()
        result: dict[int, list[dict[str, Any]]] = {}
        for r in rows:
            mid = r["message_id"]
            t_kind = r["target_kind"]
            t_id = r["target_id"]
            if t_kind == "role":
                t_name = r["target_role_key"] or str(t_id)
            elif t_kind == "principal":
                t_name = r["target_principal_name"] or str(t_id)
            else:
                t_name = "all"
            result.setdefault(mid, []).append({
                "target_kind": t_kind,
                "target_id": t_id,
                "target_name": t_name,
                "target_principal_kind": r["target_principal_kind"],
            })
        return result

    def get_message_recipients(self, message_id: int) -> list[dict[str, Any]]:
        """Returns the list of recipient dicts for a message."""
        mapping = self._get_recipients_map([message_id])
        return mapping.get(message_id, [])

    def add_message(
        self,
        room_name_or_id: int | str | None = None,
        sender: int | str | dict[str, Any] | None = None,
        content: str = "",
        role: str | None = None,
        message_type: str = "text",
        metadata: dict[str, Any] | None = None,
        is_verified: int | bool = 1,
        recipients: list[dict[str, Any]] | None = None,
        to: str | list[Any] | None = None,
        *,
        room_id: int | None = None,
        room_name: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Adds a message to a room. Validates that room is not archived.
        Saves to SQLite and appends to .log and .jsonl files.
        """
        target_room = room_id if room_id is not None else (room_name if room_name is not None else room_name_or_id)
        if target_room is None:
            raise ValueError("ID ou nome da sala não especificado.")
        room = self._resolve_room(target_room)
        if not room:
            raise ValueError(f"Sala '{target_room}' não encontrada.")
        if room.get("is_archived"):
            raise ValueError(f"Sala '{room['name']}' está arquivada: apenas leitura permitida.")

        principal = self._resolve_principal(sender) if sender else None
        sender_id = principal["id"] if principal else None
        sender_kind = (role if role else (principal.get("kind") if principal else "system")) or "system"
        sender_name = (principal.get("display_name") or principal.get("name")) if principal else (str(sender) if sender else "System")

        now_str = utc_now()
        meta_json = json.dumps(metadata or {}, ensure_ascii=False)
        verified_int = 1 if is_verified else 0

        target_list = self.resolve_recipients(to if to is not None else recipients)

        # Validate that targeted recipients have access to the room
        for r in target_list:
            t_kind = r.get("target_kind")
            t_id = r.get("target_id")
            t_name = r.get("target_name") or ""
            if t_kind == "principal":
                p_recip = self.get_principal_by_id(t_id)
                if p_recip and p_recip.get("kind") == "human" and p_recip.get("access_role") == "admin":
                    continue
                access = self.get_room_access(room["id"], t_id)
                if not access:
                    raise ValueError(f"Destinatário '@{t_name}' não tem acesso à sala '{room['name']}'.")
            elif t_kind == "role":
                conn = self._get_connection()
                has_member = conn.execute(
                    """
                    SELECT 1 FROM room_access ra
                    LEFT JOIN agents a ON ra.principal_id = a.principal_id
                    WHERE ra.room_id = ? AND (ra.role_id = ? OR (ra.role_id IS NULL AND a.default_role_id = ?));
                    """,
                    (room["id"], t_id, t_id),
                ).fetchone()
                if not has_member:
                    raise ValueError(f"O papel '@{t_name}' não está atribuído a nenhum membro com acesso à sala '{room['name']}'.")

        conn = self._get_connection()
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO messages (room_id, sender_id, sender_kind, sender_name, content, message_type, metadata, is_verified, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (room["id"], sender_id, sender_kind, sender_name, content, message_type, meta_json, verified_int, now_str),
            )
            msg_id = cursor.lastrowid

            # Handle recipients
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
                self.update_read_cursor(sender_id, room["id"], msg_id)

        msg_data = self.get_message_by_id(msg_id)
        if not msg_data:
            raise RuntimeError("Falha ao recuperar mensagem recém-criada.")

        # Append to file transcripts
        self._append_to_text_log(room["name"], msg_data)
        self._append_to_jsonl_log(room["name"], msg_data)

        return msg_data

    def get_message_by_id(self, message_id: int) -> dict[str, Any] | None:
        """Gets a message by numeric ID with its recipients and reactions."""
        conn = self._get_connection()
        row = conn.execute(
            """
            SELECT m.*, r.name as room_name
            FROM messages m
            JOIN rooms r ON m.room_id = r.id
            WHERE m.id = ?;
            """,
            (message_id,),
        ).fetchone()
        if not row:
            return None
        msg = dict(row)
        msg["metadata"] = json.loads(msg["metadata"]) if msg["metadata"] else {}
        msg["sender"] = msg["sender_name"]
        msg["role"] = msg["sender_kind"]

        # Fetch recipients
        recips_map = self._get_recipients_map([message_id])
        recips = recips_map.get(message_id, [{"target_kind": "all", "target_id": None, "target_name": "all"}])
        msg["recipients"] = recips
        msg["to"] = self._format_to_list(recips)

        # Fetch reactions
        msg["reactions"] = self.get_message_reactions(message_id)
        return msg

    def get_messages(
        self,
        room_name_or_id: int | str,
        since_id: int = 0,
        before_id: int = 0,
        limit: int = 50,
        from_beginning: bool = False,
    ) -> list[dict[str, Any]]:
        """Retrieves messages in a room with since_id / before_id pagination."""
        room = self._resolve_room(room_name_or_id)
        if not room:
            return []
        conn = self._get_connection()
        if since_id > 0 and before_id > 0:
            rows = conn.execute(
                """
                SELECT m.*, r.name as room_name
                FROM messages m
                JOIN rooms r ON m.room_id = r.id
                WHERE m.room_id = ? AND m.id > ? AND m.id < ?
                ORDER BY m.id ASC
                LIMIT ?;
                """,
                (room["id"], since_id, before_id, limit),
            ).fetchall()
        elif before_id > 0:
            rows = conn.execute(
                """
                SELECT * FROM (
                    SELECT m.*, r.name as room_name
                    FROM messages m
                    JOIN rooms r ON m.room_id = r.id
                    WHERE m.room_id = ? AND m.id < ?
                    ORDER BY m.id DESC
                    LIMIT ?
                ) ORDER BY id ASC;
                """,
                (room["id"], before_id, limit),
            ).fetchall()
        elif since_id > 0 or (since_id == 0 and from_beginning):
            rows = conn.execute(
                """
                SELECT m.*, r.name as room_name
                FROM messages m
                JOIN rooms r ON m.room_id = r.id
                WHERE m.room_id = ? AND m.id > ?
                ORDER BY m.id ASC
                LIMIT ?;
                """,
                (room["id"], since_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM (
                    SELECT m.*, r.name as room_name
                    FROM messages m
                    JOIN rooms r ON m.room_id = r.id
                    WHERE m.room_id = ?
                    ORDER BY m.id DESC
                    LIMIT ?
                ) ORDER BY id ASC;
                """,
                (room["id"], limit),
            ).fetchall()

        msg_ids = [r["id"] for r in rows]
        reactions_map = self._get_reactions_map(msg_ids)
        recipients_map = self._get_recipients_map(msg_ids)

        result = []
        for r in rows:
            m = dict(r)
            m["metadata"] = json.loads(m["metadata"]) if m["metadata"] else {}
            m["sender"] = m["sender_name"]
            m["role"] = m["sender_kind"]
            m["reactions"] = reactions_map.get(m["id"], [])
            recips = recipients_map.get(m["id"], [{"target_kind": "all", "target_id": None, "target_name": "all"}])
            m["recipients"] = recips
            m["to"] = self._format_to_list(recips)
            result.append(m)
        return result

    def get_max_message_id(self, room_name_or_id: int | str) -> int:
        """Returns the highest message ID in the room, or 0 if empty."""
        room = self._resolve_room(room_name_or_id)
        if not room:
            return 0
        conn = self._get_connection()
        cur = conn.execute("SELECT COALESCE(MAX(id), 0) FROM messages WHERE room_id = ?;", (room["id"],))
        row = cur.fetchone()
        return row[0] if row else 0

    def update_read_cursor(self, principal_id: int | str, room_name_or_id: int | str, last_message_id: int) -> None:
        """Updates or sets read position for a principal in a room."""
        room = self._resolve_room(room_name_or_id)
        p_id = principal_id
        if not room:
            alt_room = self._resolve_room(principal_id)
            if alt_room:
                room = alt_room
                p_id = room_name_or_id
        if not room:
            return
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
                (int(p_id), room["id"], last_message_id, now_str),
            )

    def get_read_cursor(self, principal_id: int | str, room_name_or_id: int | str) -> int:
        """Gets the last read message_id for a principal in a room."""
        room = self._resolve_room(room_name_or_id)
        p_id = principal_id
        if not room:
            alt_room = self._resolve_room(principal_id)
            if alt_room:
                room = alt_room
                p_id = room_name_or_id
        if not room:
            return 0
        conn = self._get_connection()
        row = conn.execute(
            "SELECT last_message_id FROM read_cursors WHERE principal_id = ? AND room_id = ?;",
            (int(p_id), room["id"]),
        ).fetchone()
        return row["last_message_id"] if row else 0

    def has_read_cursor(self, principal_id: int | str, room_name_or_id: int | str) -> bool:
        """Checks whether a read cursor record exists for a principal in a room."""
        room = self._resolve_room(room_name_or_id)
        p = self._resolve_principal(principal_id)
        if not room or not p:
            return False
        conn = self._get_connection()
        row = conn.execute(
            "SELECT 1 FROM read_cursors WHERE principal_id = ? AND room_id = ?;",
            (p["id"], room["id"]),
        ).fetchone()
        return row is not None

    def get_agent_role_in_room(self, principal_id: int | str, room_name_or_id: int | str) -> dict[str, Any] | None:
        """Retrieves effective role for an agent in a room (room_access.role_id with fallback to agents.default_role_id)."""
        p = self._resolve_principal(principal_id)
        if not p:
            return None
        room = self._resolve_room(room_name_or_id)
        if not room:
            return None
        conn = self._get_connection()
        row = conn.execute(
            """
            SELECT ar.*
            FROM room_access ra
            JOIN agent_roles ar ON ra.role_id = ar.id
            WHERE ra.room_id = ? AND ra.principal_id = ?;
            """,
            (room["id"], p["id"]),
        ).fetchone()
        if row:
            return dict(row)
        fallback = conn.execute(
            """
            SELECT ar.*
            FROM agents a
            JOIN agent_roles ar ON a.default_role_id = ar.id
            WHERE a.principal_id = ?;
            """,
            (p["id"],),
        ).fetchone()
        return dict(fallback) if fallback else None

    def is_message_for_principal(
        self,
        msg: dict[str, Any],
        principal: dict[str, Any] | int | str,
        room_name_or_id: int | str | None = None,
    ) -> bool:
        """
        Determines whether a message in a room should be delivered to / wake up a principal.
        Rules:
        - Sender never receives own message.
        - Human admins receive all messages.
        - Observers (can_write == 0 in room_access) NEVER wake on 'all' messages; only when explicitly targeted.
        - Targeted messages only wake matching principal_id or matching role_id in this room.
        - Active members (can_write == 1) wake on 'all' and on messages targeting their principal_id or role_id.
        """
        p = self._resolve_principal(principal)
        if not p:
            return False

        # 1. Senders never wake on own messages
        sender_id = msg.get("sender_id")
        if sender_id is not None and sender_id == p["id"]:
            return False
        sender_name = msg.get("sender_name") or msg.get("sender") or ""
        if sender_name and sender_name.strip().lower() == p["name"].strip().lower():
            return False

        # 2. Human admins see/receive everything
        if p.get("kind") == "human" and p.get("access_role") == "admin":
            return True

        target_room = room_name_or_id if room_name_or_id is not None else msg.get("room_id", msg.get("room_name"))
        room = self._resolve_room(target_room) if target_room is not None else None
        if not room:
            return True

        # Check room membership and observer status
        access = self.get_room_access(room["id"], p["id"])
        if not access:
            # Not a member of the room
            return False

        is_observer = (access.get("can_write", 1) == 0)

        # Check recipients
        recipients = msg.get("recipients", [])
        if not recipients:
            # Default or legacy = "all"
            return not is_observer

        # Check if explicitly targeted by principal_id
        for r in recipients:
            t_kind = r.get("target_kind")
            t_id = r.get("target_id")
            if t_kind == "principal" and t_id == p["id"]:
                return True

        # Check if explicitly targeted by role_id in this room
        agent_role = self.get_agent_role_in_room(p["id"], room["id"])
        if agent_role:
            for r in recipients:
                t_kind = r.get("target_kind")
                t_id = r.get("target_id")
                if t_kind == "role" and t_id == agent_role["id"]:
                    return True

        # Check if broadcast to 'all'
        for r in recipients:
            if r.get("target_kind") == "all":
                if is_observer:
                    return False  # Observers never wake on 'all'
                return True

        return False

    def count_consecutive_agent_messages(self, room_name_or_id: int | str) -> int:
        """
        Counts the number of consecutive agent messages directed to other agents
        in a room since the last human message.
        System messages do not count towards agent messages, nor do they reset the counter.
        Messages sent to a human or broadcast to 'all' do not count as agent-to-agent loops.
        """
        room = self._resolve_room(room_name_or_id)
        if not room:
            return 0
        conn = self._get_connection()
        rows = conn.execute(
            """
            SELECT id, sender_id, sender_kind FROM messages
            WHERE room_id = ?
            ORDER BY id DESC
            LIMIT 100;
            """,
            (room["id"],),
        ).fetchall()
        if not rows:
            return 0

        msg_ids = [r["id"] for r in rows]
        placeholders = ",".join("?" for _ in msg_ids)
        recip_rows = conn.execute(
            f"""
            SELECT mr.message_id, mr.target_kind, mr.target_id, p.kind as target_principal_kind
            FROM message_recipients mr
            LEFT JOIN principals p ON mr.target_kind = 'principal' AND mr.target_id = p.id
            WHERE mr.message_id IN ({placeholders});
            """,
            msg_ids,
        ).fetchall()

        recips_by_mid: dict[int, list[dict[str, Any]]] = {}
        for rr in recip_rows:
            recips_by_mid.setdefault(rr["message_id"], []).append(dict(rr))

        count = 0
        for r in rows:
            kind = r["sender_kind"]
            if kind == "human":
                break
            if kind == "agent":
                m_recips = recips_by_mid.get(r["id"], [])
                # Count all agent messages EXCEPT those directed ONLY to humans:
                has_all = any(rec.get("target_kind") == "all" for rec in m_recips)
                has_human = any(rec.get("target_principal_kind") == "human" for rec in m_recips)
                has_agent_target = any(
                    rec.get("target_kind") == "role" or
                    (rec.get("target_kind") == "principal" and rec.get("target_principal_kind") == "agent" and rec.get("target_id") != r["sender_id"])
                    for rec in m_recips
                )
                is_only_humans = has_human and not has_all and not has_agent_target
                if not is_only_humans:
                    count += 1
        return count


    # ------------------------------------------------------------------ Reactions
    def _get_reactions_map(self, message_ids: list[int]) -> dict[int, list[dict[str, Any]]]:
        if not message_ids:
            return {}
        conn = self._get_connection()
        placeholders = ",".join("?" for _ in message_ids)
        cursor = conn.execute(
            f"""
            SELECT rx.message_id, rx.emoji, p.name, p.display_name
            FROM reactions rx
            JOIN principals p ON rx.principal_id = p.id
            WHERE rx.message_id IN ({placeholders})
            ORDER BY rx.id ASC;
            """,
            message_ids,
        )
        msg_tally: dict[int, dict[str, list[str]]] = {}
        for row in cursor.fetchall():
            mid = row["message_id"]
            em = row["emoji"]
            user_name = row["display_name"] or row["name"]
            msg_tally.setdefault(mid, {}).setdefault(em, []).append(user_name)

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
        room_name_or_id: int | str,
        sender_name_or_id: int | str | dict[str, Any],
        emoji: str,
    ) -> dict[str, Any]:
        """Toggles an emoji reaction from a sender on a message."""
        room = self._resolve_room(room_name_or_id)
        if not room:
            raise ValueError(f"Sala '{room_name_or_id}' não encontrada.")
        principal = self._resolve_principal(sender_name_or_id)
        if not principal:
            raise ValueError(f"Principal '{sender_name_or_id}' não encontrado.")
        if room.get("is_archived"):
            raise ValueError(f"Sala '{room['name']}' está arquivada: apenas leitura permitida.")

        clean_emoji = emoji.strip()
        conn = self._get_connection()
        now_str = utc_now()
        with conn:
            cur = conn.execute(
                "SELECT id FROM reactions WHERE message_id = ? AND principal_id = ? AND emoji = ?;",
                (message_id, principal["id"], clean_emoji),
            )
            row = cur.fetchone()
            if row:
                conn.execute("DELETE FROM reactions WHERE id = ?;", (row["id"],))
                action = "removed"
            else:
                conn.execute(
                    "INSERT INTO reactions (message_id, principal_id, emoji, created_at) VALUES (?, ?, ?, ?);",
                    (message_id, principal["id"], clean_emoji, now_str),
                )
                action = "added"
        reactions = self.get_message_reactions(message_id)
        return {
            "action": action,
            "message_id": message_id,
            "room_id": room["id"],
            "room_name": room["name"],
            "principal_id": principal["id"],
            "sender": principal["display_name"] or principal["name"],
            "emoji": clean_emoji,
            "reactions": reactions,
        }

    # ------------------------------------------------------------------ Decisions
    def resolve_decision(
        self,
        message_id: int,
        decision: str,
        decider_name_or_id: int | str | dict[str, Any] = "admin",
    ) -> dict[str, Any] | None:
        """Resolves a pending human decision request."""
        decider_p = self._resolve_principal(decider_name_or_id)
        decider_name = (decider_p.get("display_name") or decider_p.get("name")) if decider_p else str(decider_name_or_id)
        conn = self._get_connection()
        cursor = conn.execute("SELECT metadata FROM messages WHERE id = ?;", (message_id,))
        row = cursor.fetchone()
        if not row:
            return None
        meta = json.loads(row["metadata"] or "{}")
        meta["status"] = "resolved"
        meta["decision"] = decision
        meta["decided_by"] = decider_name
        meta["decided_at"] = utc_now()
        with conn:
            conn.execute(
                "UPDATE messages SET metadata = ? WHERE id = ?;",
                (json.dumps(meta, ensure_ascii=False), message_id),
            )
        return meta

    # ------------------------------------------------------------------ Polls
    def create_poll(
        self,
        room_name_or_id: int | str,
        creator_name_or_id: int | str | dict[str, Any],
        question: str,
        options: list[str],
    ) -> dict[str, Any]:
        """Creates a new poll in a room."""
        room = self._resolve_room(room_name_or_id)
        if not room:
            raise ValueError(f"Sala '{room_name_or_id}' não encontrada.")
        if room.get("is_archived"):
            raise ValueError(f"Sala '{room['name']}' está arquivada: apenas leitura permitida.")
        creator = self._resolve_principal(creator_name_or_id)
        creator_id = creator["id"] if creator else None
        clean_options = [opt.strip() for opt in options if opt.strip()]
        if len(clean_options) < 2:
            raise ValueError("Uma votação necessita de pelo menos 2 opções.")
        now_str = utc_now()
        conn = self._get_connection()
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO polls (room_id, creator_id, question, options, is_closed, created_at)
                VALUES (?, ?, ?, ?, 0, ?);
                """,
                (room["id"], creator_id, question.strip(), json.dumps(clean_options, ensure_ascii=False), now_str),
            )
            poll_id = cursor.lastrowid
        return self.get_poll(poll_id)

    def get_poll(self, poll_id: int) -> dict[str, Any] | None:
        """Retrieves poll details with tally of votes."""
        conn = self._get_connection()
        row = conn.execute(
            """
            SELECT p.*, r.name as room_name, pr.name as creator_name, pr.display_name as creator_display
            FROM polls p
            JOIN rooms r ON p.room_id = r.id
            LEFT JOIN principals pr ON p.creator_id = pr.id
            WHERE p.id = ?;
            """,
            (poll_id,),
        ).fetchone()
        if not row:
            return None
        poll = dict(row)
        options = json.loads(poll["options"])
        creator_str = poll["creator_display"] or poll["creator_name"] or "System"

        votes_cur = conn.execute(
            """
            SELECT pv.option_index, pr.name, pr.display_name
            FROM poll_votes pv
            JOIN principals pr ON pv.voter_id = pr.id
            WHERE pv.poll_id = ?
            ORDER BY pv.created_at ASC;
            """,
            (poll_id,),
        )
        tally: dict[int, list[str]] = {i: [] for i in range(len(options))}
        for v in votes_cur.fetchall():
            idx = v["option_index"]
            v_name = v["display_name"] or v["name"]
            if idx in tally:
                tally[idx].append(v_name)

        results = [
            {"option": opt, "votes": len(tally[i]), "voters": tally[i]}
            for i, opt in enumerate(options)
        ]
        total_votes = sum(len(v) for v in tally.values())
        return {
            "id": poll["id"],
            "room_id": poll["room_id"],
            "room_name": poll["room_name"],
            "creator_id": poll["creator_id"],
            "creator": creator_str,
            "question": poll["question"],
            "options": options,
            "is_closed": bool(poll["is_closed"]),
            "created_at": poll["created_at"],
            "closed_at": poll["closed_at"],
            "results": results,
            "total_votes": total_votes,
        }

    def cast_vote(
        self,
        poll_id: int,
        voter_name_or_id: int | str | dict[str, Any],
        option_index: int,
    ) -> dict[str, Any]:
        """Casts or updates a vote on an active poll."""
        voter = self._resolve_principal(voter_name_or_id)
        if not voter:
            raise ValueError(f"Principal '{voter_name_or_id}' não encontrado.")
        conn = self._get_connection()
        poll_row = conn.execute("SELECT room_id, is_closed, options FROM polls WHERE id = ?", (poll_id,)).fetchone()
        if not poll_row:
            raise ValueError(f"Poll #{poll_id} não existe.")
        if poll_row["is_closed"]:
            raise ValueError(f"Poll #{poll_id} já se encontra encerrada.")
        room = self.get_room_by_id(poll_row["room_id"])
        if room and room.get("is_archived"):
            raise ValueError(f"Sala '{room['name']}' está arquivada: apenas leitura permitida.")

        opts = json.loads(poll_row["options"])
        if option_index < 0 or option_index >= len(opts):
            raise ValueError(f"Opção inválida ({option_index}). As opções vão de 0 a {len(opts)-1}.")
        now_str = utc_now()
        with conn:
            conn.execute(
                """
                INSERT INTO poll_votes (poll_id, voter_id, option_index, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(poll_id, voter_id) DO UPDATE SET
                    option_index = excluded.option_index,
                    created_at = excluded.created_at;
                """,
                (poll_id, voter["id"], option_index, now_str),
            )
        return self.get_poll(poll_id)

    def close_poll(self, poll_id: int, closer_name_or_id: int | str | dict[str, Any] | None = None) -> dict[str, Any]:
        """Closes an active poll."""
        conn = self._get_connection()
        now_str = utc_now()
        with conn:
            cursor = conn.execute(
                "UPDATE polls SET is_closed = 1, closed_at = ? WHERE id = ? AND is_closed = 0;",
                (now_str, poll_id),
            )
            if cursor.rowcount == 0:
                poll = self.get_poll(poll_id)
                if not poll:
                    raise ValueError(f"Poll #{poll_id} não existe.")
                raise ValueError(f"Poll #{poll_id} já se encontra encerrada.")
        return self.get_poll(poll_id)

    # ------------------------------------------------------------------ Tasks (Gantt-ready)
    def create_task(
        self,
        room_name_or_id: int | str,
        title: str,
        description: str = "",
        status: str = "planned",
        priority: str = "medium",
        assignee: int | str | dict[str, Any] | None = None,
        waiting_for_agent: int | str | dict[str, Any] | None = None,
        order_index: int | None = None,
        message_id: int | None = None,
        uses_gpu: bool = False,
        gpu_est_min: int = 0,
        resource: str = "",
        start_at: str = "",
        due_at: str = "",
        created_by: int | str | dict[str, Any] | None = None,
        parent_task_id: int | None = None,
        progress_percent: int = 0,
    ) -> dict[str, Any]:
        """Creates a new task in a room."""
        room = self._resolve_room(room_name_or_id)
        if not room:
            raise ValueError(f"Sala '{room_name_or_id}' não encontrada.")
        if room.get("is_archived"):
            raise ValueError(f"Sala '{room['name']}' está arquivada: escrita não permitida.")

        assignee_p = self._resolve_principal(assignee) if assignee else None
        assignee_id = assignee_p["id"] if assignee_p else None

        waiting_p = self._resolve_principal(waiting_for_agent) if waiting_for_agent else None
        waiting_for_id = waiting_p["id"] if waiting_p else None

        creator_p = self._resolve_principal(created_by) if created_by else None
        creator_id = creator_p["id"] if creator_p else None
        actor_name = (creator_p.get("display_name") or creator_p.get("name")) if creator_p else "System"

        now_str = utc_now()
        conn = self._get_connection()

        if order_index is None:
            cur = conn.execute("SELECT COALESCE(MAX(order_index), 0) + 1 FROM tasks WHERE room_id = ?;", (room["id"],))
            calc_order = cur.fetchone()[0]
        else:
            calc_order = int(order_index)

        with conn:
            cursor = conn.execute(
                """
                INSERT INTO tasks (
                    room_id, parent_task_id, title, description, status, priority,
                    assignee_id, waiting_for_id, order_index, message_id,
                    uses_gpu, gpu_est_min, resource, start_at, due_at,
                    progress_percent, created_by, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    room["id"], parent_task_id, title.strip(), description.strip(),
                    status.strip() if status else "planned", priority.strip() if priority else "medium",
                    assignee_id, waiting_for_id, calc_order, message_id,
                    1 if uses_gpu else 0, max(0, int(gpu_est_min or 0)), resource.strip() or None,
                    start_at.strip() or None, due_at.strip() or None,
                    max(0, min(100, int(progress_percent or 0))), creator_id, now_str, now_str
                ),
            )
            task_id = cursor.lastrowid
            conn.execute(
                """
                INSERT INTO task_history (task_id, action, actor_id, actor_name, to_status, details, created_at)
                VALUES (?, 'created', ?, ?, ?, ?, ?);
                """,
                (task_id, creator_id, actor_name, status, title.strip(), now_str),
            )

        if start_at and start_at.strip():
            try:
                self.create_calendar_event(
                    title=title.strip(),
                    start_at=start_at.strip(),
                    room_name_or_id=room["id"],
                    owner_id_or_name=creator_id,
                    description=description.strip(),
                    end_at=due_at.strip() or None,
                    task_id=task_id,
                    resource=resource.strip() or None,
                    target_id_or_name=assignee_id,
                    status="scheduled",
                    created_by_id_or_name=creator_id,
                )
            except Exception:
                pass

        return self.get_task_by_id(task_id)  # type: ignore

    def get_task_by_id(self, task_id: int) -> dict[str, Any] | None:
        """Retrieves a single task with principal display names and dependencies."""
        conn = self._get_connection()
        row = conn.execute(
            """
            SELECT t.*, r.name as room_name,
                   pa.name as assignee_name, pa.display_name as assignee_display,
                   pw.name as waiting_name, pw.display_name as waiting_display,
                   pc.name as creator_name, pc.display_name as creator_display
            FROM tasks t
            JOIN rooms r ON t.room_id = r.id
            LEFT JOIN principals pa ON t.assignee_id = pa.id
            LEFT JOIN principals pw ON t.waiting_for_id = pw.id
            LEFT JOIN principals pc ON t.created_by = pc.id
            WHERE t.id = ?;
            """,
            (task_id,),
        ).fetchone()
        if not row:
            return None
        t = dict(row)
        deps_cur = conn.execute("SELECT depends_on_task_id FROM task_dependencies WHERE task_id = ?;", (task_id,))
        deps = [r[0] for r in deps_cur.fetchall()]
        return {
            "id": t["id"],
            "room_id": t["room_id"],
            "room_name": t["room_name"],
            "parent_task_id": t["parent_task_id"],
            "title": t["title"],
            "description": t["description"],
            "status": t["status"],
            "priority": t["priority"],
            "assignee_id": t["assignee_id"],
            "assignee": t["assignee_display"] or t["assignee_name"] or "",
            "waiting_for_id": t["waiting_for_id"],
            "waiting_for_agent": t["waiting_display"] or t["waiting_name"] or "",
            "order_index": t["order_index"],
            "message_id": t["message_id"],
            "uses_gpu": bool(t["uses_gpu"]),
            "gpu_est_min": t["gpu_est_min"],
            "resource": t["resource"] or "",
            "start_at": t["start_at"] or "",
            "due_at": t["due_at"] or "",
            "progress_percent": t["progress_percent"],
            "created_by": t["created_by"],
            "creator": t["creator_display"] or t["creator_name"] or "System",
            "created_at": t["created_at"],
            "updated_at": t["updated_at"],
            "dependencies": deps,
        }

    def list_tasks(
        self,
        room_name_or_id: int | str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        """Lists tasks matching filters, ordered by order_index and id."""
        conn = self._get_connection()
        query = """
            SELECT t.*, r.name as room_name,
                   pa.name as assignee_name, pa.display_name as assignee_display,
                   pw.name as waiting_name, pw.display_name as waiting_display,
                   pc.name as creator_name, pc.display_name as creator_display
            FROM tasks t
            JOIN rooms r ON t.room_id = r.id
            LEFT JOIN principals pa ON t.assignee_id = pa.id
            LEFT JOIN principals pw ON t.waiting_for_id = pw.id
            LEFT JOIN principals pc ON t.created_by = pc.id
            WHERE 1=1
        """
        params: list[Any] = []
        if room_name_or_id:
            room = self._resolve_room(room_name_or_id)
            if room:
                query += " AND t.room_id = ?"
                params.append(room["id"])
        if status:
            query += " AND t.status = ?"
            params.append(status.strip())
        query += " ORDER BY t.order_index ASC, t.id ASC;"

        rows = conn.execute(query, params).fetchall()
        task_ids = [r["id"] for r in rows]

        deps_map: dict[int, list[int]] = {tid: [] for tid in task_ids}
        if task_ids:
            placeholders = ",".join("?" for _ in task_ids)
            deps_cur = conn.execute(
                f"SELECT task_id, depends_on_task_id FROM task_dependencies WHERE task_id IN ({placeholders});",
                task_ids,
            )
            for d in deps_cur.fetchall():
                deps_map[d["task_id"]].append(d["depends_on_task_id"])

        results = []
        for r in rows:
            t = dict(r)
            results.append({
                "id": t["id"],
                "room_id": t["room_id"],
                "room_name": t["room_name"],
                "parent_task_id": t["parent_task_id"],
                "title": t["title"],
                "description": t["description"],
                "status": t["status"],
                "priority": t["priority"],
                "assignee_id": t["assignee_id"],
                "assignee": t["assignee_display"] or t["assignee_name"] or "",
                "waiting_for_id": t["waiting_for_id"],
                "waiting_for_agent": t["waiting_display"] or t["waiting_name"] or "",
                "order_index": t["order_index"],
                "message_id": t["message_id"],
                "uses_gpu": bool(t["uses_gpu"]),
                "gpu_est_min": t["gpu_est_min"],
                "resource": t["resource"] or "",
                "start_at": t["start_at"] or "",
                "due_at": t["due_at"] or "",
                "progress_percent": t["progress_percent"],
                "created_by": t["created_by"],
                "creator": t["creator_display"] or t["creator_name"] or "System",
                "created_at": t["created_at"],
                "updated_at": t["updated_at"],
                "dependencies": deps_map.get(t["id"], []),
            })
        return results

    def update_task(
        self,
        task_id: int,
        actor: int | str | dict[str, Any] | None = None,
        title: str | None = None,
        description: str | None = None,
        status: str | None = None,
        assignee: int | str | dict[str, Any] | None = None,
        waiting_for_agent: int | str | dict[str, Any] | None = None,
        priority: str | None = None,
        order_index: int | None = None,
        message_id: int | None = None,
        uses_gpu: bool | None = None,
        gpu_est_min: int | None = None,
        start_at: str | None = None,
        due_at: str | None = None,
        resource: str | None = None,
        progress_percent: int | None = None,
    ) -> dict[str, Any]:
        """Updates fields of an existing task and logs history."""
        task = self.get_task_by_id(task_id)
        if not task:
            raise ValueError(f"Tarefa #{task_id} não encontrada.")

        actor_p = self._resolve_principal(actor) if actor else None
        actor_id = actor_p["id"] if actor_p else None
        actor_name = (actor_p.get("display_name") or actor_p.get("name")) if actor_p else "System"

        now_str = utc_now()
        updates = []
        params = []
        old_status = task["status"]

        if title is not None and title.strip():
            updates.append("title = ?")
            params.append(title.strip())
        if description is not None:
            updates.append("description = ?")
            params.append(description.strip())
        if status is not None and status.strip():
            updates.append("status = ?")
            params.append(status.strip())
        if assignee is not None:
            assignee_p = self._resolve_principal(assignee) if assignee else None
            updates.append("assignee_id = ?")
            params.append(assignee_p["id"] if assignee_p else None)
        if waiting_for_agent is not None:
            wait_p = self._resolve_principal(waiting_for_agent) if waiting_for_agent else None
            updates.append("waiting_for_id = ?")
            params.append(wait_p["id"] if wait_p else None)
        if priority is not None and priority.strip():
            updates.append("priority = ?")
            params.append(priority.strip())
        if order_index is not None:
            updates.append("order_index = ?")
            params.append(int(order_index))
        if message_id is not None:
            updates.append("message_id = ?")
            params.append(int(message_id))
        if uses_gpu is not None:
            updates.append("uses_gpu = ?")
            params.append(1 if uses_gpu else 0)
        if gpu_est_min is not None:
            updates.append("gpu_est_min = ?")
            params.append(max(0, int(gpu_est_min)))
        if start_at is not None:
            updates.append("start_at = ?")
            params.append(start_at.strip() or None)
        if due_at is not None:
            updates.append("due_at = ?")
            params.append(due_at.strip() or None)
        if resource is not None:
            updates.append("resource = ?")
            params.append(resource.strip() or None)
        if progress_percent is not None:
            updates.append("progress_percent = ?")
            params.append(max(0, min(100, int(progress_percent))))

        if not updates:
            return task

        updates.append("updated_at = ?")
        params.append(now_str)
        params.append(task_id)

        conn = self._get_connection()
        with conn:
            conn.execute(f"UPDATE tasks SET {', '.join(updates)} WHERE id = ?;", params)
            new_status = status.strip() if status and status.strip() else old_status
            action = "status_change" if (status and status != old_status) else "updated"
            conn.execute(
                """
                INSERT INTO task_history (task_id, action, actor_id, actor_name, from_status, to_status, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (task_id, action, actor_id, actor_name, old_status, new_status, f"Updated fields: {', '.join(updates)}", now_str),
            )
        return self.get_task_by_id(task_id)  # type: ignore

    def delete_task(self, task_id: int) -> bool:
        """Deletes a task by ID."""
        conn = self._get_connection()
        with conn:
            cur = conn.execute("DELETE FROM tasks WHERE id = ?;", (task_id,))
            return cur.rowcount > 0

    def reorder_tasks(self, room_name_or_id: int | str, task_ids: list[int]) -> list[dict[str, Any]]:
        """Reorders tasks within a room according to the given ID order."""
        room = self._resolve_room(room_name_or_id)
        if not room:
            raise ValueError(f"Sala '{room_name_or_id}' não encontrada.")
        conn = self._get_connection()
        now_str = utc_now()
        with conn:
            for idx, tid in enumerate(task_ids):
                conn.execute(
                    "UPDATE tasks SET order_index = ?, updated_at = ? WHERE id = ? AND room_id = ?;",
                    (idx, now_str, tid, room["id"]),
                )
        return self.list_tasks(room_name_or_id=room["id"])

    def add_task_dependency(self, task_id: int, depends_on_task_id: int) -> None:
        """Adds a dependency between tasks with cycle detection."""
        if task_id == depends_on_task_id:
            raise ValueError("Uma tarefa não pode depender de si própria.")
        conn = self._get_connection()
        # Cycle detection: check if task_id can reach depends_on_task_id
        visited = set()
        queue = [task_id]
        while queue:
            curr = queue.pop(0)
            if curr == depends_on_task_id:
                raise ValueError("Dependência circular detetada: não é possível adicionar esta dependência.")
            visited.add(curr)
            cur = conn.execute("SELECT depends_on_task_id FROM task_dependencies WHERE task_id = ?;", (curr,))
            for r in cur.fetchall():
                dep = r[0]
                if dep not in visited:
                    queue.append(dep)

        with conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO task_dependencies (task_id, depends_on_task_id)
                VALUES (?, ?);
                """,
                (task_id, depends_on_task_id),
            )

    def get_task_history(self, task_id: int) -> list[dict[str, Any]]:
        """Retrieves audit history for a task."""
        conn = self._get_connection()
        rows = conn.execute("SELECT * FROM task_history WHERE task_id = ? ORDER BY id ASC;", (task_id,)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ Calendar & Resources
    def create_calendar_event(
        self,
        title: str,
        start_at: str,
        room_name_or_id: int | str | None = None,
        owner_id_or_name: int | str | dict[str, Any] | None = None,
        description: str = "",
        end_at: str | None = None,
        event_type: str = "event",
        task_id: int | None = None,
        resource: str | None = None,
        target_id_or_name: int | str | dict[str, Any] | None = None,
        status: str = "scheduled",
        wake_on_start: int = 1,
        wake_on_end: int = 0,
        created_by_id_or_name: int | str | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Creates a calendar event (room-linked, personal, or resource reservation)."""
        room = self._resolve_room(room_name_or_id) if room_name_or_id else None
        room_id = room["id"] if room else None

        owner = self._resolve_principal(owner_id_or_name) if owner_id_or_name else None
        owner_id = owner["id"] if owner else None

        target = self._resolve_principal(target_id_or_name) if target_id_or_name else None
        target_id = target["id"] if target else None

        creator = self._resolve_principal(created_by_id_or_name) if created_by_id_or_name else None
        created_by_id = creator["id"] if creator else None

        now_str = utc_now()
        conn = self._get_connection()
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO calendar_events (
                    room_id, owner_id, title, description, start_at, end_at,
                    event_type, task_id, resource, target_id, status,
                    wake_on_start, wake_on_end, notified_start, notified_end,
                    created_by, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, ?);
                """,
                (
                    room_id, owner_id, title.strip(), description.strip(), start_at.strip(),
                    end_at.strip() if end_at else None, event_type.strip(), task_id,
                    resource.strip() if resource else None, target_id, status.strip(),
                    1 if wake_on_start else 0, 1 if wake_on_end else 0,
                    created_by_id, now_str, now_str
                ),
            )
            event_id = cursor.lastrowid
        return self.get_calendar_event_by_id(event_id)  # type: ignore

    def get_calendar_event_by_id(self, event_id: int) -> dict[str, Any] | None:
        """Retrieves a single calendar event with joined names."""
        conn = self._get_connection()
        row = conn.execute(
            """
            SELECT ce.*, r.name as room_name,
                   po.name as owner_name, po.display_name as owner_display,
                   pt.name as target_name, pt.display_name as target_display,
                   pc.name as creator_name, pc.display_name as creator_display
            FROM calendar_events ce
            LEFT JOIN rooms r ON ce.room_id = r.id
            LEFT JOIN principals po ON ce.owner_id = po.id
            LEFT JOIN principals pt ON ce.target_id = pt.id
            LEFT JOIN principals pc ON ce.created_by = pc.id
            WHERE ce.id = ?;
            """,
            (event_id,),
        ).fetchone()
        if not row:
            return None
        e = dict(row)
        return {
            "id": e["id"],
            "room_id": e["room_id"],
            "room_name": e["room_name"] or "",
            "owner_id": e["owner_id"],
            "owner": e["owner_display"] or e["owner_name"] or "",
            "title": e["title"],
            "description": e["description"],
            "start_at": e["start_at"],
            "end_at": e["end_at"] or "",
            "event_type": e["event_type"],
            "task_id": e["task_id"],
            "resource": e["resource"] or "",
            "target_id": e["target_id"],
            "target_agent": e["target_display"] or e["target_name"] or "",
            "status": e["status"],
            "wake_on_start": bool(e["wake_on_start"]),
            "wake_on_end": bool(e["wake_on_end"]),
            "notified_start": bool(e["notified_start"]),
            "notified_end": bool(e["notified_end"]),
            "created_by": e["created_by"],
            "creator": e["creator_display"] or e["creator_name"] or "System",
            "created_at": e["created_at"],
            "updated_at": e["updated_at"],
        }

    def list_calendar_events(
        self,
        room_name_or_id: int | str | None = None,
        owner_id_or_name: int | str | dict[str, Any] | None = None,
        resource: str | None = None,
        start_after: str | None = None,
        end_before: str | None = None,
        hide_completed: bool = False,
    ) -> list[dict[str, Any]]:
        """Lists calendar events with filtering."""
        conn = self._get_connection()
        query = """
            SELECT ce.*, r.name as room_name,
                   po.name as owner_name, po.display_name as owner_display,
                   pt.name as target_name, pt.display_name as target_display,
                   pc.name as creator_name, pc.display_name as creator_display
            FROM calendar_events ce
            LEFT JOIN rooms r ON ce.room_id = r.id
            LEFT JOIN principals po ON ce.owner_id = po.id
            LEFT JOIN principals pt ON ce.target_id = pt.id
            LEFT JOIN principals pc ON ce.created_by = pc.id
            WHERE 1=1
        """
        params: list[Any] = []
        if room_name_or_id:
            room = self._resolve_room(room_name_or_id)
            if room:
                query += " AND ce.room_id = ?"
                params.append(room["id"])
        if owner_id_or_name:
            owner = self._resolve_principal(owner_id_or_name)
            if owner:
                query += " AND ce.owner_id = ?"
                params.append(owner["id"])
        if resource:
            query += " AND ce.resource = ?"
            params.append(resource.strip())
        if start_after:
            query += " AND ce.start_at >= ?"
            params.append(start_after.strip())
        if end_before:
            query += " AND ce.start_at <= ?"
            params.append(end_before.strip())
        if hide_completed:
            query += " AND ce.status NOT IN ('done', 'completed', 'cancelled')"
        query += " ORDER BY ce.start_at ASC, ce.id ASC;"

        rows = conn.execute(query, params).fetchall()
        return [
            {
                "id": e["id"],
                "room_id": e["room_id"],
                "room_name": e["room_name"] or "",
                "owner_id": e["owner_id"],
                "owner": e["owner_display"] or e["owner_name"] or "",
                "title": e["title"],
                "description": e["description"],
                "start_at": e["start_at"],
                "end_at": e["end_at"] or "",
                "event_type": e["event_type"],
                "task_id": e["task_id"],
                "resource": e["resource"] or "",
                "target_id": e["target_id"],
                "target_agent": e["target_display"] or e["target_name"] or "",
                "status": e["status"],
                "wake_on_start": bool(e["wake_on_start"]),
                "wake_on_end": bool(e["wake_on_end"]),
                "created_by": e["created_by"],
                "created_at": e["created_at"],
                "updated_at": e["updated_at"],
            }
            for e in rows
        ]

    def update_calendar_event(
        self,
        event_id: int,
        title: str | None = None,
        description: str | None = None,
        start_at: str | None = None,
        end_at: str | None = None,
        status: str | None = None,
        resource: str | None = None,
    ) -> dict[str, Any]:
        """Updates fields of an existing calendar event."""
        event = self.get_calendar_event_by_id(event_id)
        if not event:
            raise ValueError(f"Evento de calendário #{event_id} não encontrado.")
        updates = []
        params = []
        if title is not None and title.strip():
            updates.append("title = ?")
            params.append(title.strip())
        if description is not None:
            updates.append("description = ?")
            params.append(description.strip())
        if start_at is not None and start_at.strip():
            updates.append("start_at = ?")
            params.append(start_at.strip())
        if end_at is not None:
            updates.append("end_at = ?")
            params.append(end_at.strip() or None)
        if status is not None and status.strip():
            updates.append("status = ?")
            params.append(status.strip())
        if resource is not None:
            updates.append("resource = ?")
            params.append(resource.strip() or None)

        if updates:
            now_str = utc_now()
            updates.append("updated_at = ?")
            params.append(now_str)
            params.append(event_id)
            conn = self._get_connection()
            with conn:
                conn.execute(f"UPDATE calendar_events SET {', '.join(updates)} WHERE id = ?;", params)
        return self.get_calendar_event_by_id(event_id)  # type: ignore

    def delete_calendar_event(self, event_id: int) -> bool:
        """Deletes a calendar event by ID."""
        conn = self._get_connection()
        with conn:
            cur = conn.execute("DELETE FROM calendar_events WHERE id = ?;", (event_id,))
            return cur.rowcount > 0

    def check_resource_availability(
        self,
        resource: str,
        start_at: str,
        end_at: str,
        exclude_event_id: int | None = None,
    ) -> dict[str, Any]:
        """Checks for conflicting reservations on a shared resource."""
        conn = self._get_connection()
        clean_res = resource.strip()
        query = """
            SELECT id, title, start_at, end_at, status
            FROM calendar_events
            WHERE resource = ? COLLATE NOCASE
              AND status IN ('scheduled', 'in_progress')
              AND NOT (end_at <= ? OR start_at >= ?)
        """
        params = [clean_res, start_at, end_at]
        if exclude_event_id:
            query += " AND id != ?"
            params.append(exclude_event_id)
        rows = conn.execute(query, params).fetchall()
        conflicts = [dict(r) for r in rows]
        return {
            "resource": clean_res,
            "available": len(conflicts) == 0,
            "conflicts": conflicts,
        }

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

    def get_room_audit_log(self, room_name_or_id: int | str, limit: int = 50) -> list[dict[str, Any]]:
        """Fetches recent audit log entries for a room."""
        room = self._resolve_room(room_name_or_id)
        if not room:
            return []
        conn = self._get_connection()
        rows = conn.execute(
            """
            SELECT * FROM audit_log
            WHERE room_id = ?
            ORDER BY id DESC
            LIMIT ?;
            """,
            (room["id"], limit),
        ).fetchall()
        return [dict(r) for r in rows]
