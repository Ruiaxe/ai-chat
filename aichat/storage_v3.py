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
import secrets
import string
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

import re

SCHEMA_FILE = Path(__file__).resolve().parent.parent / "migrations" / "v3" / "schema_v3.sql"
DEFAULT_V3_DB = DATA_DIR / "chat_v3.db"

CALLSIGN_REGEX = re.compile(r"^[\w\s.\-()]{1,64}$", re.UNICODE)


def validate_callsign(callsign: str) -> bool:
    """
    Validates an agent callsign.
    Allows letters, digits, spaces, hyphens, underscores, dots, and parentheses up to 64 chars.
    Rejects special characters like quotes, semicolons, angle brackets, slashes, etc.
    """
    if not callsign or not isinstance(callsign, str):
        return False
    clean = callsign.strip()
    if not clean or len(clean) > 64:
        return False
    return bool(CALLSIGN_REGEX.match(clean))


_UNSET = object()


class StorageV3:
    """Complete SQLite storage layer for ai-chat v3 according to schema_v3.sql."""

    _local = threading.local()

    def __init__(self, db_path: Path | str | None = None, logs_dir: Path = LOGS_DIR):
        from aichat.storage import validate_db_path
        self.db_path = validate_db_path(db_path, caller="StorageV3", default_path=DEFAULT_V3_DB)
        self.logs_dir = Path(logs_dir)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self._active_listeners: dict[int, int] = {}
        self._listeners_lock = threading.Lock()
        self._failed_ip_attempts: dict[str, list[float]] = {}
        self._ip_lock = threading.Lock()
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
        if hasattr(self, "_ip_lock"):
            with self._ip_lock:
                self._failed_ip_attempts.clear()
        if hasattr(self._local, "conns"):
            path_key = str(self.db_path.resolve())
            conn = self._local.conns.pop(path_key, None)
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def reset_ip_lockouts(self) -> None:
        """Resets all IP-based failure lockouts for this storage instance."""
        if hasattr(self, "_ip_lock"):
            with self._ip_lock:
                self._failed_ip_attempts.clear()

    @property
    def v3(self) -> "StorageV3":
        return self

    def is_v3(self) -> bool:
        return True

    @property
    def v3(self) -> "StorageV3":
        return self

    def mask_tokens_in_text(self, text: str, human_token: str = "") -> str:
        """Data Loss Prevention (DLP): Masks any secret tokens in text."""
        if not text:
            return text
        masked = text
        if human_token and len(human_token) >= 16:
            masked = masked.replace(human_token, "[REDACTED_TOKEN]")
        return masked

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
        self._ensure_v31_schema(conn)

    def _ensure_v31_schema(self, conn: sqlite3.Connection) -> None:
        """Ensures v3.1 columns and system_settings table exist on existing or newly created v3 databases."""
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(agents);").fetchall()}
        v31_cols = [
            ("harness", "TEXT NOT NULL DEFAULT 'other'"),
            ("wake_mode", "TEXT NOT NULL DEFAULT 'tool'"),
            ("listening_now", "INTEGER NOT NULL DEFAULT 0"),
            ("last_listen_at", "TEXT"),
            ("last_activity_at", "TEXT"),
            ("unconfirmed_batch_ids", "TEXT NOT NULL DEFAULT ''"),
            ("unconfirmed_batch_id", "TEXT NOT NULL DEFAULT ''"),
            ("unconfirmed_delivered_at", "TEXT"),
            ("stalled_alert_count", "INTEGER NOT NULL DEFAULT 0"),
            ("last_stalled_alert_at", "TEXT"),
        ]
        with conn:
            for col_name, col_def in v31_cols:
                if col_name not in cols:
                    conn.execute(f"ALTER TABLE agents ADD COLUMN {col_name} {col_def};")
            # In-memory counter reset: any lingering listening_now from server crash is reset to 0
            conn.execute("UPDATE agents SET listening_now = 0;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS system_settings (
                    key         TEXT PRIMARY KEY,
                    value       TEXT NOT NULL,
                    updated_at  TEXT NOT NULL
                );
                """
            )
            for k, v in [("t_idle_seconds", "180"), ("t_unread_seconds", "120"), ("max_wake_timeout", "600")]:
                conn.execute(
                    "INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES (?, ?, ?);",
                    (k, v, utc_now()),
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
                   a.default_role_id, ar.role_key as default_role_key,
                   a.harness, a.wake_mode, a.listening_now, a.last_listen_at, a.last_activity_at,
                   a.stalled_alert_count, a.last_stalled_alert_at, a.unconfirmed_batch_ids
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
                   a.default_role_id, ar.role_key as default_role_key,
                   a.harness, a.wake_mode, a.listening_now, a.last_listen_at, a.last_activity_at,
                   a.stalled_alert_count, a.last_stalled_alert_at, a.unconfirmed_batch_ids
            FROM principals p
            LEFT JOIN humans h ON p.id = h.principal_id
            LEFT JOIN agents a ON p.id = a.principal_id
            LEFT JOIN agent_roles ar ON a.default_role_id = ar.id
            WHERE p.name = ? COLLATE NOCASE OR p.display_name = ? COLLATE NOCASE;
            """,
            (name.strip(), name.strip()),
        ).fetchone()
        return dict(row) if row else None

    def list_principals(self, kind: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
        """Lists principals with optional kind and status filters."""
        conn = self._get_connection()
        query = """
            SELECT p.*, 
                   h.access_role, h.must_change_password, h.failed_logins, h.locked_until, h.last_login_at,
                   a.default_role_id, ar.role_key as default_role_key,
                   a.harness, a.wake_mode, a.listening_now, a.last_listen_at, a.last_activity_at,
                   a.stalled_alert_count, a.last_stalled_alert_at, a.unconfirmed_batch_ids
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

    def delete_principal(self, principal_id: int, actor_id: int | None = None, actor_name: str = "admin") -> bool:
        """Deletes a principal. Protects last admin."""
        self._ensure_not_last_active_admin(principal_id, "remover")
        p = self.get_principal_by_id(principal_id)
        p_name = p["name"] if p else str(principal_id)
        conn = self._get_connection()
        with conn:
            cursor = conn.execute("DELETE FROM principals WHERE id = ?;", (principal_id,))
            deleted = cursor.rowcount > 0
        if deleted:
            self.log_audit(
                actor_id=actor_id,
                actor_name=actor_name,
                action="delete_principal",
                target_type="principal",
                target_id=principal_id,
                details=f"Removeu principal '{p_name}' (#{principal_id})",
            )
        return deleted

    # ------------------------------------------------------------------ Humans & Passwords
    def create_human(
        self,
        username: str,
        password: str,
        display_name: str = "",
        access_role: str = "user",
        must_change_password: int = 1,
        actor_id: int | None = None,
        actor_name: str = "admin",
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
            self.log_audit(
                actor_id=actor_id,
                actor_name=actor_name,
                action="create_human",
                target_type="principal",
                target_id=pid,
                details=f"Criou utilizador '{username}' (role={access_role})",
            )
            return pid

    def list_humans(self) -> list[dict[str, Any]]:
        """Lists all human principals with their humans table data."""
        conn = self._get_connection()
        rows = conn.execute(
            """
            SELECT p.id, p.name, p.display_name, p.status, p.is_legacy, p.created_at,
                   h.access_role, h.must_change_password, h.failed_logins, h.locked_until, h.last_login_at
            FROM principals p
            JOIN humans h ON p.id = h.principal_id
            ORDER BY p.id ASC;
            """
        ).fetchall()
        return [dict(r) for r in rows]

    def update_human(
        self,
        principal_id: int,
        display_name: str | None = None,
        access_role: str | None = None,
        status: str | None = None,
        reset_password: str | None = None,
        actor_id: int | None = None,
        actor_name: str = "admin",
    ) -> dict[str, Any]:
        """
        Updates human profile, access role, status, or resets password.
        Enforces safeguard preventing demoting, deactivating, or removing the last active admin.
        """
        p = self.get_principal_by_id(principal_id)
        if not p or p.get("kind") != "human":
            raise ValueError(f"Utilizador #{principal_id} não encontrado.")

        # Safeguard: cannot deactivate or demote the last active admin
        if (access_role and access_role != "admin") or (status and status != "active"):
            self._ensure_not_last_active_admin(principal_id, "despromover ou desativar")

        conn = self._get_connection()
        p_updates = []
        p_params = []
        if display_name is not None and display_name.strip():
            p_updates.append("display_name = ?")
            p_params.append(display_name.strip())
        if status is not None and status.strip():
            p_updates.append("status = ?")
            p_params.append(status.strip())

        h_updates = []
        h_params = []
        if access_role is not None and access_role.strip():
            h_updates.append("access_role = ?")
            h_params.append(access_role.strip())
        if reset_password is not None and reset_password.strip():
            pwd_hash = hash_password(reset_password.strip())
            h_updates.append("password_hash = ?")
            h_params.append(pwd_hash)
            h_updates.append("must_change_password = 1")
            h_updates.append("failed_logins = 0")
            h_updates.append("locked_until = NULL")

        with conn:
            if p_updates:
                p_params.append(principal_id)
                conn.execute(f"UPDATE principals SET {', '.join(p_updates)} WHERE id = ?;", p_params)
            if h_updates:
                h_params.append(principal_id)
                conn.execute(f"UPDATE humans SET {', '.join(h_updates)} WHERE principal_id = ?;", h_params)

        self.log_audit(
            actor_id=actor_id,
            actor_name=actor_name,
            action="update_human",
            target_type="principal",
            target_id=principal_id,
            details=f"Atualizou utilizador '{p['name']}' (role={access_role}, status={status}, pwd_reset={bool(reset_password)})",
        )
        return self.get_principal_by_id(principal_id)  # type: ignore

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

    def reset_human_password(
        self,
        principal_id: int,
        actor_id: int | None = None,
        actor_name: str = "admin",
    ) -> str:
        """
        Resets human password with a secure random temporary password,
        marks must_change_password=1, clears failed_logins and locked_until,
        and logs audit without the password.
        Returns the plaintext temporary password (to be shown once to admin).
        """
        p = self.get_principal_by_id(principal_id)
        if not p or p.get("kind") != "human":
            raise ValueError(f"Utilizador #{principal_id} não encontrado.")

        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        temp_pwd = "Tmp-" + "".join(secrets.choice(alphabet) for _ in range(12))

        pwd_hash = hash_password(temp_pwd)
        conn = self._get_connection()
        with conn:
            conn.execute(
                """
                UPDATE humans
                SET password_hash = ?,
                    must_change_password = 1,
                    failed_logins = 0,
                    locked_until = NULL
                WHERE principal_id = ?;
                """,
                (pwd_hash, principal_id),
            )

        self.log_audit(
            actor_id=actor_id,
            actor_name=actor_name,
            action="reset_password",
            target_type="principal",
            target_id=principal_id,
            details=f"password reposta pelo admin {actor_name} para o utilizador {p['name']}",
        )
        return temp_pwd

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
        create_credential: bool = True,
        harness: str = "other",
        wake_mode: str = "tool",
        actor_id: int | None = None,
        actor_name: str = "admin",
    ) -> tuple[int, str]:
        """
        Creates an agent principal, agents row, and optional initial credential.
        Returns (principal_id, raw_agent_token). Plain token is never logged.
        """
        conn = self._get_connection()
        now_str = utc_now()
        clean_callsign = (callsign or "").strip()
        if not clean_callsign:
            raise ValueError("Callsign não pode ser vazio.")
        if not validate_callsign(clean_callsign):
            raise ValueError("Callsign inválido. Deve conter entre 1 e 64 caracteres alfanuméricos, espaços, hífen, underscore, ponto ou parênteses.")

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
                """
                INSERT INTO agents (principal_id, default_role_id, harness, wake_mode)
                VALUES (?, ?, ?, ?);
                """,
                (pid, target_role_id, harness, wake_mode),
            )
            raw_token = ""
            t_hint = ""
            if create_credential:
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

        self.log_audit(
            actor_id=actor_id,
            actor_name=actor_name,
            action="create_agent",
            target_type="principal",
            target_id=pid,
            details=f"Criou agente '{clean_callsign}' (status={status}, role_id={target_role_id}, hint={t_hint})",
        )
        return pid, raw_token

    def count_pending_agents(self) -> int:
        """Returns the count of agent principals currently in 'pending' status."""
        conn = self._get_connection()
        row = conn.execute("SELECT count(*) as cnt FROM principals WHERE kind = 'agent' AND status = 'pending';").fetchone()
        return row["cnt"] if row else 0

    def self_register_agent(self, callsign: str, description: str = "") -> dict[str, Any]:
        """
        Submits an agent self-registration request.
        Creates a principal with status 'pending' WITHOUT credentials.
        """
        clean_callsign = (callsign or "").strip()
        if not clean_callsign:
            raise ValueError("Callsign não pode ser vazio.")
        if not validate_callsign(clean_callsign):
            raise ValueError("Callsign inválido. Deve conter entre 1 e 64 caracteres alfanuméricos, espaços, hífen, underscore, ponto ou parênteses.")
        existing = self.get_principal_by_name(clean_callsign)
        if existing:
            raise ValueError(f"Agente ou utilizador com o nome '{clean_callsign}' já existe.")
        if self.count_pending_agents() >= 5:
            raise ValueError("Limite de pedidos de registo pendentes atingido (máximo 5). Aguarde pela aprovação de um administrador em /admin antes de submeter novos pedidos.")
        pid, _ = self.create_agent(
            callsign=clean_callsign,
            display_name=description or clean_callsign,
            status="pending",
            create_credential=False,
            actor_name="agent_self_register",
        )
        return {
            "status": "pending",
            "principal_id": pid,
            "callsign": clean_callsign,
            "message": f"Pedido de registo submetido para o agente '{clean_callsign}'. O estado está pendente de aprovação por um administrador em /admin. O token será emitido aquando da aprovação.",
        }

    def approve_agent(
        self,
        principal_id: int,
        actor_id: int | None = None,
        actor_name: str = "admin",
    ) -> dict[str, Any]:
        """
        Approves a pending agent principal:
        Sets status = 'active', generates initial credential token, logs to audit.
        Returns dict containing raw token (emitted once).
        """
        p = self.get_principal_by_id(principal_id)
        if not p or p.get("kind") != "agent":
            raise ValueError(f"Agente #{principal_id} não encontrado.")
        if p["status"] == "active":
            raise ValueError(f"Agente '{p['name']}' já se encontra ativo.")

        conn = self._get_connection()
        now_str = utc_now()
        raw_token = new_agent_token()
        t_hash = hash_token(raw_token)
        t_hint = token_hint(raw_token)

        with conn:
            conn.execute("UPDATE principals SET status = 'active' WHERE id = ?;", (principal_id,))
            conn.execute(
                """
                INSERT INTO credentials (principal_id, token_hash, token_hint, created_at)
                VALUES (?, ?, ?, ?);
                """,
                (principal_id, t_hash, t_hint, now_str),
            )

        self.log_audit(
            actor_id=actor_id,
            actor_name=actor_name,
            action="approve_agent",
            target_type="principal",
            target_id=principal_id,
            details=f"Aprovou agente '{p['name']}' (hint={t_hint})",
        )
        updated = self.get_principal_by_id(principal_id) or {}
        return {
            "status": "active",
            "principal_id": principal_id,
            "callsign": p["name"],
            "token": raw_token,
            "token_hint": t_hint,
            "agent": updated,
        }

    def update_agent_wake_profile(
        self,
        principal_id: int,
        harness: str | None = None,
        wake_mode: str | None = None,
        actor_id: int | None = None,
        actor_name: str = "admin",
    ) -> dict[str, Any]:
        """Updates agent harness and wake_mode profile."""
        p = self.get_principal_by_id(principal_id)
        if not p or p.get("kind") != "agent":
            raise ValueError(f"Agente #{principal_id} não encontrado.")

        updates = []
        params = []
        if harness is not None:
            if harness not in ("claude-code", "antigravity", "opencode", "other"):
                raise ValueError(f"Harness inválido: '{harness}'. Opções: claude-code, antigravity, opencode, other")
            updates.append("harness = ?")
            params.append(harness)
        if wake_mode is not None:
            if wake_mode not in ("hook", "background", "tool"):
                raise ValueError(f"Wake mode inválido: '{wake_mode}'. Opções: hook, background, tool")
            updates.append("wake_mode = ?")
            params.append(wake_mode)

        if updates:
            conn = self._get_connection()
            params.append(principal_id)
            with conn:
                conn.execute(f"UPDATE agents SET {', '.join(updates)} WHERE principal_id = ?;", params)

        self.log_audit(
            actor_id=actor_id,
            actor_name=actor_name,
            action="update_agent_wake_profile",
            target_type="principal",
            target_id=principal_id,
            details=f"Atualizou perfil de wake do agente '{p['name']}' (harness={harness}, wake_mode={wake_mode})",
        )
        return self.get_principal_by_id(principal_id) or {}

    def get_setting(self, key: str, default: str = "") -> str:
        """Retrieves system setting by key."""
        conn = self._get_connection()
        row = conn.execute("SELECT value FROM system_settings WHERE key = ?;", (key,)).fetchone()
        return str(row["value"]) if row else default

    def set_setting(self, key: str, value: str) -> None:
        """Sets or updates system setting."""
        conn = self._get_connection()
        now_str = utc_now()
        with conn:
            conn.execute(
                """
                INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at;
                """,
                (key, str(value), now_str),
            )

    def get_system_thresholds(self) -> dict[str, int]:
        """Returns configured system thresholds for liveliness and wake-up."""
        try:
            t_idle = int(self.get_setting("t_idle_seconds", "180"))
        except (ValueError, TypeError):
            t_idle = 180
        try:
            t_unread = int(self.get_setting("t_unread_seconds", "120"))
        except (ValueError, TypeError):
            t_unread = 120
        try:
            max_wake = int(self.get_setting("max_wake_timeout", "600"))
        except (ValueError, TypeError):
            max_wake = 600
        return {
            "t_idle_seconds": t_idle,
            "t_unread_seconds": t_unread,
            "max_wake_timeout": max_wake,
            "t_idle_minutes": max(1, round(t_idle / 60)),
            "t_unread_minutes": max(1, round(t_unread / 60)),
        }

    def is_agent_listening(self, principal_id: int | str) -> bool:
        """Returns True if agent currently has at least one active listening connection in-memory."""
        pid = principal_id
        if isinstance(principal_id, str):
            p = self.get_principal_by_name(principal_id)
            if not p:
                return False
            pid = p["id"]
        try:
            pid_int = int(pid)
        except (ValueError, TypeError):
            return False
        with self._listeners_lock:
            return self._active_listeners.get(pid_int, 0) > 0

    def set_agent_listening(self, principal_id: int | str, listening: bool) -> None:
        """Sets listening_now flag and last_listen_at for an agent using in-memory counter."""
        pid = principal_id
        if isinstance(principal_id, str):
            p = self.get_principal_by_name(principal_id)
            if not p:
                return
            pid = p["id"]
        try:
            pid_int = int(pid)
        except (ValueError, TypeError):
            return

        with self._listeners_lock:
            if listening:
                self._active_listeners[pid_int] = self._active_listeners.get(pid_int, 0) + 1
            else:
                curr = self._active_listeners.get(pid_int, 0)
                if curr > 1:
                    self._active_listeners[pid_int] = curr - 1
                else:
                    self._active_listeners.pop(pid_int, None)
            is_active = self._active_listeners.get(pid_int, 0) > 0

        conn = self._get_connection()
        now_str = utc_now()
        with conn:
            if is_active:
                conn.execute(
                    "UPDATE agents SET listening_now = 1, last_listen_at = ? WHERE principal_id = ?;",
                    (now_str, pid_int),
                )
            else:
                conn.execute(
                    "UPDATE agents SET listening_now = 0 WHERE principal_id = ?;",
                    (pid_int,),
                )

    def record_agent_activity(self, principal_id: int | str) -> None:
        """Records authenticated activity timestamp for an agent."""
        pid = principal_id
        if isinstance(principal_id, str):
            p = self.get_principal_by_name(principal_id)
            if not p:
                return
            pid = p["id"]
        try:
            pid_int = int(pid)
        except (ValueError, TypeError):
            return
        conn = self._get_connection()
        now_str = utc_now()
        with conn:
            conn.execute(
                "UPDATE agents SET last_activity_at = ? WHERE principal_id = ?;",
                (now_str, pid_int),
            )

    def get_unread_directed_messages_for_agent(
        self,
        principal_id: int,
        room_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """
        Returns all unread messages in accessible rooms that are directly addressed to this agent
        (either by principal_id or by the agent's role in the respective room).
        """
        conn = self._get_connection()
        query = """
            SELECT m.id, m.room_id, r.name as room_name, m.created_at, m.sender_id, m.sender_name,
                   m.content, m.message_type
            FROM messages m
            JOIN rooms r ON m.room_id = r.id
            JOIN room_access ra ON m.room_id = ra.room_id AND ra.principal_id = ?
            LEFT JOIN read_cursors rc ON rc.room_id = m.room_id AND rc.principal_id = ?
            JOIN message_recipients mr ON mr.message_id = m.id
            WHERE m.sender_id != ?
              AND m.id > COALESCE(rc.last_message_id, 0)
              AND (
                (mr.target_kind = 'principal' AND mr.target_id = ?)
                OR (mr.target_kind = 'role' AND mr.target_id IN (
                    SELECT COALESCE(ra2.role_id, a.default_role_id)
                    FROM agents a
                    LEFT JOIN room_access ra2 ON ra2.room_id = m.room_id AND ra2.principal_id = a.principal_id
                    WHERE a.principal_id = ?
                ))
              )
        """
        params: list[Any] = [principal_id, principal_id, principal_id, principal_id, principal_id]
        if room_id is not None:
            query += " AND m.room_id = ?"
            params.append(room_id)
        query += " GROUP BY m.id ORDER BY m.id ASC;"
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_agent_liveliness(self, principal_id: int | str) -> dict[str, Any]:
        """
        Computes the 5 liveliness states for an agent:
        🟢 a escutar (is_agent_listening == True)
        🔵 a trabalhar (not listening && (last_activity <= T_idle OR has recent in_progress task <= 30m))
        💤 sem trabalho (not listening && unread_directed_count == 0)
        🔴 parado (not listening && unread_directed_count > 0 && unread_age >= T_unread && idle_age >= T_idle && no recent in_progress task)
        ⚫ offline (not listening && unread_directed_count == 0 && (last_activity is None or idle_age > 24h))
        """
        if isinstance(principal_id, int):
            agent = self.get_principal_by_id(principal_id)
        else:
            agent = self.get_principal_by_name(str(principal_id))
            if agent:
                principal_id = agent["id"]

        if not agent or agent.get("kind") != "agent":
            return {"state": "offline", "state_icon": "⚫", "state_label": "offline", "state_badge": "⚫ offline"}

        pid = agent["id"]
        thresholds = self.get_system_thresholds()
        t_idle = thresholds["t_idle_seconds"]
        t_unread = thresholds["t_unread_seconds"]

        # 🟢 a escutar: check in-memory counter
        listening_now = self.is_agent_listening(pid)
        if listening_now:
            return {
                "state": "listening",
                "state_icon": "🟢",
                "state_label": "a escutar",
                "state_badge": "🟢 a escutar",
                "listening_now": 1,
                "last_listen_at": agent.get("last_listen_at"),
                "last_activity_at": agent.get("last_activity_at"),
                "unread_directed_count": 0,
            }

        now = datetime.now(timezone.utc)
        def _parse_iso(ts_str: str | None) -> datetime | None:
            if not ts_str:
                return None
            try:
                clean = ts_str.replace("Z", "+00:00")
                return datetime.fromisoformat(clean)
            except Exception:
                return None

        last_act_dt = _parse_iso(agent.get("last_activity_at"))
        idle_age = (now - last_act_dt).total_seconds() if last_act_dt else float("inf")

        # Check if agent has an active in_progress task updated recently (<= 1800s / 30m)
        conn = self._get_connection()
        task_row = conn.execute(
            """
            SELECT id, title, updated_at FROM tasks
            WHERE assignee_id = ? AND status = 'in_progress'
            ORDER BY updated_at DESC LIMIT 1;
            """,
            (pid,),
        ).fetchone()

        has_recent_task = False
        task_info: dict[str, Any] = {}
        if task_row:
            t_updated_dt = _parse_iso(task_row["updated_at"])
            task_age = (now - t_updated_dt).total_seconds() if t_updated_dt else float("inf")
            if task_age <= 1800:
                has_recent_task = True
                task_info = {
                    "active_task_id": task_row["id"],
                    "active_task_title": task_row["title"],
                    "task_age_seconds": int(task_age),
                }

        unread_msgs = self.get_unread_directed_messages_for_agent(pid)
        unread_count = len(unread_msgs)

        # 🔵 a trabalhar: not listening, but had activity within T_idle OR has recent in_progress task
        if (last_act_dt and idle_age <= t_idle) or has_recent_task:
            return {
                "state": "working",
                "state_icon": "🔵",
                "state_label": "a trabalhar",
                "state_badge": "🔵 a trabalhar",
                "listening_now": 0,
                "last_listen_at": agent.get("last_listen_at"),
                "last_activity_at": agent.get("last_activity_at"),
                "idle_seconds": int(idle_age) if last_act_dt else None,
                "unread_directed_count": unread_count,
                **task_info,
            }

        # Check unread directed messages (only stalled if NOT working on a recent task)
        if unread_count > 0:
            oldest_unread_dt = _parse_iso(unread_msgs[0]["created_at"])
            unread_age = (now - oldest_unread_dt).total_seconds() if oldest_unread_dt else 0
            if unread_age >= t_unread and idle_age >= t_idle:
                return {
                    "state": "stalled",
                    "state_icon": "🔴",
                    "state_label": "parado",
                    "state_badge": "🔴 parado",
                    "listening_now": 0,
                    "last_listen_at": agent.get("last_listen_at"),
                    "last_activity_at": agent.get("last_activity_at"),
                    "unread_directed_count": unread_count,
                    "unread_age_seconds": int(unread_age),
                    "idle_seconds": int(idle_age) if last_act_dt else None,
                    "oldest_unread_at": unread_msgs[0]["created_at"],
                }
            else:
                return {
                    "state": "idle",
                    "state_icon": "💤",
                    "state_label": "sem trabalho",
                    "state_badge": "💤 sem trabalho",
                    "listening_now": 0,
                    "last_listen_at": agent.get("last_listen_at"),
                    "last_activity_at": agent.get("last_activity_at"),
                    "unread_directed_count": unread_count,
                }

        # No unread messages directed to agent
        if last_act_dt is None or idle_age > 86400:
            return {
                "state": "offline",
                "state_icon": "⚫",
                "state_label": "offline",
                "state_badge": "⚫ offline",
                "listening_now": 0,
                "last_listen_at": agent.get("last_listen_at"),
                "last_activity_at": agent.get("last_activity_at"),
                "unread_directed_count": 0,
            }

        return {
            "state": "idle",
            "state_icon": "💤",
            "state_label": "sem trabalho",
            "state_badge": "💤 sem trabalho",
            "listening_now": 0,
            "last_listen_at": agent.get("last_listen_at"),
            "last_activity_at": agent.get("last_activity_at"),
            "unread_directed_count": 0,
            "idle_seconds": int(idle_age) if last_act_dt else None,
        }

    def get_room_team_status(self, room_name_or_id: str | int) -> list[dict[str, Any]]:
        """
        Returns presence and liveliness status for all room members:
        Name, role in room, 5-state liveliness icon and label, unread count.
        No tokens or secrets.
        """
        room = self._resolve_room(room_name_or_id)
        if not room:
            return []
        members = self.list_room_members(room["id"])
        result = []
        for m in members:
            p_id = m["principal_id"]
            kind = m["kind"]
            name = m["name"]
            role_title = m.get("room_role_name") or m.get("room_role_key") or m.get("default_role_name") or ("Administrador" if m.get("access_role") == "admin" else "Membro")

            if kind == "agent":
                liv = self.get_agent_liveliness(p_id)
                unread = self.get_unread_directed_messages_for_agent(p_id, room_id=room["id"])
                badge = liv.get("state_badge") or f"{liv['state_icon']} {liv['state_label']}"
                result.append({
                    "principal_id": p_id,
                    "name": name,
                    "kind": "agent",
                    "role": role_title,
                    "state": liv["state"],
                    "state_icon": liv["state_icon"],
                    "state_label": liv["state_label"],
                    "state_badge": badge,
                    "liveliness": {
                        "state": liv["state"],
                        "state_badge": badge,
                        "listening_now": liv.get("listening_now", 0) == 1,
                        "unread_count": len(unread),
                    },
                    "unread_directed_count": len(unread),
                    "unread_messages": unread,
                    "last_activity_at": liv.get("last_activity_at"),
                    "last_listen_at": liv.get("last_listen_at"),
                })
            else:
                result.append({
                    "principal_id": p_id,
                    "name": name,
                    "kind": "human",
                    "role": role_title,
                    "state": "idle",
                    "state_icon": "🟢",
                    "state_label": "ativo",
                    "state_badge": "🟢 ativo",
                    "liveliness": {
                        "state": "idle",
                        "state_badge": "🟢 ativo",
                        "listening_now": True,
                        "unread_count": 0,
                    },
                    "unread_directed_count": 0,
                    "unread_messages": [],
                    "last_activity_at": m.get("last_login_at"),
                    "last_listen_at": None,
                })
        return result

    def get_unconfirmed_batch_info(self, principal_id: int) -> dict[str, Any]:
        """Returns details about unconfirmed delivered batch."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT unconfirmed_batch_ids, unconfirmed_batch_id, unconfirmed_delivered_at FROM agents WHERE principal_id = ?;",
            (principal_id,),
        ).fetchone()
        if not row or not row["unconfirmed_batch_ids"]:
            return {"batch_id": "", "message_ids": [], "delivered_at": None}
        raw = str(row["unconfirmed_batch_ids"]).strip()
        if not raw:
            return {"batch_id": "", "message_ids": [], "delivered_at": None}
        try:
            ids = [int(x.strip()) for x in raw.split(",") if x.strip().isdigit()]
        except Exception:
            ids = []
        return {
            "batch_id": str(row["unconfirmed_batch_id"] or ""),
            "message_ids": ids,
            "delivered_at": row["unconfirmed_delivered_at"],
        }

    def get_unconfirmed_batch(self, principal_id: int) -> list[int]:
        """Returns message IDs for unconfirmed delivered batch, if any."""
        info = self.get_unconfirmed_batch_info(principal_id)
        return info["message_ids"]

    def set_unconfirmed_batch(self, principal_id: int, message_ids: list[int], batch_id: str = "") -> None:
        """Records an unconfirmed delivery batch for reliable at-least-once delivery."""
        conn = self._get_connection()
        val = ",".join(str(i) for i in message_ids) if message_ids else ""
        now_str = utc_now() if message_ids else None
        with conn:
            conn.execute(
                """
                UPDATE agents
                SET unconfirmed_batch_ids = ?, unconfirmed_batch_id = ?, unconfirmed_delivered_at = ?
                WHERE principal_id = ?;
                """,
                (val, str(batch_id or ""), now_str, principal_id),
            )

    def confirm_batch(self, principal_id: int, ack_id: int | str | None = None) -> None:
        """
        Confirms delivery batch. Clears unconfirmed batch and advances read cursor.
        """
        conn = self._get_connection()
        info = self.get_unconfirmed_batch_info(principal_id)
        unconfirmed = info["message_ids"]
        max_unconfirmed = max(unconfirmed) if unconfirmed else 0
        effective_ack = 0
        if isinstance(ack_id, int) and ack_id > 0:
            effective_ack = max(ack_id, max_unconfirmed)
        elif isinstance(ack_id, str) and ack_id.isdigit():
            effective_ack = max(int(ack_id), max_unconfirmed)
        else:
            effective_ack = max_unconfirmed

        with conn:
            conn.execute(
                """
                UPDATE agents
                SET unconfirmed_batch_ids = '', unconfirmed_batch_id = '', unconfirmed_delivered_at = NULL
                WHERE principal_id = ?;
                """,
                (principal_id,),
            )
            if effective_ack > 0:
                rows = conn.execute(
                    "SELECT DISTINCT room_id FROM messages WHERE id <= ?;",
                    (effective_ack,),
                ).fetchall()
                for r in rows:
                    rid = r["room_id"]
                    has_acc = conn.execute(
                        "SELECT 1 FROM room_access WHERE room_id = ? AND principal_id = ?;",
                        (rid, principal_id),
                    ).fetchone()
                    if has_acc:
                        self.update_read_cursor(principal_id, rid, effective_ack)

    def list_stalled_agents_to_alert(self, t_idle: int = 600, t_unread: int = 600) -> list[dict[str, Any]]:
        """
        Finds stalled agents due for an alert according to backoff:
        count 0: immediate (0m)
        count 1: 10m (600s)
        count 2: 30m (1800s)
        count >= 3: 60m (3600s)
        """
        conn = self._get_connection()
        agents = conn.execute(
            """
            SELECT p.id as principal_id, p.name, p.status,
                    a.listening_now, a.last_listen_at, a.last_activity_at,
                    a.stalled_alert_count, a.last_stalled_alert_at, p.created_at as registered_at
            FROM principals p
            JOIN agents a ON p.id = a.principal_id
            WHERE p.status = 'active';
            """
        ).fetchall()

        now = datetime.now(timezone.utc)
        def _parse_iso(ts_str: str | None) -> datetime | None:
            if not ts_str:
                return None
            try:
                return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                return None

        candidates = []
        for ag in agents:
            pid = ag["principal_id"]
            if self.is_agent_listening(pid):
                continue

            # If agent is working on an in_progress task updated recently (<= 1800s), not stalled
            t_row = conn.execute(
                """
                SELECT updated_at FROM tasks
                WHERE assignee_id = ? AND status = 'in_progress'
                ORDER BY updated_at DESC LIMIT 1;
                """,
                (pid,),
            ).fetchone()
            if t_row:
                t_dt = _parse_iso(t_row["updated_at"])
                if t_dt and (now - t_dt).total_seconds() <= 1800:
                    continue

            unread_msgs = self.get_unread_directed_messages_for_agent(pid)
            if not unread_msgs:
                continue

            last_act_dt = _parse_iso(ag["last_activity_at"]) or _parse_iso(ag["registered_at"])
            idle_age = (now - last_act_dt).total_seconds() if last_act_dt else float("inf")
            oldest_unread_dt = _parse_iso(unread_msgs[0]["created_at"])
            unread_age = (now - oldest_unread_dt).total_seconds() if oldest_unread_dt else 0

            if idle_age < t_idle or unread_age < t_unread:
                continue

            # Agent is stalled! Check backoff
            count = ag["stalled_alert_count"] or 0
            last_alert_dt = _parse_iso(ag["last_stalled_alert_at"])

            should_alert = False
            if count == 0 or last_alert_dt is None:
                should_alert = True
            else:
                elapsed_since_last_alert = (now - last_alert_dt).total_seconds()
                if count == 1 and elapsed_since_last_alert >= 600:
                    should_alert = True
                elif count == 2 and elapsed_since_last_alert >= 1800:
                    should_alert = True
                elif count >= 3 and elapsed_since_last_alert >= 3600:
                    should_alert = True

            if should_alert:
                candidates.append({
                    "principal_id": pid,
                    "name": ag["name"],
                    "unread_count": len(unread_msgs),
                    "unread_minutes": max(1, int(unread_age // 60)),
                    "activity_minutes": max(1, int(idle_age // 60)) if idle_age != float("inf") else 0,
                    "room_id": unread_msgs[0]["room_id"],
                    "room_name": unread_msgs[0]["room_name"],
                    "stalled_alert_count": count,
                })
        return candidates

    def record_stalled_alert(self, principal_id: int) -> None:
        """Increments stalled_alert_count and updates last_stalled_alert_at."""
        conn = self._get_connection()
        now_str = utc_now()
        with conn:
            conn.execute(
                """
                UPDATE agents
                SET stalled_alert_count = COALESCE(stalled_alert_count, 0) + 1,
                    last_stalled_alert_at = ?
                WHERE principal_id = ?;
                """,
                (now_str, principal_id),
            )

    def clear_stalled_alert(self, principal_id: int) -> bool:
        """
        Resets stalled alert state if agent was stalled.
        Returns True if the agent was previously alerted as stalled (so recovery message can be sent).
        """
        conn = self._get_connection()
        row = conn.execute(
            "SELECT stalled_alert_count FROM agents WHERE principal_id = ?;",
            (principal_id,),
        ).fetchone()
        was_stalled = bool(row and (row["stalled_alert_count"] or 0) > 0)
        if was_stalled:
            with conn:
                conn.execute(
                    """
                    UPDATE agents
                    SET stalled_alert_count = 0, last_stalled_alert_at = NULL
                    WHERE principal_id = ?;
                    """,
                    (principal_id,),
                )
        return was_stalled

    def get_messages_by_ids(self, message_ids: list[int]) -> list[dict[str, Any]]:
        """Retrieves specific messages by their IDs."""
        if not message_ids:
            return []
        conn = self._get_connection()
        placeholders = ",".join("?" for _ in message_ids)
        rows = conn.execute(
            f"""
            SELECT m.*, r.name as room_name, p.display_name as sender_display_name, p.name as sender_username
            FROM messages m
            JOIN rooms r ON m.room_id = r.id
            LEFT JOIN principals p ON m.sender_id = p.id
            WHERE m.id IN ({placeholders})
            ORDER BY m.id ASC;
            """,
            message_ids,
        ).fetchall()
        msg_ids = [r["id"] for r in rows]
        reactions_map = self._get_reactions_map(msg_ids)
        recipients_map = self._get_recipients_map(msg_ids)
        result = []
        for r in rows:
            m = dict(r)
            m["metadata"] = json.loads(m["metadata"]) if m["metadata"] else {}
            m["sender"] = m["sender_name"]
            m["display_name"] = m.get("sender_display_name") or m["sender_name"]
            m["sender_username"] = m.get("sender_username") or m["sender_name"]
            m["role"] = m["sender_kind"]
            m["reactions"] = reactions_map.get(m["id"], [])
            recips = recipients_map.get(m["id"], [{"target_kind": "all", "target_id": None, "target_name": "all"}])
            m["recipients"] = recips
            m["to"] = self._format_to_list(recips)
            result.append(m)
        return result

    def list_agents(self) -> list[dict[str, Any]]:
        """Lists all agent principals with default role information and credential summaries."""
        conn = self._get_connection()
        rows = conn.execute(
            """
            SELECT p.id, p.name, p.display_name, p.status, p.is_system, p.is_legacy, p.created_at,
                   a.default_role_id, ar.role_key as default_role_key, ar.display_name as default_role_name,
                   a.harness, a.wake_mode, a.listening_now, a.last_listen_at, a.last_activity_at,
                   a.stalled_alert_count, a.last_stalled_alert_at, a.unconfirmed_batch_ids
            FROM principals p
            JOIN agents a ON p.id = a.principal_id
            LEFT JOIN agent_roles ar ON a.default_role_id = ar.id
            ORDER BY p.id ASC;
            """
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["credentials"] = self.list_agent_credentials(d["id"])
            d["liveliness"] = self.get_agent_liveliness(d["id"])
            result.append(d)
        return result

    def update_agent(
        self,
        principal_id: int,
        display_name: str | None = None,
        status: str | None = None,
        default_role_id: int | None = None,
        actor_id: int | None = None,
        actor_name: str = "admin",
    ) -> dict[str, Any]:
        """Updates agent display name, status, or default role."""
        p = self.get_principal_by_id(principal_id)
        if not p or p.get("kind") != "agent":
            raise ValueError(f"Agente #{principal_id} não encontrado.")

        conn = self._get_connection()
        p_updates = []
        p_params = []
        if display_name is not None and display_name.strip():
            p_updates.append("display_name = ?")
            p_params.append(display_name.strip())
        if status is not None and status.strip():
            p_updates.append("status = ?")
            p_params.append(status.strip())

        a_updates = []
        a_params = []
        if default_role_id is not None:
            a_updates.append("default_role_id = ?")
            a_params.append(default_role_id if default_role_id > 0 else None)

        with conn:
            if p_updates:
                p_params.append(principal_id)
                conn.execute(f"UPDATE principals SET {', '.join(p_updates)} WHERE id = ?;", p_params)
            if a_updates:
                a_params.append(principal_id)
                conn.execute(f"UPDATE agents SET {', '.join(a_updates)} WHERE principal_id = ?;", a_params)

        self.log_audit(
            actor_id=actor_id,
            actor_name=actor_name,
            action="update_agent",
            target_type="principal",
            target_id=principal_id,
            details=f"Atualizou agente '{p['name']}' (status={status}, default_role_id={default_role_id})",
        )
        return self.get_principal_by_id(principal_id)  # type: ignore

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

    def verify_member_token(self, room_name: str, member_name: str, token: str) -> tuple[bool, str]:
        """
        Validates the member's authentication token and room permissions in v3.
        Returns (is_valid, error_msg).
        """
        clean_room = (room_name or "").strip()
        clean_member = (member_name or "").strip()
        clean_token = (token or "").strip()

        if not clean_token:
            return False, f"Acesso negado: Remetente '{clean_member}' não autenticado (token em falta)."

        principal, err = self.authenticate_agent_token(clean_token)
        if not principal:
            principal = self.authenticate_human_session(clean_token)
        if not principal:
            return False, f"Acesso negado: Credenciais inválidas para '{clean_member}'."

        if principal.get("status") != "active":
            return False, f"Acesso negado: O registo de '{clean_member}' está desativado pelo supervisor (status='{principal.get('status')}')."

        p_name = principal.get("name", "")
        p_display = principal.get("display_name", "")
        if clean_member and clean_member.lower() not in (p_name.lower(), p_display.lower()):
            return False, f"Impersonation blocked: Remetente '{clean_member}' é uma identidade protegida. Token fornecido pertence a '{p_name}'."

        if clean_room:
            room = self.get_room(clean_room)
            if not room:
                return False, f"Acesso negado: Sala '{clean_room}' não existe."
            if not self.authorize(principal, "write_room", {"room_id": room["id"]}):
                return False, f"Acesso negado: '{p_name}' não tem permissão de escrita na sala '{clean_room}'."

        return True, ""

    def rotate_agent_token(
        self,
        principal_id: int,
        revoke_old: bool = True,
        revoke_previous: bool | None = None,
        actor_id: int | None = None,
        actor_name: str = "admin",
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

        self.log_audit(
            actor_id=actor_id,
            actor_name=actor_name,
            action="rotate_token",
            target_type="credential",
            target_id=principal_id,
            details=f"Rodou token do agente #{principal_id} (novo hint={t_hint})",
        )
        return raw_token, t_hint

    def revoke_credential_by_hint(
        self,
        principal_id: int,
        hint: str,
        actor_id: int | None = None,
        actor_name: str = "admin",
    ) -> bool:
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
            revoked = cursor.rowcount > 0
        if revoked:
            self.log_audit(
                actor_id=actor_id,
                actor_name=actor_name,
                action="revoke_token",
                target_type="credential",
                target_id=principal_id,
                details=f"Revogou token hint={hint.strip()} do agente #{principal_id}",
            )
        return revoked

    def revoke_agent_credential(
        self,
        principal_id: int,
        credential_id: int | None = None,
        hint: str | None = None,
        actor_id: int | None = None,
        actor_name: str = "admin",
    ) -> bool:
        """Revokes an agent credential by ID or hint."""
        if hint:
            return self.revoke_credential_by_hint(principal_id, hint, actor_id=actor_id, actor_name=actor_name)
        if credential_id is not None:
            conn = self._get_connection()
            now_str = utc_now()
            with conn:
                cursor = conn.execute(
                    "UPDATE credentials SET revoked_at = ? WHERE id = ? AND principal_id = ? AND revoked_at IS NULL;",
                    (now_str, credential_id, principal_id),
                )
                revoked = cursor.rowcount > 0
            if revoked:
                self.log_audit(
                    actor_id=actor_id,
                    actor_name=actor_name,
                    action="revoke_token",
                    target_type="credential",
                    target_id=principal_id,
                    details=f"Revogou credencial #{credential_id} do agente #{principal_id}",
                )
            return revoked
        return False

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

    def get_role_usage(self, role_id: int) -> dict[str, Any]:
        """
        Returns details of where a role is used:
        - default_agents: agents having this as default role
        - room_agents: agents having this role in specific rooms
        """
        role = self.get_role_by_id(role_id)
        if not role:
            raise ValueError(f"Papel #{role_id} não encontrado.")
        conn = self._get_connection()
        def_rows = conn.execute(
            """
            SELECT p.id, p.name, p.display_name, p.status
            FROM agents a
            JOIN principals p ON a.principal_id = p.id
            WHERE a.default_role_id = ?
            ORDER BY p.name ASC;
            """,
            (role_id,),
        ).fetchall()
        default_agents = [dict(r) for r in def_rows]

        room_rows = conn.execute(
            """
            SELECT p.id as principal_id, p.name as agent_name, p.display_name as agent_display_name,
                   r.id as room_id, r.name as room_name, r.is_archived
            FROM room_access ra
            JOIN principals p ON ra.principal_id = p.id
            JOIN rooms r ON ra.room_id = r.id
            WHERE ra.role_id = ?
            ORDER BY r.name ASC, p.name ASC;
            """,
            (role_id,),
        ).fetchall()
        room_agents = [dict(r) for r in room_rows]

        total_uses = len(default_agents) + len(room_agents)
        return {
            "role_id": role["id"],
            "role_key": role["role_key"],
            "display_name": role["display_name"],
            "default_agents": default_agents,
            "room_agents": room_agents,
            "total_uses": total_uses,
            "in_use": total_uses > 0,
        }

    def list_roles(self) -> list[dict[str, Any]]:
        """Lists all agent roles with usage summary."""
        conn = self._get_connection()
        rows = conn.execute("SELECT * FROM agent_roles ORDER BY id ASC;").fetchall()
        roles = []
        for r in rows:
            d = dict(r)
            d["usage"] = self.get_role_usage(d["id"])
            roles.append(d)
        return roles

    def create_role(
        self,
        role_key: str,
        display_name: str,
        description: str = "",
        reminder_text: str = "",
        actor_id: int | None = None,
        actor_name: str = "admin",
    ) -> dict[str, Any]:
        """Creates a new agent role and logs audit."""
        clean_key = role_key.strip().lower()
        clean_disp = display_name.strip()
        conn = self._get_connection()
        now_str = utc_now()
        with conn:
            cursor = conn.execute(
                """
                INSERT INTO agent_roles (role_key, display_name, description, reminder_text, is_builtin, updated_at, updated_by)
                VALUES (?, ?, ?, ?, 0, ?, ?);
                """,
                (clean_key, clean_disp, description.strip(), reminder_text.strip(), now_str, actor_id),
            )
            role_id = cursor.lastrowid

        self.log_audit(
            actor_id=actor_id,
            actor_name=actor_name,
            action="create_role",
            target_type="role",
            target_id=role_id,
            details=f"Criou papel '{clean_key}' ({clean_disp})",
        )
        return self.get_role_by_id(role_id)  # type: ignore

    def update_role(
        self,
        role_id: int,
        display_name: str | None = None,
        description: str | None = None,
        reminder_text: str | None = None,
        actor_id: int | None = None,
        actor_name: str = "admin",
    ) -> dict[str, Any]:
        """Updates agent role fields (reminder_text, description, display_name) and logs audit."""
        role = self.get_role_by_id(role_id)
        if not role:
            raise ValueError(f"Papel #{role_id} não encontrado.")

        updates = ["updated_at = ?", "updated_by = ?"]
        now_str = utc_now()
        params: list[Any] = [now_str, actor_id]

        if display_name is not None and display_name.strip():
            updates.append("display_name = ?")
            params.append(display_name.strip())
        if description is not None:
            updates.append("description = ?")
            params.append(description.strip())
        if reminder_text is not None:
            updates.append("reminder_text = ?")
            params.append(reminder_text.strip())

        params.append(role_id)
        conn = self._get_connection()
        with conn:
            conn.execute(f"UPDATE agent_roles SET {', '.join(updates)} WHERE id = ?;", params)

        self.log_audit(
            actor_id=actor_id,
            actor_name=actor_name,
            action="update_role",
            target_type="role",
            target_id=role_id,
            details=f"Atualizou papel '{role['role_key']}' (#{role_id})",
        )
        return self.get_role_by_id(role_id)  # type: ignore

    def delete_role(self, role_id: int, actor_id: int | None = None, actor_name: str = "admin") -> bool:
        """Deletes an agent role if it's not a builtin role and not in use."""
        role = self.get_role_by_id(role_id)
        if not role:
            return False
        if role.get("is_builtin"):
            raise ValueError(f"Papel do sistema '{role['role_key']}' não pode ser removido.")

        usage = self.get_role_usage(role_id)
        if usage["in_use"]:
            details_list = []
            if usage["default_agents"]:
                names = ", ".join(a.get("display_name") or a["name"] for a in usage["default_agents"])
                details_list.append(f"papel por defeito de: {names}")
            if usage["room_agents"]:
                rooms_info = ", ".join(f"{a.get('agent_display_name') or a['agent_name']} em #{a['room_name']}" for a in usage["room_agents"])
                details_list.append(f"atribuído na(s) sala(s): {rooms_info}")
            reason = "; ".join(details_list)
            raise ValueError(f"Papel '{role['display_name']}' está em uso ({reason}) e não pode ser removido.")

        conn = self._get_connection()
        with conn:
            cur = conn.execute("DELETE FROM agent_roles WHERE id = ?;", (role_id,))
            deleted = cur.rowcount > 0
        if deleted:
            self.log_audit(
                actor_id=actor_id,
                actor_name=actor_name,
                action="delete_role",
                target_type="role",
                target_id=role_id,
                details=f"Removeu papel '{role['role_key']}' (#{role_id})",
            )
        return deleted

    def update_role_reminder(self, role_id: int, reminder_text: str, updated_by_id: int | None = None) -> bool:
        """Updates reminder text for an agent role. Only admins should call this."""
        try:
            self.update_role(role_id, reminder_text=reminder_text, actor_id=updated_by_id)
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------ Rooms & Room Access
    def create_room(
        self,
        name: str,
        topic: str = "",
        created_by_id: int | None = None,
        created_by: int | None = None,
        actor_id: int | None = None,
        actor_name: str = "admin",
    ) -> dict[str, Any]:
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

        self.log_audit(
            actor_id=actor_id or actual_creator,
            actor_name=actor_name,
            action="create_room",
            target_type="room",
            target_id=room_id,
            room_id=room_id,
            details=f"Criou sala '{clean_name}'",
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
                   (SELECT COUNT(*) FROM room_access ra WHERE ra.room_id = r.id) as member_count,
                   (SELECT COUNT(*) FROM messages m WHERE m.room_id = r.id) as message_count
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

    def archive_room(self, room_id_or_name: int | str, actor_id: int | None = None, actor_name: str = "admin") -> bool:
        """Marks a room as archived. Restricted to admins."""
        if actor_id is not None:
            actor = self.get_principal_by_id(actor_id)
            if actor and not self.authorize(actor, "admin"):
                raise PermissionError("Acesso negado: Apenas administradores podem arquivar salas.")
        room = self._resolve_room(room_id_or_name)
        if not room:
            return False
        conn = self._get_connection()
        with conn:
            cursor = conn.execute("UPDATE rooms SET is_archived = 1 WHERE id = ?;", (room["id"],))
            archived = cursor.rowcount > 0
        if archived:
            self.log_audit(
                actor_id=actor_id,
                actor_name=actor_name,
                action="archive_room",
                target_type="room",
                target_id=room["id"],
                room_id=room["id"],
                details=f"Arquivou sala '{room['name']}' (#{room['id']})",
            )
        return archived

    def unarchive_room(self, room_id_or_name: int | str, actor_id: int | None = None, actor_name: str = "admin") -> bool:
        """Unarchives a room. Restricted to admins."""
        if actor_id is not None:
            actor = self.get_principal_by_id(actor_id)
            if actor and not self.authorize(actor, "admin"):
                raise PermissionError("Acesso negado: Apenas administradores podem desarquivar salas.")
        room = self._resolve_room(room_id_or_name)
        if not room:
            return False
        conn = self._get_connection()
        with conn:
            cursor = conn.execute("UPDATE rooms SET is_archived = 0 WHERE id = ?;", (room["id"],))
            unarchived = cursor.rowcount > 0
        if unarchived:
            self.log_audit(
                actor_id=actor_id,
                actor_name=actor_name,
                action="unarchive_room",
                target_type="room",
                target_id=room["id"],
                room_id=room["id"],
                details=f"Desarquivou sala '{room['name']}' (#{room['id']})",
            )
        return unarchived

    def grant_room_access(
        self,
        room_id: int | str | dict[str, Any],
        principal_id: int | str | dict[str, Any],
        role_id: int | None = None,
        can_write: int = 1,
        granted_by_id: int | None = None,
        actor_id: int | None = None,
        actor_name: str = "admin",
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
        eff_can_write = 1 if can_write else 0
        effective_granter = actor_id or granted_by_id
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
                (room["id"], principal["id"], role_id, eff_can_write, effective_granter, now_str),
            )
            max_mid = self.get_max_message_id(room["id"])
            conn.execute(
                """
                INSERT OR IGNORE INTO read_cursors (principal_id, room_id, last_message_id, updated_at)
                VALUES (?, ?, ?, ?);
                """,
                (principal["id"], room["id"], max_mid, now_str),
            )

        mode = "leitura/escrita" if eff_can_write else "observador (leitura)"
        self.log_audit(
            actor_id=effective_granter,
            actor_name=actor_name,
            action="grant_room_access",
            target_type="room_access",
            target_id=principal["id"],
            room_id=room["id"],
            details=f"Atribuiu acesso à sala '{room['name']}' ao principal '{principal['name']}' ({mode}, role_id={role_id})",
        )

    def revoke_room_access(
        self,
        room_id: int | str | dict[str, Any],
        principal_id: int | str | dict[str, Any],
        actor_id: int | None = None,
        actor_name: str = "admin",
    ) -> bool:
        """Revokes a principal's access to a room."""
        room = self._resolve_room(room_id)
        if not room:
            return False
        principal = self._resolve_principal(principal_id)
        if not principal:
            return False
        conn = self._get_connection()
        with conn:
            cursor = conn.execute(
                "DELETE FROM room_access WHERE room_id = ? AND principal_id = ?;",
                (room["id"], principal["id"]),
            )
            revoked = cursor.rowcount > 0
        if revoked:
            self.log_audit(
                actor_id=actor_id,
                actor_name=actor_name,
                action="revoke_room_access",
                target_type="room_access",
                target_id=principal["id"],
                room_id=room["id"],
                details=f"Removeu acesso do principal '{principal['name']}' à sala '{room['name']}'",
            )
        return revoked

    def update_room_access(
        self,
        room_id: int | str | dict[str, Any],
        principal_id: int | str | dict[str, Any],
        role_id: Any = _UNSET,
        can_write: Any = _UNSET,
        actor_id: int | None = None,
        actor_name: str = "admin",
    ) -> dict[str, Any]:
        """
        Updates role and/or write permission for an existing member of a room.
        Distinguishes role_id=_UNSET (field omitted, do not change) from role_id=None (clear room-specific role, fallback to default).
        Distinguishes can_write=_UNSET (field omitted, do not change) from can_write=0/1.
        Raises KeyError if the principal is not an existing member of the room.
        Records previous and new values in the audit log (e.g. 'role: — → project_manager').
        """
        room = self._resolve_room(room_id)
        if not room:
            raise ValueError(f"Sala '{room_id}' não encontrada.")
        principal = self._resolve_principal(principal_id)
        if not principal:
            raise ValueError(f"Principal '{principal_id}' não encontrado.")

        conn = self._get_connection()
        row = conn.execute(
            """
            SELECT ra.*, r.role_key, r.display_name as role_display_name
            FROM room_access ra
            LEFT JOIN agent_roles r ON ra.role_id = r.id
            WHERE ra.room_id = ? AND ra.principal_id = ?;
            """,
            (room["id"], principal["id"]),
        ).fetchone()

        if not row:
            raise KeyError(f"O principal '{principal['name']}' não é membro da sala '{room['name']}'.")

        old_role_id = row["role_id"]
        old_role_name = row["role_display_name"] or row["role_key"] or "—"
        old_can_write = row["can_write"]

        # Calculate new role_id
        if role_id is not _UNSET:
            if role_id is None or role_id == 0 or role_id == "":
                target_role_id = None
                new_role_name = "—"
            else:
                target_role_id = int(role_id)
                r_row = conn.execute("SELECT role_key, display_name FROM agent_roles WHERE id = ?;", (target_role_id,)).fetchone()
                if not r_row:
                    raise ValueError(f"Papel ID {target_role_id} não encontrado.")
                new_role_name = r_row["display_name"] or r_row["role_key"]
        else:
            target_role_id = old_role_id
            new_role_name = old_role_name

        # Calculate new can_write
        if can_write is not _UNSET:
            target_can_write = 1 if can_write else 0
        else:
            target_can_write = old_can_write

        with conn:
            conn.execute(
                """
                UPDATE room_access
                SET role_id = ?, can_write = ?
                WHERE room_id = ? AND principal_id = ?;
                """,
                (target_role_id, target_can_write, room["id"], principal["id"]),
            )

        changes = []
        if role_id is not _UNSET and old_role_id != target_role_id:
            changes.append(f"role: {old_role_name} → {new_role_name}")
        if can_write is not _UNSET and old_can_write != target_can_write:
            old_perm = "leitura e escrita" if old_can_write else "observador"
            new_perm = "leitura e escrita" if target_can_write else "observador"
            changes.append(f"permissão: {old_perm} → {new_perm}")

        details = f"Atualizou acesso de '{principal['name']}' na sala '{room['name']}'"
        if changes:
            details += f": {', '.join(changes)}"
        else:
            details += " (sem alterações)"

        self.log_audit(
            actor_id=actor_id,
            actor_name=actor_name,
            action="update_room_access",
            target_type="room_access",
            target_id=principal["id"],
            room_id=room["id"],
            details=details,
        )

        return {
            "room_id": room["id"],
            "principal_id": principal["id"],
            "role_id": target_role_id,
            "can_write": target_can_write,
        }

    def bulk_grant_room_access(
        self,
        grants: list[dict[str, Any]],
        actor_id: int | None = None,
        actor_name: str = "admin",
    ) -> int:
        """
        Performs bulk assignment or revocation of room access for multiple (room, principal) pairs.
        Each grant dict should have:
          - room_id: int | str
          - principal_id: int | str
          - role_id: int | None (optional)
          - can_write: int (0 or 1, default 1)
          - remove: bool (default False; if True, revokes access)
        """
        count = 0
        conn = self._get_connection()
        now_str = utc_now()
        with conn:
            for g in grants:
                r_spec = g.get("room_id")
                p_spec = g.get("principal_id")
                if not r_spec or not p_spec:
                    continue
                room = self._resolve_room(r_spec)
                principal = self._resolve_principal(p_spec)
                if not room or not principal:
                    continue

                if g.get("remove"):
                    cur = conn.execute(
                        "DELETE FROM room_access WHERE room_id = ? AND principal_id = ?;",
                        (room["id"], principal["id"]),
                    )
                    if cur.rowcount > 0:
                        count += 1
                else:
                    role_id = g.get("role_id")
                    can_write = 1 if g.get("can_write", 1) else 0
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
                        (room["id"], principal["id"], role_id, can_write, actor_id, now_str),
                    )
                    max_mid = self.get_max_message_id(room["id"])
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO read_cursors (principal_id, room_id, last_message_id, updated_at)
                        VALUES (?, ?, ?, ?);
                        """,
                        (principal["id"], room["id"], max_mid, now_str),
                    )
                    count += 1

        self.log_audit(
            actor_id=actor_id,
            actor_name=actor_name,
            action="bulk_grant_room_access",
            target_type="room_access",
            target_id=None,
            room_id=None,
            details=f"Atribuição em massa de {count} acessos em salas",
        )
        return count

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
        """Lists all principals granted access to a room with their roles, default roles, and write permissions."""
        conn = self._get_connection()
        rows = conn.execute(
            """
            SELECT ra.*, p.kind, p.name, p.display_name, p.status, p.is_system,
                   r.role_key, r.display_name as role_display_name, r.reminder_text,
                   a.default_role_id, def_r.role_key as default_role_key, def_r.display_name as default_role_display_name
            FROM room_access ra
            JOIN principals p ON ra.principal_id = p.id
            LEFT JOIN agents a ON p.id = a.principal_id
            LEFT JOIN agent_roles r ON ra.role_id = r.id
            LEFT JOIN agent_roles def_r ON a.default_role_id = def_r.id
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

    def get_access_matrix(self, include_archived: bool = True, include_humans: bool = True) -> dict[str, Any]:
        """
        Returns full data necessary to render the rooms x principals access matrix:
        - rooms: list of rooms (optionally filtered by is_archived)
        - principals: list of agents (and optionally humans), with default roles
        - roles: catalog of agent roles
        - access: list of room_access entries
        """
        conn = self._get_connection()
        # 1. Rooms
        r_query = "SELECT id, name, topic, is_archived FROM rooms"
        if not include_archived:
            r_query += " WHERE is_archived = 0"
        r_query += " ORDER BY is_archived ASC, name ASC;"
        rooms = [dict(r) for r in conn.execute(r_query).fetchall()]

        # 2. Principals (agents, and humans if requested)
        p_query = """
            SELECT p.id, p.name, p.display_name, p.kind, p.status,
                   a.default_role_id, ar.role_key as default_role_key, ar.display_name as default_role_display_name,
                   h.access_role
            FROM principals p
            LEFT JOIN agents a ON p.id = a.principal_id
            LEFT JOIN agent_roles ar ON a.default_role_id = ar.id
            LEFT JOIN humans h ON p.id = h.principal_id
            WHERE p.status = 'active'
        """
        if not include_humans:
            p_query += " AND p.kind = 'agent'"
        p_query += " ORDER BY p.kind ASC, p.name ASC;"
        principals = [dict(r) for r in conn.execute(p_query).fetchall()]

        # 3. Roles
        roles = [dict(r) for r in conn.execute("SELECT id, role_key, display_name FROM agent_roles ORDER BY display_name ASC;").fetchall()]

        # 4. Access entries
        acc_query = """
            SELECT ra.room_id, ra.principal_id, ra.role_id, ra.can_write
            FROM room_access ra;
        """
        access = [dict(r) for r in conn.execute(acc_query).fetchall()]

        return {
            "rooms": rooms,
            "principals": principals,
            "roles": roles,
            "access": access,
        }

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
        else:
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

        # Compute unread counters if principal is human
        if principal.get("kind") == "human":
            cursor_rows = conn.execute(
                "SELECT room_id, last_message_id FROM read_cursors WHERE principal_id = ?;",
                (pid,),
            ).fetchall()
            cursor_map = {row["room_id"]: row["last_message_id"] for row in cursor_rows}

            for r in result:
                rid = r["id"]
                last_mid = cursor_map.get(rid, 0)
                tot_row = conn.execute(
                    """
                    SELECT COUNT(*) as cnt FROM messages
                    WHERE room_id = ? AND id > ? AND (sender_id IS NULL OR sender_id != ?);
                    """,
                    (rid, last_mid, pid),
                ).fetchone()
                r["unread_total"] = tot_row["cnt"] if tot_row else 0

                dir_row = conn.execute(
                    """
                    SELECT COUNT(DISTINCT m.id) as cnt
                    FROM messages m
                    JOIN message_recipients mr ON m.id = mr.message_id
                    WHERE m.room_id = ? AND m.id > ? AND (m.sender_id IS NULL OR m.sender_id != ?)
                      AND mr.target_kind = 'principal' AND mr.target_id = ?;
                    """,
                    (rid, last_mid, pid, pid),
                ).fetchone()
                r["unread_directed"] = dir_row["cnt"] if dir_row else 0
        else:
            for r in result:
                r["unread_total"] = 0
                r["unread_directed"] = 0

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
                if not role_row and not princ_row:
                    princ_row = conn.execute(
                        "SELECT id, name, display_name FROM principals WHERE display_name = ? COLLATE NOCASE;",
                        (clean,),
                    ).fetchone()

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

    def validate_room_recipients(
        self,
        room_name_or_id: int | str | dict[str, Any],
        recipients: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Validates that all targeted recipients have access to the room (or that targeted roles
        are assigned to at least one member with access). Raises ValueError on failure.
        """
        room = room_name_or_id if isinstance(room_name_or_id, dict) else self._resolve_room(room_name_or_id)
        if not room:
            raise ValueError(f"Sala '{room_name_or_id}' não encontrada.")

        for r in recipients:
            t_kind = r.get("target_kind")
            t_id = r.get("target_id")
            t_name = r.get("target_name") or ""
            if t_kind == "principal":
                if t_id == 0:
                    continue
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

        return recipients

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

        sender_id_param = kwargs.get("sender_id")
        principal = (self._resolve_principal(sender_id_param) if sender_id_param else None) or (self._resolve_principal(sender) if sender else None)
        sender_id = principal["id"] if principal else None
        sender_kind = (role if role else (principal.get("kind") if principal else "system")) or "system"
        sender_name = (principal.get("display_name") or principal.get("name")) if principal else (str(sender) if sender else "System")

        now_str = utc_now()
        meta_json = json.dumps(metadata or {}, ensure_ascii=False)
        verified_int = 1 if is_verified else 0

        target_list = self.resolve_recipients(to if to is not None else recipients)
        self.validate_room_recipients(room, target_list)

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
            SELECT m.*, r.name as room_name, p.display_name as sender_display_name, p.name as sender_username
            FROM messages m
            JOIN rooms r ON m.room_id = r.id
            LEFT JOIN principals p ON m.sender_id = p.id
            WHERE m.id = ?;
            """,
            (message_id,),
        ).fetchone()
        if not row:
            return None
        msg = dict(row)
        msg["metadata"] = json.loads(msg["metadata"]) if msg["metadata"] else {}
        msg["sender"] = msg["sender_name"]
        msg["display_name"] = msg.get("sender_display_name") or msg["sender_name"]
        msg["sender_username"] = msg.get("sender_username") or msg["sender_name"]
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
                SELECT m.*, r.name as room_name, p.display_name as sender_display_name, p.name as sender_username
                FROM messages m
                JOIN rooms r ON m.room_id = r.id
                LEFT JOIN principals p ON m.sender_id = p.id
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
                    SELECT m.*, r.name as room_name, p.display_name as sender_display_name, p.name as sender_username
                    FROM messages m
                    JOIN rooms r ON m.room_id = r.id
                    LEFT JOIN principals p ON m.sender_id = p.id
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
                SELECT m.*, r.name as room_name, p.display_name as sender_display_name, p.name as sender_username
                FROM messages m
                JOIN rooms r ON m.room_id = r.id
                LEFT JOIN principals p ON m.sender_id = p.id
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
                    SELECT m.*, r.name as room_name, p.display_name as sender_display_name, p.name as sender_username
                    FROM messages m
                    JOIN rooms r ON m.room_id = r.id
                    LEFT JOIN principals p ON m.sender_id = p.id
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

        # Read receipts computation for this room
        cursor_rows = conn.execute(
            "SELECT principal_id, last_message_id FROM read_cursors WHERE room_id = ?;",
            (room["id"],),
        ).fetchall()
        room_cursors = {cr["principal_id"]: cr["last_message_id"] for cr in cursor_rows}

        member_rows = conn.execute(
            """
            SELECT ra.principal_id, COALESCE(ra.role_id, a.default_role_id) as effective_role_id
            FROM room_access ra
            LEFT JOIN agents a ON ra.principal_id = a.principal_id
            WHERE ra.room_id = ?;
            """,
            (room["id"],),
        ).fetchall()
        room_members = {mr["principal_id"]: mr["effective_role_id"] for mr in member_rows}

        result = []
        for r in rows:
            m = dict(r)
            m["metadata"] = json.loads(m["metadata"]) if m["metadata"] else {}
            m["sender"] = m["sender_name"]
            m["display_name"] = m.get("sender_display_name") or m["sender_name"]
            m["sender_username"] = m.get("sender_username") or m["sender_name"]
            m["role"] = m["sender_kind"]
            m["reactions"] = reactions_map.get(m["id"], [])
            recips = recipients_map.get(m["id"], [{"target_kind": "all", "target_id": None, "target_name": "all"}])
            m["recipients"] = recips
            m["to"] = self._format_to_list(recips)

            # Determine read receipts (✓ / ✓✓)
            sender_id = m.get("sender_id")
            mid = m["id"]
            read_by_all = True
            has_targets = False

            for rec in recips:
                t_kind = rec.get("target_kind")
                t_id = rec.get("target_id")
                if t_kind == "principal" and t_id is not None:
                    if t_id != sender_id:
                        has_targets = True
                        if room_cursors.get(t_id, 0) < mid:
                            read_by_all = False
                            break
                elif t_kind == "role" and t_id is not None:
                    role_pids = [pid for pid, r_id in room_members.items() if r_id == t_id and pid != sender_id]
                    if role_pids:
                        has_targets = True
                        if any(room_cursors.get(pid, 0) < mid for pid in role_pids):
                            read_by_all = False
                            break

            if not has_targets:
                # Broadcast to all active room members
                other_members = [pid for pid in room_members.keys() if pid != sender_id]
                if other_members:
                    if any(room_cursors.get(pid, 0) < mid for pid in other_members):
                        read_by_all = False

            m["read_by_all"] = read_by_all
            m["read_status"] = "read" if read_by_all else "delivered"
            m["read_receipt"] = "✓✓" if read_by_all else "✓"

            result.append(m)
        return result

    def list_messages(self, room_name_or_id: int | str, **kwargs: Any) -> list[dict[str, Any]]:
        """Alias for get_messages."""
        return self.get_messages(room_name_or_id, **kwargs)

    def get_max_message_id(self, room_name_or_id: int | str) -> int:
        """Returns the highest message ID in the room, or 0 if empty."""
        room = self._resolve_room(room_name_or_id)
        if not room:
            return 0
        conn = self._get_connection()
        cur = conn.execute("SELECT COALESCE(MAX(id), 0) FROM messages WHERE room_id = ?;", (room["id"],))
        row = cur.fetchone()
        return row[0] if row else 0

    get_max_message_id_in_room = get_max_message_id

    def update_read_cursor(self, principal_id: int | str, room_name_or_id: int | str, last_message_id: int, clamp_to_max: bool = False) -> None:
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
        effective_mid = int(last_message_id)
        if clamp_to_max:
            max_mid = self.get_max_message_id(room["id"])
            effective_mid = min(max(0, effective_mid), max_mid)
        with conn:
            conn.execute(
                """
                INSERT INTO read_cursors (principal_id, room_id, last_message_id, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(principal_id, room_id) DO UPDATE SET
                    last_message_id = MAX(read_cursors.last_message_id, excluded.last_message_id),
                    updated_at = excluded.updated_at;
                """,
                (int(p_id), room["id"], effective_mid, now_str),
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

        target_room = room_name_or_id if room_name_or_id is not None else msg.get("room_id", msg.get("room_name"))
        room = self._resolve_room(target_room) if target_room is not None else None
        if not room:
            return True

        is_admin = (p.get("kind") == "human" and p.get("access_role") == "admin")
        access = self.get_room_access(room["id"], p["id"])
        if not access and not is_admin:
            # Not a member of the room
            return False

        is_observer = bool(access and access.get("can_write", 1) == 0)

        # Check recipients
        recipients = msg.get("recipients", [])
        if not recipients:
            # Default or legacy = "all"
            if is_admin:
                return True
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
                if is_admin:
                    return True
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
        decider: int | str | dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        """Resolves a pending human decision request."""
        target_decider = decider if decider is not None else decider_name_or_id
        decider_p = self._resolve_principal(target_decider)
        decider_name = (decider_p.get("display_name") or decider_p.get("name")) if decider_p else str(target_decider)
        conn = self._get_connection()
        cursor = conn.execute("SELECT metadata FROM messages WHERE id = ?;", (message_id,))
        row = cursor.fetchone()
        if not row:
            return None
        meta = json.loads(row["metadata"] or "{}")
        if meta.get("status") == "resolved":
            raise ValueError(f"A decisão para a mensagem #{message_id} já foi resolvida anteriormente.")
        meta["status"] = "resolved"
        meta["decision"] = decision
        meta["decided_by"] = decider_p["id"] if decider_p else (target_decider if isinstance(target_decider, int) else decider_name)
        meta["decided_by_name"] = decider_name
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
        """Closes an active poll. Enforces that closer is creator or admin."""
        conn = self._get_connection()
        poll_row = conn.execute("SELECT creator_id, is_closed FROM polls WHERE id = ?;", (poll_id,)).fetchone()
        if not poll_row:
            raise ValueError(f"Poll #{poll_id} não existe.")
        if poll_row["is_closed"]:
            raise ValueError(f"Poll #{poll_id} já se encontra encerrada.")

        if closer_name_or_id is not None:
            closer_p = self._resolve_principal(closer_name_or_id)
            if closer_p and not self.authorize(closer_p, "manage_poll", {"creator_id": poll_row["creator_id"]}):
                raise PermissionError("Apenas o criador da votação ou um administrador pode encerrá-la.")

        now_str = utc_now()
        with conn:
            conn.execute(
                "UPDATE polls SET is_closed = 1, closed_at = ? WHERE id = ? AND is_closed = 0;",
                (now_str, poll_id),
            )
        return self.get_poll(poll_id)

    # ------------------------------------------------------------------ Tasks (Gantt-ready)
    def create_task(
        self,
        room_name_or_id: int | str | None = None,
        title: str = "",
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
        dependencies: list[int] | None = None,
        *,
        room_name: str | None = None,
        room_id: int | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Creates a new task in a room."""
        target_room = room_name_or_id if room_name_or_id is not None else (room_name if room_name is not None else room_id)
        room = self._resolve_room(target_room)
        if not room:
            raise ValueError(f"Sala '{target_room}' não encontrada.")
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

        if dependencies:
            try:
                for dep_id in dependencies:
                    self.add_task_dependency(task_id, int(dep_id))
            except Exception:
                with conn:
                    conn.execute("DELETE FROM task_history WHERE task_id = ?;", (task_id,))
                    conn.execute("DELETE FROM task_dependencies WHERE task_id = ?;", (task_id,))
                    conn.execute("DELETE FROM tasks WHERE id = ?;", (task_id,))
                raise

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
            "assignee_name": t["assignee_name"] or "",
            "waiting_for_id": t["waiting_for_id"],
            "waiting_for_agent": t["waiting_display"] or t["waiting_name"] or "",
            "waiting_name": t["waiting_name"] or "",
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
            "creator_name": t["creator_name"] or "",
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
                "assignee_name": t["assignee_name"] or "",
                "waiting_for_id": t["waiting_for_id"],
                "waiting_for_agent": t["waiting_display"] or t["waiting_name"] or "",
                "waiting_name": t["waiting_name"] or "",
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
                "creator_name": t["creator_name"] or "",
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
        parent_task_id: int | None = None,
        dependencies: list[int] | None = None,
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
        if parent_task_id is not None:
            updates.append("parent_task_id = ?")
            params.append(int(parent_task_id) if int(parent_task_id) > 0 else None)

        conn = self._get_connection()
        if dependencies is not None:
            old_deps = self.get_task_dependencies(task_id)
            with conn:
                conn.execute("DELETE FROM task_dependencies WHERE task_id = ?;", (task_id,))
            try:
                for dep_id in dependencies:
                    self.add_task_dependency(task_id, int(dep_id))
            except Exception:
                with conn:
                    conn.execute("DELETE FROM task_dependencies WHERE task_id = ?;", (task_id,))
                    for od in old_deps:
                        conn.execute("INSERT OR IGNORE INTO task_dependencies (task_id, depends_on_task_id) VALUES (?, ?);", (task_id, od))
                raise

        if not updates and dependencies is None:
            return task

        if updates:
            updates.append("updated_at = ?")
            params.append(now_str)
            params.append(task_id)
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
        tid = int(task_id)
        dep_id = int(depends_on_task_id)
        if tid == dep_id:
            raise ValueError("Uma tarefa não pode depender de si própria.")

        conn = self._get_connection()
        t1 = conn.execute("SELECT id FROM tasks WHERE id = ?;", (tid,)).fetchone()
        t2 = conn.execute("SELECT id FROM tasks WHERE id = ?;", (dep_id,)).fetchone()
        if not t1 or not t2:
            raise ValueError(f"Uma das tarefas (#{tid}, #{dep_id}) não existe.")

        # Cycle detection: verify if dep_id can already reach tid
        visited = set()
        queue = [dep_id]
        while queue:
            curr = queue.pop(0)
            if curr == tid:
                raise ValueError(f"Dependência circular detetada: a tarefa #{tid} não pode depender da tarefa #{dep_id}.")
            visited.add(curr)
            cur = conn.execute("SELECT depends_on_task_id FROM task_dependencies WHERE task_id = ?;", (curr,))
            for r in cur.fetchall():
                next_dep = r[0]
                if next_dep not in visited:
                    queue.append(next_dep)

        with conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO task_dependencies (task_id, depends_on_task_id)
                VALUES (?, ?);
                """,
                (tid, dep_id),
            )

    def remove_task_dependency(self, task_id: int, depends_on_task_id: int) -> bool:
        """Removes a dependency between tasks."""
        conn = self._get_connection()
        with conn:
            cur = conn.execute(
                "DELETE FROM task_dependencies WHERE task_id = ? AND depends_on_task_id = ?;",
                (int(task_id), int(depends_on_task_id)),
            )
            return cur.rowcount > 0

    def get_task_dependencies(self, task_id: int) -> list[int]:
        """Retrieves IDs of tasks this task depends on."""
        conn = self._get_connection()
        cur = conn.execute("SELECT depends_on_task_id FROM task_dependencies WHERE task_id = ?;", (int(task_id),))
        return [r[0] for r in cur.fetchall()]

    def get_unblocked_tasks_on_completion(self, completed_task_id: int) -> list[dict[str, Any]]:
        """
        Finds tasks that were blocked by completed_task_id and now have ALL their dependencies satisfied (status == 'done').
        """
        conn = self._get_connection()
        cur = conn.execute(
            """
            SELECT td.task_id
            FROM task_dependencies td
            JOIN tasks t ON td.task_id = t.id
            WHERE td.depends_on_task_id = ?
              AND t.status NOT IN ('done', 'cancelled');
            """,
            (int(completed_task_id),),
        )
        dependent_task_ids = [r[0] for r in cur.fetchall()]
        unblocked = []
        for tid in dependent_task_ids:
            unfinished = conn.execute(
                """
                SELECT 1
                FROM task_dependencies td
                JOIN tasks t ON td.depends_on_task_id = t.id
                WHERE td.task_id = ? AND t.status != 'done' AND td.depends_on_task_id != ?
                LIMIT 1;
                """,
                (tid, int(completed_task_id)),
            ).fetchone()
            if not unfinished:
                task_obj = self.get_task_by_id(tid)
                if task_obj:
                    unblocked.append(task_obj)
        return unblocked

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
        force: bool = False,
        is_personal: bool = False,
        *,
        room_name: str | None = None,
        room_id: int | None = None,
        target_agent: str | None = None,
        created_by: int | str | dict[str, Any] | None = None,
        owner: int | str | dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Creates a calendar event (room-linked, personal, or resource reservation)."""
        clean_res = (resource or "").strip()
        clean_start = start_at.strip()
        clean_end = end_at.strip() if end_at and end_at.strip() else clean_start

        if clean_res and not force:
            avail = self.check_resource_availability(clean_res, clean_start, clean_end)
            if not avail["available"]:
                c = avail["conflicts"][0]
                c_end = c.get("end_at") or c.get("start_at")
                raise ValueError(
                    f"Conflito de reserva de recurso: o recurso '{clean_res}' já está reservado pelo evento #{c['id']} ('{c['title']}') entre {c['start_at']} e {c_end}."
                )

        target_creator = created_by_id_or_name if created_by_id_or_name is not None else created_by
        creator = self._resolve_principal(target_creator) if target_creator else None
        created_by_id = creator["id"] if creator else None

        target_room = room_name_or_id if room_name_or_id is not None else (room_name if room_name is not None else room_id)
        room = self._resolve_room(target_room) if target_room else None
        r_id = room["id"] if room else None

        target_owner = owner_id_or_name if owner_id_or_name is not None else owner
        own = self._resolve_principal(target_owner) if target_owner else None
        owner_id = own["id"] if own else None

        if is_personal:
            r_id = None
            if not owner_id and creator:
                owner_id = creator["id"]

        effective_target = target_id_or_name if target_id_or_name is not None else target_agent
        target = self._resolve_principal(effective_target) if effective_target else None
        target_id = target["id"] if target else None

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
                    r_id, owner_id, title.strip(), description.strip(), clean_start,
                    clean_end if end_at else None, event_type.strip(), task_id,
                    clean_res or None, target_id, status.strip(),
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
            "is_personal": bool(e["owner_id"] is not None and e["room_id"] is None and (not e["resource"])),
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
        filter_type: str | None = None,
        requester_id_or_name: int | str | dict[str, Any] | None = None,
        *,
        room_name: str | None = None,
        room_id: int | None = None,
        owner: int | str | dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        """Lists calendar events with filtering."""
        target_room = room_name_or_id if room_name_or_id is not None else (room_name if room_name is not None else room_id)
        target_owner = owner_id_or_name if owner_id_or_name is not None else owner
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
        if target_room:
            room = self._resolve_room(target_room)
            if room:
                query += " AND ce.room_id = ?"
                params.append(room["id"])
        if target_owner:
            own = self._resolve_principal(target_owner)
            if own:
                query += " AND ce.owner_id = ?"
                params.append(own["id"])
        if resource:
            query += " AND ce.resource = ?"
            params.append(resource.strip())
        if filter_type:
            ft = filter_type.strip().lower()
            if ft == "room":
                query += " AND ce.room_id IS NOT NULL"
            elif ft == "personal":
                query += " AND ce.owner_id IS NOT NULL AND ce.room_id IS NULL AND (ce.resource IS NULL OR ce.resource = '')"
            elif ft == "resource":
                query += " AND ce.resource IS NOT NULL AND ce.resource != ''"
        if start_after:
            query += " AND ce.start_at >= ?"
            params.append(start_after.strip())
        if end_before:
            query += " AND ce.start_at <= ?"
            params.append(end_before.strip())
        if hide_completed:
            query += " AND ce.status NOT IN ('done', 'completed', 'cancelled')"

        # Privacy check: personal events only visible by creator/owner (or admin)
        if requester_id_or_name is not None:
            req = self._resolve_principal(requester_id_or_name)
            is_admin = bool(req and req.get("access_role") == "admin")
            if not is_admin:
                if req:
                    query += " AND (ce.room_id IS NOT NULL OR (ce.resource IS NOT NULL AND ce.resource != '') OR ce.owner_id = ?)"
                    params.append(req["id"])
                else:
                    query += " AND (ce.room_id IS NOT NULL OR (ce.resource IS NOT NULL AND ce.resource != ''))"

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
                "is_personal": bool(e["owner_id"] is not None and e["room_id"] is None and (not e["resource"])),
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
        force: bool = False,
    ) -> dict[str, Any]:
        """Updates fields of an existing calendar event."""
        event = self.get_calendar_event_by_id(event_id)
        if not event:
            raise ValueError(f"Evento de calendário #{event_id} não encontrado.")

        target_res = (resource if resource is not None else event.get("resource", "") or "").strip()
        target_start = (start_at if start_at is not None else event.get("start_at", "") or "").strip()
        target_end = (end_at if end_at is not None else event.get("end_at", "") or "").strip() or target_start

        if target_res and not force and (resource is not None or start_at is not None or end_at is not None):
            avail = self.check_resource_availability(target_res, target_start, target_end, exclude_event_id=event_id)
            if not avail["available"]:
                c = avail["conflicts"][0]
                c_end = c.get("end_at") or c.get("start_at")
                raise ValueError(
                    f"Conflito de reserva de recurso: o recurso '{target_res}' já está reservado pelo evento #{c['id']} ('{c['title']}') entre {c['start_at']} e {c_end}."
                )

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
        clean_start = start_at.strip()
        clean_end = end_at.strip() if end_at and end_at.strip() else clean_start
        query = """
            SELECT ce.id, ce.title, ce.start_at, ce.end_at, ce.status, ce.resource,
                   r.name as room_name,
                   pc.name as creator_name, pc.display_name as creator_display, pc.kind as creator_kind
            FROM calendar_events ce
            LEFT JOIN rooms r ON ce.room_id = r.id
            LEFT JOIN principals pc ON ce.created_by = pc.id
            WHERE ce.resource = ? COLLATE NOCASE
              AND ce.status IN ('scheduled', 'in_progress')
        """
        params: list[Any] = [clean_res]
        if clean_start == clean_end:
            query += " AND (ce.start_at <= ? AND COALESCE(ce.end_at, ce.start_at) >= ?)"
            params.extend([clean_start, clean_start])
        else:
            query += " AND (ce.start_at < ? AND COALESCE(ce.end_at, ce.start_at) > ?)"
            params.extend([clean_end, clean_start])

        if exclude_event_id:
            query += " AND ce.id != ?"
            params.append(exclude_event_id)
        rows = conn.execute(query, params).fetchall()
        conflicts = []
        for r in rows:
            c = dict(r)
            c["created_by"] = c.get("creator_display") or c.get("creator_name") or "utilizador"
            conflicts.append(c)
        return {
            "resource": clean_res,
            "available": len(conflicts) == 0,
            "conflicts": conflicts,
        }

    def check_resource_conflicts(
        self,
        resource: str,
        start_at: str,
        end_at: str | None = None,
        exclude_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """Returns conflicting calendar events for a resource."""
        res = self.check_resource_availability(
            resource=resource,
            start_at=start_at,
            end_at=end_at or start_at,
            exclude_event_id=exclude_id,
        )
        return res.get("conflicts", [])


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

    def list_audit_log(
        self,
        limit: int = 50,
        offset: int = 0,
        actor_id: int | None = None,
        action: str | None = None,
        room_id: int | None = None,
        target_type: str | None = None,
        target_id: int | None = None,
    ) -> dict[str, Any]:
        """Queries audit log entries with optional filters (who, what, room, target) and pagination."""
        conn = self._get_connection()
        where_clauses = ["1=1"]
        params: list[Any] = []
        if actor_id is not None:
            where_clauses.append("actor_id = ?")
            params.append(actor_id)
        if action and action.strip():
            where_clauses.append("action = ?")
            params.append(action.strip())
        if room_id is not None:
            where_clauses.append("room_id = ?")
            params.append(room_id)
        if target_type and target_type.strip():
            where_clauses.append("target_type = ?")
            params.append(target_type.strip())
        if target_id is not None:
            where_clauses.append("target_id = ?")
            params.append(target_id)

        where_sql = " AND ".join(where_clauses)
        count_row = conn.execute(f"SELECT COUNT(*) as cnt FROM audit_log WHERE {where_sql};", params).fetchone()
        total = count_row["cnt"] if count_row else 0

        eff_limit = max(1, min(limit, 200))
        eff_offset = max(0, offset)
        fetch_params = params + [eff_limit, eff_offset]
        rows = conn.execute(
            f"SELECT * FROM audit_log WHERE {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?;",
            fetch_params,
        ).fetchall()

        return {
            "total": total,
            "limit": eff_limit,
            "offset": eff_offset,
            "items": [dict(r) for r in rows],
        }
