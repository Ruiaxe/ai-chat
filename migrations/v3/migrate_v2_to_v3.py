#!/usr/bin/env python
"""
Migrate an ai-chat v2.x database (up to 2.8) into a new v3 database.

Safety properties:
  * The source database is never modified. It is opened read-only and first copied
    with SQLite's backup API (a consistent snapshot, even while the server runs).
  * The v3 database is written to a NEW file inside one transaction; on any error the
    partial file is deleted.
  * No v2 secret is carried over: per-room tokens, agent tokens, room passwords
    (hashed and clear-text) and browser sessions are discarded. New agent tokens and
    an initial admin password are generated and written ONLY to the credentials file.

Usage (stop the server first for a clean cut-over):
    python migrations/v3/migrate_v2_to_v3.py --source data/chat.db --target data/chat_v3.db \
        --admin-username Rui --out-dir migration_output
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sqlite3
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

SCHEMA_FILE = Path(__file__).with_name("schema_v3.sql")
SCHEMA_VERSION = 3

# Names that v2 reserved for the human user; in v3 they all resolve to the admin principal.
V2_HUMAN_ALIASES = {"human", "rui", "admin", "administrator", "system", "moderator", "root"}
# created_by / actor values that v2 used for server-generated rows.
V2_SYSTEM_ACTORS = {"system", ""}

TASK_STATUSES = {"planned", "in_progress", "waiting_human", "waiting_agent", "done", "cancelled"}
TASK_PRIORITIES = {"low", "medium", "high", "urgent"}

SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN = 2**14, 8, 1, 32


# ------------------------------------------------------------------ crypto helpers (reference for v3 code)

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_hex, hash_hex = stored.split("$")
    except ValueError:
        return False
    if algo != "scrypt":
        return False
    digest = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex),
                            n=int(n), r=int(r), p=int(p), dklen=len(hash_hex) // 2)
    return secrets.compare_digest(digest.hex(), hash_hex)


def new_agent_token() -> str:
    return "aic_" + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ migration

class Migration:
    def __init__(self, src: sqlite3.Connection, dst: sqlite3.Connection, admin_username: str,
                 source_tz: ZoneInfo, grant_public_rooms: bool):
        self.src = src
        self.dst = dst
        self.admin_username = admin_username.strip()
        self.source_tz = source_tz
        self.grant_public_rooms = grant_public_rooms
        self.now = utc_now()
        self.report: dict = {"warnings": [], "counts": {}, "dropped": {}}
        self.credentials: dict = {"agents": {}}
        self.principal_ids: dict[str, int] = {}   # lowercase name -> id
        self.principal_kind: dict[int, str] = {}
        self.room_ids: dict[str, int] = {}        # lowercase name -> id
        self.admin_id = 0

    # -------------------------------------------------------------- helpers

    def warn(self, msg: str) -> None:
        self.report["warnings"].append(msg)

    def drop(self, key: str, n: int = 1) -> None:
        self.report["dropped"][key] = self.report["dropped"].get(key, 0) + n

    def has_table(self, name: str) -> bool:
        return self.src.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None

    def columns(self, table: str) -> set[str]:
        return {r[1] for r in self.src.execute(f"PRAGMA table_info({table})")}

    def rows(self, table: str, order_by: str = "rowid"):
        if not self.has_table(table):
            self.warn(f"source table '{table}' not found; skipped")
            return []
        return self.src.execute(f"SELECT * FROM {table} ORDER BY {order_by}").fetchall()

    def ts(self, value, fallback: bool = True) -> str | None:
        """Converts a v2 timestamp (naive local ISO) to v3 UTC ISO. Date-only values are kept."""
        text = (str(value).strip() if value is not None else "")
        if not text:
            return self.now if fallback else None
        if len(text) == 10:
            try:
                date.fromisoformat(text)
                return text
            except ValueError:
                pass
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            self.warn(f"unparseable timestamp kept as-is: {text!r}")
            return text
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=self.source_tz)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def is_human_alias(self, name: str) -> bool:
        key = (name or "").strip().lower()
        return key in V2_HUMAN_ALIASES or key == self.admin_username.lower()

    def principal(self, name: str | None, *, system_is_null: bool = True, create_legacy: bool = True) -> int | None:
        """Resolves a v2 name to a principal id, creating an inactive legacy agent when unknown."""
        clean = (name or "").strip()
        key = clean.lower()
        if not clean or (system_is_null and key in V2_SYSTEM_ACTORS):
            return None
        if self.is_human_alias(clean):
            return self.admin_id
        if key in self.principal_ids:
            return self.principal_ids[key]
        if not create_legacy:
            return None
        cur = self.dst.execute(
            "INSERT INTO principals (kind, name, display_name, status, is_legacy, created_at) VALUES ('agent', ?, ?, 'inactive', 1, ?)",
            (clean, clean, self.now),
        )
        pid = cur.lastrowid
        self.dst.execute("INSERT INTO agents (principal_id) VALUES (?)", (pid,))
        self.principal_ids[key] = pid
        self.principal_kind[pid] = "agent"
        self.report["counts"]["legacy_principals"] = self.report["counts"].get("legacy_principals", 0) + 1
        return pid

    def room(self, name: str | None) -> int | None:
        clean = (name or "").strip()
        if not clean:
            return None
        key = clean.lower()
        if key not in self.room_ids:
            cur = self.dst.execute(
                "INSERT INTO rooms (name, topic, is_archived, created_at) VALUES (?, 'Recovered by v3 migration (room row was missing in v2)', 1, ?)",
                (clean, self.now),
            )
            self.room_ids[key] = cur.lastrowid
            self.warn(f"room '{clean}' was referenced but did not exist; recreated as archived")
        return self.room_ids[key]

    # -------------------------------------------------------------- steps

    def run(self) -> None:
        self.create_admin()
        self.migrate_agents()
        self.migrate_rooms()
        self.migrate_access()
        self.migrate_messages()
        self.migrate_reactions()
        self.migrate_polls()
        self.migrate_tasks()
        self.migrate_calendar()
        self.migrate_audit()
        self.init_read_cursors()
        self.record_discarded_secrets()
        self.dst.execute("INSERT INTO schema_version (version, applied_at, notes) VALUES (?, ?, ?)",
                         (SCHEMA_VERSION, self.now, "migrated from v2 by migrate_v2_to_v3.py"))

    def create_admin(self) -> None:
        password = secrets.token_urlsafe(18)
        cur = self.dst.execute(
            "INSERT INTO principals (kind, name, display_name, status, created_at) VALUES ('human', ?, ?, 'active', ?)",
            (self.admin_username, self.admin_username, self.now),
        )
        self.admin_id = cur.lastrowid
        self.dst.execute(
            "INSERT INTO humans (principal_id, access_role, password_hash, must_change_password) VALUES (?, 'admin', ?, 1)",
            (self.admin_id, hash_password(password)),
        )
        self.principal_ids[self.admin_username.lower()] = self.admin_id
        self.principal_kind[self.admin_id] = "human"
        self.credentials["admin"] = {"username": self.admin_username, "initial_password": password,
                                     "note": "must be changed at first login"}

    def migrate_agents(self) -> None:
        n = 0
        for row in self.rows("member_identities", "created_at"):
            cols = row.keys()
            name = (row["member_name"] or "").strip()
            if not name:
                continue
            if self.is_human_alias(name) or (row["role"] or "").lower() == "human":
                self.warn(f"identity '{name}' is a human alias; merged into admin '{self.admin_username}'")
                continue
            status = (row["status"] if "status" in cols else "active") or "active"
            if status not in ("active", "inactive", "pending"):
                status = "inactive"
            is_system = int(row["is_system"]) if "is_system" in cols and row["is_system"] else 0
            cur = self.dst.execute(
                "INSERT INTO principals (kind, name, display_name, status, is_system, created_at) VALUES ('agent', ?, ?, ?, ?, ?)",
                (name, name, status, is_system, self.ts(row["created_at"])),
            )
            pid = cur.lastrowid
            self.dst.execute("INSERT INTO agents (principal_id) VALUES (?)", (pid,))
            self.principal_ids[name.lower()] = pid
            self.principal_kind[pid] = "agent"
            if status == "active":
                token = new_agent_token()
                self.dst.execute(
                    "INSERT INTO credentials (principal_id, token_hash, token_hint, created_at) VALUES (?, ?, ?, ?)",
                    (pid, hash_token(token), token[-4:], self.now),
                )
                self.credentials["agents"][name] = token
            n += 1
        self.report["counts"]["agents"] = n

    def migrate_rooms(self) -> None:
        cols = self.columns("rooms") if self.has_table("rooms") else set()
        protected, public = [], []
        for row in self.rows("rooms", "id"):
            archived = int(row["is_archived"] or 0) if "is_archived" in cols else 0
            self.dst.execute(
                "INSERT INTO rooms (id, name, topic, is_archived, created_at) VALUES (?, ?, ?, ?, ?)",
                (row["id"], row["name"], row["topic"] or "", archived, self.ts(row["created_at"])),
            )
            self.room_ids[row["name"].strip().lower()] = row["id"]
            (protected if row["is_protected"] else public).append(row["name"])
        self.report["counts"]["rooms"] = len(protected) + len(public)
        self.report["protected_rooms_v2"] = protected
        self.report["public_rooms_v2"] = public

    def migrate_access(self) -> None:
        granted: set[tuple[int, int]] = set()

        def grant(room_id: int, pid: int) -> None:
            if (room_id, pid) in granted or self.principal_kind.get(pid) != "agent":
                return
            self.dst.execute("INSERT INTO room_access (room_id, principal_id, granted_by, granted_at) VALUES (?, ?, ?, ?)",
                             (room_id, pid, self.admin_id, self.now))
            granted.add((room_id, pid))

        for row in self.rows("members", "id"):
            pid = self.principal(row["member_name"], create_legacy=False)
            if pid is None:
                continue  # unknown or human names: admins see every room anyway
            grant(self.room(row["room_name"]), pid)

        if self.grant_public_rooms:
            real_agents = [pid for key, pid in self.principal_ids.items()
                           if self.principal_kind.get(pid) == "agent"]
            for room_name in self.report["public_rooms_v2"]:
                for pid in real_agents:
                    grant(self.room_ids[room_name.lower()], pid)
        self.report["counts"]["room_access"] = len(granted)

    def migrate_messages(self) -> None:
        cols = self.columns("messages") if self.has_table("messages") else set()
        odd_roles: dict[str, int] = {}
        n = 0
        for row in self.rows("messages", "id"):
            role = row["role"] or ""
            if role == "human":
                kind, sender_id = "human", self.admin_id
            elif role == "system":
                kind, sender_id = "system", None
            else:
                if role != "agent":
                    odd_roles[role] = odd_roles.get(role, 0) + 1
                kind = "agent"
                sender_id = self.principal(row["sender"], system_is_null=False)
                if sender_id == self.admin_id:
                    # an agent-role message under a reserved human name: keep it, but never attribute it to the admin
                    sender_id = None
                    self.warn(f"message #{row['id']}: agent-role message used reserved name '{row['sender']}'; stored without sender_id")
            metadata = row["metadata"] if "metadata" in cols and row["metadata"] else "{}"
            try:
                json.loads(metadata)
            except (TypeError, ValueError):
                metadata = "{}"
                self.warn(f"message #{row['id']}: invalid metadata JSON replaced with {{}}")
            self.dst.execute(
                """INSERT INTO messages (id, room_id, sender_id, sender_kind, sender_name, content, message_type,
                                         metadata, is_verified, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (row["id"], self.room(row["room_name"]), sender_id, kind, row["sender"], row["content"],
                 (row["message_type"] if "message_type" in cols else None) or "text", metadata,
                 int(row["is_verified"] or 0) if "is_verified" in cols else 0, self.ts(row["created_at"])),
            )
            n += 1
        self.report["counts"]["messages"] = n
        if odd_roles:
            self.report["unusual_message_roles"] = odd_roles

    def message_exists(self, message_id) -> bool:
        return message_id is not None and self.dst.execute("SELECT 1 FROM messages WHERE id=?", (message_id,)).fetchone() is not None

    def migrate_reactions(self) -> None:
        n = 0
        for row in self.rows("reactions", "id"):
            if not self.message_exists(row["message_id"]):
                self.drop("reactions_on_missing_message")
                continue
            pid = self.principal(row["sender"], system_is_null=False)
            if pid is None:
                self.drop("reactions_without_sender")
                continue
            cur = self.dst.execute(
                "INSERT OR IGNORE INTO reactions (message_id, principal_id, emoji, created_at) VALUES (?, ?, ?, ?)",
                (row["message_id"], pid, row["emoji"], self.ts(row["created_at"])),
            )
            if cur.rowcount:
                n += 1
            else:
                self.drop("reactions_duplicate_after_alias_merge")
        self.report["counts"]["reactions"] = n

    def migrate_polls(self) -> None:
        n = 0
        for row in self.rows("polls", "id"):
            self.dst.execute(
                "INSERT INTO polls (id, room_id, creator_id, question, options, is_closed, created_at, closed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (row["id"], self.room(row["room_name"]), self.principal(row["creator"], system_is_null=False),
                 row["question"], row["options"], int(row["is_closed"] or 0), self.ts(row["created_at"]),
                 self.ts(row["closed_at"], fallback=False)),
            )
            n += 1
        self.report["counts"]["polls"] = n
        votes = 0
        for row in self.rows("poll_votes", "created_at, id"):  # later votes win after alias merging
            if not self.dst.execute("SELECT 1 FROM polls WHERE id=?", (row["poll_id"],)).fetchone():
                self.drop("votes_on_missing_poll")
                continue
            pid = self.principal(row["voter"], system_is_null=False)
            if pid is None:
                self.drop("votes_without_voter")
                continue
            existed = self.dst.execute("SELECT 1 FROM poll_votes WHERE poll_id=? AND voter_id=?", (row["poll_id"], pid)).fetchone()
            self.dst.execute(
                "INSERT OR REPLACE INTO poll_votes (poll_id, voter_id, option_index, created_at) VALUES (?, ?, ?, ?)",
                (row["poll_id"], pid, row["option_index"], self.ts(row["created_at"])),
            )
            if existed:
                self.drop("votes_merged_after_alias_merge")
            else:
                votes += 1
        self.report["counts"]["poll_votes"] = votes

    def migrate_tasks(self) -> None:
        cols = self.columns("tasks") if self.has_table("tasks") else set()

        def col(row, name, default=None):
            return row[name] if name in cols else default

        n = 0
        for row in self.rows("tasks", "id"):
            status = row["status"] if row["status"] in TASK_STATUSES else "planned"
            priority = row["priority"] if row["priority"] in TASK_PRIORITIES else "medium"
            if status != row["status"] or priority != row["priority"]:
                self.warn(f"task #{row['id']}: invalid status/priority normalised")
            message_id = row["message_id"] if self.message_exists(row["message_id"]) else None
            self.dst.execute(
                """INSERT INTO tasks (id, room_id, title, description, status, priority, assignee_id, waiting_for_id,
                                      order_index, message_id, uses_gpu, gpu_est_min, resource, start_at, due_at,
                                      progress_percent, created_by, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (row["id"], self.room(row["room_name"]), row["title"], row["description"] or "", status, priority,
                 self.principal(row["assignee"]), self.principal(col(row, "waiting_for_agent")),
                 row["order_index"] or 0, message_id, int(col(row, "uses_gpu", 0) or 0), int(col(row, "gpu_est_min", 0) or 0),
                 (col(row, "resource") or None), self.ts(col(row, "start_at"), fallback=False),
                 self.ts(col(row, "due_at"), fallback=False), 100 if status == "done" else 0,
                 self.principal(row["created_by"]), self.ts(row["created_at"]), self.ts(row["updated_at"])),
            )
            n += 1
        self.report["counts"]["tasks"] = n
        h = 0
        for row in self.rows("task_history", "id"):
            if not self.dst.execute("SELECT 1 FROM tasks WHERE id=?", (row["task_id"],)).fetchone():
                self.drop("task_history_on_missing_task")
                continue
            self.dst.execute(
                """INSERT INTO task_history (id, task_id, action, actor_id, actor_name, from_status, to_status, details, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (row["id"], row["task_id"], row["action"], self.principal(row["actor"]), row["actor"] or "",
                 row["from_status"] or "", row["to_status"] or "", row["details"] or "", self.ts(row["created_at"])),
            )
            h += 1
        self.report["counts"]["task_history"] = h

    def migrate_calendar(self) -> None:
        n = 0
        for row in self.rows("calendar_events", "id"):
            task_id = row["task_id"]
            if task_id is not None and not self.dst.execute("SELECT 1 FROM tasks WHERE id=?", (task_id,)).fetchone():
                task_id = None
            self.dst.execute(
                """INSERT INTO calendar_events (id, room_id, title, description, start_at, end_at, event_type, task_id,
                                                resource, target_id, status, wake_on_start, wake_on_end, notified_start,
                                                notified_end, created_by, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (row["id"], self.room(row["room_name"]), row["title"], row["description"] or "",
                 self.ts(row["start_at"]), self.ts(row["end_at"], fallback=False), row["event_type"] or "event", task_id,
                 row["resource"] or None, self.principal(row["target_agent"]), row["status"] or "scheduled",
                 int(row["wake_on_start"] or 0), int(row["wake_on_end"] or 0), int(row["notified_start"] or 0),
                 int(row["notified_end"] or 0), self.principal(row["created_by"]), self.ts(row["created_at"]),
                 self.ts(row["updated_at"])),
            )
            n += 1
        self.report["counts"]["calendar_events"] = n

    def migrate_audit(self) -> None:
        n = 0
        for row in self.rows("room_audit_log", "id"):
            room_id = self.room(row["room_name"])
            self.dst.execute(
                """INSERT INTO audit_log (actor_id, actor_name, action, target_type, target_id, room_id, status, details, created_at)
                   VALUES (?, ?, ?, 'room', ?, ?, ?, ?, ?)""",
                (self.principal(row["member_name"]), row["member_name"] or "", row["action"], room_id, room_id,
                 row["status"] or "ok", row["details"] or "", self.ts(row["created_at"])),
            )
            n += 1
        self.dst.execute(
            "INSERT INTO audit_log (actor_id, actor_name, action, target_type, status, details, created_at) VALUES (?, ?, 'migration_v2_to_v3', 'database', 'ok', ?, ?)",
            (self.admin_id, self.admin_username, json.dumps(self.report["counts"]), self.now),
        )
        self.report["counts"]["audit_log"] = n

    def init_read_cursors(self) -> None:
        # Start every granted principal at the current end of each room, so nobody is woken by old history.
        cur = self.dst.execute(
            """INSERT INTO read_cursors (principal_id, room_id, last_message_id, updated_at)
               SELECT ra.principal_id, ra.room_id, COALESCE((SELECT MAX(id) FROM messages m WHERE m.room_id = ra.room_id), 0), ?
               FROM room_access ra""",
            (self.now,),
        )
        self.report["counts"]["read_cursors"] = cur.rowcount

    def record_discarded_secrets(self) -> None:
        d = self.report["dropped"]
        if self.has_table("members") and "token" in self.columns("members"):
            d["per_room_tokens"] = self.src.execute("SELECT COUNT(*) FROM members WHERE COALESCE(token,'') <> ''").fetchone()[0]
        if self.has_table("member_identities"):
            d["v2_agent_tokens_rotated"] = self.src.execute("SELECT COUNT(*) FROM member_identities").fetchone()[0]
        if self.has_table("rooms"):
            rc = self.columns("rooms")
            d["room_passwords"] = self.src.execute("SELECT COUNT(*) FROM rooms WHERE is_protected = 1").fetchone()[0]
            if "clear_password" in rc:
                d["room_clear_text_passwords"] = self.src.execute("SELECT COUNT(*) FROM rooms WHERE COALESCE(clear_password,'') <> ''").fetchone()[0]
        if self.has_table("human_sessions"):
            d["browser_sessions"] = self.src.execute("SELECT COUNT(*) FROM human_sessions").fetchone()[0]


# ------------------------------------------------------------------ verification

def verify(src: sqlite3.Connection, dst: sqlite3.Connection, report: dict) -> list[str]:
    problems = []
    if dst.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        problems.append("integrity_check failed")
    fk = dst.execute("PRAGMA foreign_key_check").fetchall()
    if fk:
        problems.append(f"foreign_key_check: {len(fk)} violations, e.g. {tuple(fk[0])}")

    def count(conn, table):
        exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] if exists else 0

    for table in ("messages", "polls", "tasks", "calendar_events"):
        if count(src, table) != count(dst, table):
            problems.append(f"{table}: {count(src, table)} in v2 vs {count(dst, table)} in v3")
    if count(src, "messages"):
        src_max = src.execute("SELECT MAX(id) FROM messages").fetchone()[0]
        dst_max = dst.execute("SELECT MAX(id) FROM messages").fetchone()[0]
        if src_max != dst_max:
            problems.append(f"message ids not preserved: max {src_max} vs {dst_max}")
    expected_reactions = count(src, "reactions") - sum(v for k, v in report["dropped"].items() if k.startswith("reactions_"))
    if count(dst, "reactions") != expected_reactions:
        problems.append(f"reactions: expected {expected_reactions}, got {count(dst, 'reactions')}")
    return problems


# ------------------------------------------------------------------ entry point

def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Migrate an ai-chat v2 database to v3 (non-destructive).")
    ap.add_argument("--source", required=True, type=Path, help="v2 chat.db (opened read-only)")
    ap.add_argument("--target", required=True, type=Path, help="new v3 database file (must not exist)")
    ap.add_argument("--admin-username", required=True, help="username of the first admin (e.g. Rui)")
    ap.add_argument("--out-dir", type=Path, default=Path("migration_output"), help="where the backup, report and credentials go")
    ap.add_argument("--source-tz", default="Europe/Lisbon", help="timezone of v2's naive timestamps (default Europe/Lisbon)")
    ap.add_argument("--grant-public-rooms", action="store_true",
                    help="also grant every registered agent access to rooms that were public in v2")
    args = ap.parse_args(argv)

    if not args.source.is_file():
        print(f"source not found: {args.source}", file=sys.stderr)
        return 2
    if args.target.exists():
        print(f"target already exists, refusing to overwrite: {args.target}", file=sys.stderr)
        return 2
    try:
        source_tz = ZoneInfo(args.source_tz)
    except Exception as e:
        print(f"unknown timezone {args.source_tz!r} ({e}); on Windows run: pip install tzdata", file=sys.stderr)
        return 2

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    backup_path = args.out_dir / f"chat_v2_backup_{stamp}.db"

    # 1. consistent snapshot of the live v2 database
    live = sqlite3.connect(f"file:{args.source.resolve().as_posix()}?mode=ro", uri=True)
    snap = sqlite3.connect(backup_path)
    live.backup(snap)
    live.close()
    snap.close()
    print(f"[1/4] backup written: {backup_path}")

    src = sqlite3.connect(f"file:{backup_path.resolve().as_posix()}?mode=ro", uri=True)
    src.row_factory = sqlite3.Row
    dst = sqlite3.connect(args.target)
    dst.row_factory = sqlite3.Row
    try:
        dst.executescript(SCHEMA_FILE.read_text(encoding="utf-8"))
        dst.execute("PRAGMA foreign_keys = ON")
        dst.execute("BEGIN")
        mig = Migration(src, dst, args.admin_username, source_tz, args.grant_public_rooms)
        mig.run()
        problems = verify(src, dst, mig.report)
        if problems:
            raise RuntimeError("verification failed:\n  - " + "\n  - ".join(problems))
        dst.commit()
        dst.execute("PRAGMA journal_mode = WAL")
        print(f"[2/4] v3 database written and verified: {args.target}")
    except Exception:
        dst.close()
        src.close()
        args.target.unlink(missing_ok=True)
        raise
    finally:
        try:
            dst.close()
            src.close()
        except Exception:
            pass

    report_path = args.out_dir / f"migration_report_{stamp}.json"
    report_path.write_text(json.dumps(mig.report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[3/4] report: {report_path}")

    creds_path = args.out_dir / f"credentials_{stamp}.txt"
    lines = [
        "ai-chat v3 credentials — distribute, then DELETE this file.",
        "",
        f"Admin username:          {mig.credentials['admin']['username']}",
        f"Admin initial password:  {mig.credentials['admin']['initial_password']}   (must be changed at first login)",
        "",
        "Agent tokens (put each one in that agent's MCP config as 'Authorization: Bearer <token>'):",
    ]
    lines += [f"  {name:30} {token}" for name, token in sorted(mig.credentials["agents"].items(), key=lambda kv: kv[0].lower())]
    write_private(creds_path, "\n".join(lines) + "\n")
    print(f"[4/4] credentials (mode 600): {creds_path}")

    c = mig.report["counts"]
    print(f"\nmigrated: {c.get('rooms', 0)} rooms, {c.get('messages', 0)} messages, {c.get('agents', 0)} agents "
          f"({len(mig.credentials['agents'])} with new tokens), {c.get('legacy_principals', 0)} legacy names, "
          f"{c.get('room_access', 0)} room grants, {c.get('tasks', 0)} tasks, {c.get('calendar_events', 0)} events")
    if mig.report["warnings"]:
        print(f"warnings: {len(mig.report['warnings'])} (see report)")
    if mig.report.get("public_rooms_v2") and not args.grant_public_rooms:
        print(f"note: {len(mig.report['public_rooms_v2'])} rooms were public in v2; only their previous members were granted "
              "access (use --grant-public-rooms or the admin console to widen)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
