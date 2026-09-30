import asyncio
import hashlib
import os
import secrets
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from aichat.storage import ChatStorage


def _format_id_ranges(ids: list[int]) -> list[str]:
    """Compress a list of integer IDs into interval strings, e.g. ['2-61'] or ['1-3', '7', '10-12']."""
    if not ids:
        return []
    sorted_unique = sorted(set(ids))
    ranges: list[str] = []
    start = sorted_unique[0]
    prev = sorted_unique[0]
    for x in sorted_unique[1:]:
        if x == prev + 1:
            prev = x
        else:
            if start == prev:
                ranges.append(str(start))
            else:
                ranges.append(f"{start}-{prev}")
            start = x
            prev = x
    if start == prev:
        ranges.append(str(start))
    else:
        ranges.append(f"{start}-{prev}")
    return ranges


def _limit_skipped_ids(ids: list[int], max_items: int = 20) -> list[int]:
    """Limits skipped_ids list: if exceeding max_items, returns the first N//2 and last N//2 elements."""
    if len(ids) <= max_items:
        return ids
    half = max_items // 2
    return ids[:half] + ids[-half:]


class ChatHub:
    """Core hub managing room business logic, authentication, pub/sub events, and WebSockets."""

    RESERVED_HUMAN_NAMES = {"human", "rui", "admin", "administrator", "system", "moderator", "root"}

    def __init__(self, storage: ChatStorage | None = None, human_token: str | None = None):
        self.storage = storage or ChatStorage()
        # Active WebSocket connections per room: {room_name: {ws: {"name": str, "is_human": bool, "connected_at": str}}}
        self._active_websockets: dict[str, dict[Any, dict[str, Any]]] = {}
        # Waiting listeners for long polling: {room_name: list[dict[str, Any]]}
        self._room_listeners: dict[str, list[dict[str, Any]]] = {}
        # Recent HTTP / Sentinel polls: {(room_key, name_lower): {"name": str, "room": str, "timestamp": float, "last_seen": str, "client": str, "is_human": bool}}
        self._recent_http_polls: dict[tuple[str, str], dict[str, Any]] = {}
        # Reaction events log for long-polling notification: list of event dicts
        self._reaction_events: list[dict[str, Any]] = []
        self._reaction_seq: int = 0
        # Activity log and wake-up listeners for Sentinel / background watchers
        self._activity_events: list[dict[str, Any]] = []
        self._activity_seq: int = 0
        self._activity_listeners: dict[str, list[dict[str, Any]]] = {}
        self._lock = asyncio.Lock()

        # Human identity name
        self.human_name: str = "Rui"

        # Human authentication token (supports env var, persisted local file, or generated)
        env_token = os.environ.get("AICHAT_HUMAN_TOKEN", "").strip()
        token_file = self.storage.db_path.parent / ".human_token"
        if human_token:
            self.human_token = human_token
        elif env_token:
            self.human_token = env_token
        elif token_file.exists():
            try:
                saved = token_file.read_text(encoding="utf-8").strip()
                if len(saved) >= 16:
                    self.human_token = saved
                else:
                    self.human_token = secrets.token_hex(24)
                    token_file.write_text(self.human_token, encoding="utf-8")
            except Exception:
                self.human_token = secrets.token_hex(24)
        else:
            self.human_token = secrets.token_hex(24)
            try:
                token_file.write_text(self.human_token, encoding="utf-8")
            except Exception:
                pass

        # Human session management and ephemeral one-time auth codes (D5)
        self._one_time_auth_codes: dict[str, float] = {}  # code -> expiry_ts

    def generate_one_time_auth_code(self, expiry_seconds: int = 300) -> str:
        """Generates a secure ephemeral single-use auth code for login without master token."""
        code = secrets.token_hex(16)
        now = time.time()
        # Clean expired
        self._one_time_auth_codes = {c: exp for c, exp in self._one_time_auth_codes.items() if exp > now}
        self._one_time_auth_codes[code] = now + expiry_seconds
        return code

    def consume_one_time_code(self, code: str) -> bool:
        """Validates and immediately consumes a single-use auth code."""
        clean_code = (code or "").strip()
        if not clean_code:
            return False
        now = time.time()
        expiry = self._one_time_auth_codes.pop(clean_code, None)
        if expiry is not None and expiry > now:
            return True
        return False

    def _hash_session_id(self, session_id: str) -> str:
        """Computes SHA-256 hash of a session ID for secure storage."""
        return hashlib.sha256(session_id.encode("utf-8")).hexdigest()

    def create_human_session(self, ttl_seconds: int = 86400 * 30) -> str:
        """Creates a session ID for an authenticated human browser session, stored in SQLite."""
        session_id = secrets.token_hex(32)
        now = time.time()
        expires_at = now + ttl_seconds
        session_hash = self._hash_session_id(session_id)
        self.storage.save_human_session(session_hash, expires_at=expires_at, created_at=now)
        return session_id

    def verify_human_session(self, session_id: str) -> bool:
        """Checks if a session ID belongs to a currently active human session in SQLite."""
        clean_id = (session_id or "").strip()
        if not clean_id:
            return False
        session_hash = self._hash_session_id(clean_id)
        return self.storage.verify_human_session(session_hash)

    def invalidate_human_session(self, session_id: str) -> None:
        """Invalidates an active human session upon logout from SQLite."""
        clean_id = (session_id or "").strip()
        if clean_id:
            session_hash = self._hash_session_id(clean_id)
            self.storage.delete_human_session(session_hash)

    def _hash_password(self, password: str, salt: str | None = None) -> tuple[str, str]:
        """Generates salted SHA-256 hash for a password."""
        if not salt:
            salt = secrets.token_hex(16)
        hash_val = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
        return hash_val, salt

    def _verify_password(self, password: str, stored_hash: str, salt: str) -> bool:
        """Verifies a password against the stored salt and hash."""
        calc_hash, _ = self._hash_password(password, salt)
        return secrets.compare_digest(calc_hash, stored_hash)

    def create_room(
        self,
        name: str,
        password: str = "",
        topic: str = "",
    ) -> dict[str, Any]:
        """Creates a new chat room, optionally protected with password."""
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Room name cannot be empty.")

        existing = self.storage.get_room(clean_name)
        if existing:
            raise ValueError(f"Room '{clean_name}' already exists.")

        is_protected = bool(password.strip())
        pwd_hash = ""
        salt = ""
        if is_protected:
            pwd_hash, salt = self._hash_password(password.strip())

        room = self.storage.create_room(
            name=clean_name,
            topic=topic.strip(),
            password_hash=pwd_hash,
            salt=salt,
            is_protected=is_protected,
            clear_password=password.strip() if is_protected else "",
        )
        return room

    def verify_room_access(self, room_name: str, password: str = "", requester_token: str = "") -> bool:
        """Checks if access to the room is granted. Authenticated human supervisor has master access."""
        room = self.storage.get_room(room_name)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")

        if not room["is_protected"]:
            return True

        # Verified human supervisor has master access to all rooms
        clean_req = (requester_token or "").strip()
        if clean_req and secrets.compare_digest(clean_req, self.human_token):
            return True

        # Supervisor master key provided as room password
        clean_pwd = (password or "").strip()
        if clean_pwd and secrets.compare_digest(clean_pwd, self.human_token):
            return True

        # Room is protected, verify password
        if not clean_pwd:
            return False
        return self._verify_password(clean_pwd, room["password_hash"], room["salt"])

    def get_canonical_room_name(self, room_name: str, password: str = "", requester_token: str = "") -> str:
        """Resolves room, checks existence and password access, and returns canonical name."""
        room = self.storage.get_room(room_name)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")
        if not self.verify_room_access(room_name, password, requester_token=requester_token):
            raise PermissionError(f"Access denied to room '{room_name}': Invalid or missing password.")
        return room["name"]

    def list_rooms(self, include_archived: bool = True) -> list[dict[str, Any]]:
        """Lists all existing rooms with metadata."""
        return self.storage.list_rooms(include_archived=include_archived)

    def get_room_info(self, room_name: str, password: str = "", requester_token: str = "") -> dict[str, Any]:
        """Gets room information, verifying password if protected."""
        room = self.storage.get_room(room_name)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")

        if room["is_protected"] and not self.verify_room_access(room_name, password, requester_token=requester_token):
            raise PermissionError(f"Room '{room_name}' is password protected. Correct password is required.")

        members = self.storage.list_members(room_name)
        return {
            "id": room["id"],
            "name": room["name"],
            "topic": room["topic"],
            "is_protected": bool(room["is_protected"]),
            "created_at": room["created_at"],
            "members": members,
        }

    def join_room(
        self,
        room_name: str,
        member_name: str,
        role: str = "agent",
        password: str = "",
        member_token: str = "",
    ) -> dict[str, Any]:
        """Registers a member into a room, validating password if protected, and returns their auth token."""
        clean_member = member_name.strip()
        if not clean_member:
            raise ValueError("Member name cannot be empty.")

        if clean_member.lower() in self.RESERVED_HUMAN_NAMES:
            raise ValueError(f"O nome '{clean_member}' está reservado para o utilizador humano. Agentes devem usar outro nome.")

        room = self.storage.get_room(room_name)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")
        canonical_name = room["name"]

        if not self.verify_room_access(canonical_name, password):
            self.storage.log_audit_event(canonical_name, clean_member, "join", "failure", "Invalid or missing password")
            raise PermissionError(f"Access denied to room '{canonical_name}': Invalid or missing password.")

        token = self.storage.add_or_update_member(canonical_name, clean_member, role, token=member_token or None, generate_token=True)
        self.storage.log_audit_event(canonical_name, clean_member, "join", "success", f"role={role}")
        return {
            "status": "joined",
            "room_name": canonical_name,
            "member_name": clean_member,
            "role": role,
            "member_token": token,
        }

    def leave_room(self, room_name: str, member_name: str, member_token: str = "") -> dict[str, Any]:
        """Removes a member from a room, requiring member_token if member is registered."""
        import secrets
        room = self.storage.get_room(room_name)
        canonical_name = room["name"] if room else room_name
        clean_member = member_name.strip()
        mem = self.storage.get_member(canonical_name, clean_member)
        if mem and mem.get("token"):
            clean_token = (member_token or "").strip()
            if not clean_token or not secrets.compare_digest(clean_token, mem["token"]):
                self.storage.log_audit_event(canonical_name, clean_member, "leave", "failure", "Invalid member_token")
                raise PermissionError(f"Acesso negado: Para sair da sala com a identidade '{clean_member}', forneça o member_token correto.")
        
        was_member = bool(mem)
        self.storage.remove_member(canonical_name, clean_member)
        self.storage.log_audit_event(
            canonical_name,
            clean_member,
            "leave",
            "success" if was_member else "noop",
            "Member removed" if was_member else "Was not registered in room",
        )
        return {
            "status": "left",
            "room_name": canonical_name,
            "member_name": clean_member,
            "was_member": was_member,
        }

    def rotate_member_token(
        self,
        room_name: str,
        member_name: str,
        current_token: str = "",
        password: str = "",
        supervisor_token: str = "",
    ) -> dict[str, Any]:
        """Rotates a member's token for a room. Restricted to supervisor Rui."""
        import secrets
        clean_st = (supervisor_token or "").strip()
        if not clean_st or not secrets.compare_digest(clean_st, self.human_token):
            self.storage.log_audit_event(room_name, member_name, "token_rotate", "failure", "Unauthorized token rotation attempt by non-supervisor")
            raise PermissionError("Acesso negado: Apenas o supervisor humano Rui pode gerir e rodar tokens.")

        clean_member = member_name.strip()
        room = self.storage.get_room(room_name)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")
        canonical_name = room["name"]

        mem = self.storage.get_member(canonical_name, clean_member)
        if not mem:
            raise ValueError(f"O membro '{clean_member}' não está registado na sala '{canonical_name}'.")

        new_token = self.storage.rotate_member_token(canonical_name, clean_member)
        self.storage.log_audit_event(canonical_name, clean_member, "token_rotate", "success", "Token rotated by supervisor")
        return {
            "status": "rotated",
            "room_name": canonical_name,
            "member_name": clean_member,
            "member_token": new_token,
        }

    def authenticate_agent(self, token: str, expected_callsign: str = "") -> dict[str, Any]:
        """
        Authenticates an agent token against the registry (v3 or v2).
        Returns identity dict: {"callsign": ..., "role": ..., "is_human": bool, "status": ...}.
        Raises PermissionError if token is missing, invalid, or belongs to a different callsign.
        """
        import secrets
        clean_token = (token or "").strip()
        if not clean_token:
            raise PermissionError("Acesso negado: Token de agente em falta. O acesso requer um agent_token aprovado no servidor.")

        # Check if caller is authenticated human supervisor
        if secrets.compare_digest(clean_token, self.human_token):
            return {
                "callsign": "Rui",
                "role": "human",
                "is_human": True,
                "status": "active",
                "is_system": True,
            }

        # v3 authentication
        if self.storage.is_v3():
            agent, err = self.storage.authenticate_agent_token(clean_token)
            if err:
                raise PermissionError(f"Acesso negado: {err}")
            if expected_callsign:
                clean_expected = expected_callsign.strip().lower()
                if agent["name"].lower() != clean_expected:
                    raise PermissionError(f"Impersonation blocked: O token fornecido pertence a '{agent['name']}', não pode agir como '{expected_callsign}'.")
            return {
                "id": agent["id"],
                "callsign": agent["name"],
                "role": agent.get("default_role_key") or "agent",
                "is_human": False,
                "status": agent.get("status", "active"),
                "is_system": bool(agent.get("is_system", False)),
                "principal": agent,
            }

        # v2 fallback
        agent = self.storage.get_agent_identity_by_token(clean_token, include_inactive=True)
        if not agent:
            raise PermissionError("Acesso negado: Token de agente inválido ou não autorizado. Registo fechado, consulte o supervisor Rui.")

        if agent.get("status") != "active":
            raise PermissionError(f"Acesso negado: O agente '{agent['callsign']}' está desativado pelo supervisor (status='{agent.get('status')}'). Contacte o supervisor Rui.")

        if expected_callsign:
            clean_expected = expected_callsign.strip().lower()
            if agent["callsign"].lower() != clean_expected:
                raise PermissionError(f"Impersonation blocked: O token fornecido pertence a '{agent['callsign']}', não pode agir como '{expected_callsign}'.")

        return {
            "callsign": agent["callsign"],
            "role": agent.get("role", "agent"),
            "is_human": False,
            "status": agent.get("status", "active"),
            "is_system": agent.get("is_system", False),
        }

    def list_registered_agents(self, requester_token: str = "") -> list[dict[str, Any]]:
        """Lists registered agents, revealing tokens only to the authenticated human supervisor."""
        import secrets
        is_supervisor = bool(requester_token and secrets.compare_digest(requester_token.strip(), self.human_token))
        return self.storage.list_registered_agents(include_tokens=is_supervisor)

    def register_agent_admin(
        self,
        callsign: str,
        token: str | None = None,
        role: str = "agent",
        is_system: bool = False,
        supervisor_token: str = "",
    ) -> dict[str, Any]:
        """Provisions a new unique agent in the closed registry. Restricted to supervisor."""
        import secrets
        clean_st = (supervisor_token or "").strip()
        if not clean_st or not secrets.compare_digest(clean_st, self.human_token):
            raise PermissionError("Acesso negado: Apenas o supervisor humano Rui pode registar novos agentes.")

        clean_callsign = (callsign or "").strip()
        if clean_callsign.lower() in self.RESERVED_HUMAN_NAMES:
            raise ValueError(f"O nome '{clean_callsign}' está reservado para o utilizador humano. Agentes devem usar outro nome.")

        res = self.storage.register_agent_admin(callsign=clean_callsign, token=token, role=role, is_system=is_system)
        self.storage.log_audit_event("system", "Rui", "agent_register", "success", f"Registered agent '{callsign}'")
        return res

    def self_register_agent(self, callsign: str, description: str = "") -> dict[str, Any]:
        """Allows an agent to self-register a unique callsign. The access token is withheld for supervisor delivery."""
        clean_callsign = (callsign or "").strip()
        if not clean_callsign:
            raise ValueError("Callsign do agente não pode estar vazio.")
        if clean_callsign.lower() in self.RESERVED_HUMAN_NAMES:
            raise ValueError(f"O nome '{clean_callsign}' está reservado para o utilizador humano. Agentes devem usar outro nome.")

        if hasattr(self.storage, "is_v3") and self.storage.is_v3():
            return self.storage.v3.self_register_agent(clean_callsign, description=description)

        res = self.storage.register_agent_admin(callsign=clean_callsign, role="agent", is_system=False, is_self_registration=True)
        self.storage.log_audit_event("system", clean_callsign, "agent_self_register", "success", f"Self-registered agent '{clean_callsign}' (token held for supervisor delivery)")
        return {
            "status": "registered_pending_token",
            "callsign": clean_callsign,
            "role": res.get("role", "agent"),
            "created_at": res.get("created_at", ""),
            "message": f"Registo submetido com sucesso para '{clean_callsign}'. O teu pedido está pendente de aprovação por um administrador.",
        }

    def rotate_agent_token_admin(
        self,
        callsign: str,
        new_token: str | None = None,
        supervisor_token: str = "",
    ) -> str:
        """Rotates an agent's secret token in the closed registry. Restricted to supervisor."""
        import secrets
        clean_st = (supervisor_token or "").strip()
        if not clean_st or not secrets.compare_digest(clean_st, self.human_token):
            raise PermissionError("Acesso negado: Apenas o supervisor humano Rui pode rodar tokens de agentes.")

        rotated = self.storage.rotate_agent_token_admin(callsign=callsign, new_token=new_token)
        self.storage.log_audit_event("system", "Rui", "agent_token_rotate", "success", f"Rotated token for agent '{callsign}'")
        return rotated

    def delete_agent_admin(self, callsign: str, supervisor_token: str = "") -> None:
        """Deletes an agent from registry and rooms. Restricted to supervisor."""
        import secrets
        clean_st = (supervisor_token or "").strip()
        if not clean_st or not secrets.compare_digest(clean_st, self.human_token):
            raise PermissionError("Acesso negado: Apenas o supervisor humano Rui pode remover agentes.")
        self.storage.delete_agent_admin(callsign)
        self.storage.log_audit_event("system", "Rui", "agent_delete", "success", f"Deleted agent '{callsign}'")

    def update_agent_status_admin(self, callsign: str, status: str, supervisor_token: str = "") -> None:
        """Updates an agent's status ('active', 'inactive', 'pending'). Restricted to supervisor."""
        import secrets
        clean_st = (supervisor_token or "").strip()
        if not clean_st or not secrets.compare_digest(clean_st, self.human_token):
            raise PermissionError("Acesso negado: Apenas o supervisor humano Rui pode alterar o estado de agentes.")
        clean_status = (status or "").strip().lower()
        if clean_status not in ("active", "inactive", "pending"):
            raise ValueError(f"Estado inválido '{status}'. Deve ser 'active', 'inactive' ou 'pending'.")
        self.storage.update_agent_status_admin(callsign, clean_status)
        self.storage.log_audit_event("system", "Rui", "agent_status_update", "success", f"Updated status of agent '{callsign}' to '{clean_status}'")

    def change_room_password(
        self,
        room_name: str,
        old_password: str,
        new_password: str,
        actor_name: str = "",
        supervisor_token: str = "",
    ) -> dict[str, Any]:
        """Changes room password. Restricted to supervisor Rui."""
        import secrets
        clean_room = room_name.strip()
        room = self.storage.get_room(clean_room)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")
        canonical_name = room["name"]
        clean_actor = (actor_name or "System").strip()

        authorized = False
        if supervisor_token and secrets.compare_digest(supervisor_token.strip(), self.human_token):
            authorized = True

        if not authorized:
            self.storage.log_audit_event(canonical_name, clean_actor, "password_change", "failure", "Unauthorized attempt by non-supervisor")
            raise PermissionError("Acesso negado: Apenas o supervisor humano Rui pode definir ou alterar a senha de salas.")

        clean_new = new_password.strip()
        is_protected = bool(clean_new)
        pwd_hash = ""
        salt = ""
        if is_protected:
            pwd_hash, salt = self._hash_password(clean_new)

        self.storage.update_room_password(canonical_name, pwd_hash, salt, is_protected, clear_password=clean_new)
        self.storage.log_audit_event(canonical_name, clean_actor, "password_change", "success", f"is_protected={is_protected}")
        return {
            "status": "password_changed",
            "room_name": canonical_name,
            "is_protected": is_protected,
        }

    def kick_member(
        self,
        room_name: str,
        member_to_kick: str,
        actor_name: str,
        supervisor_token: str = "",
        room_password: str = "",
    ) -> dict[str, Any]:
        """Kicks/ejects a member from a room. Requires supervisor token, human actor, or room password."""
        import secrets
        clean_room = room_name.strip()
        room = self.storage.get_room(clean_room)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")
        canonical_name = room["name"]
        clean_kick = member_to_kick.strip()
        clean_actor = actor_name.strip()

        authorized = False
        if supervisor_token and secrets.compare_digest(supervisor_token.strip(), self.human_token):
            authorized = True
        elif clean_actor.lower() in self.RESERVED_HUMAN_NAMES:
            authorized = True
        elif room_password and self.verify_room_access(canonical_name, room_password):
            authorized = True

        if not authorized:
            self.storage.log_audit_event(canonical_name, clean_actor, "kick", "failure", f"Unauthorized attempt to kick '{clean_kick}'")
            raise PermissionError("Acesso negado: Apenas o supervisor humano ou detentores da senha da sala podem expulsar membros.")

        mem = self.storage.get_member(canonical_name, clean_kick)
        if not mem:
            raise ValueError(f"O membro '{clean_kick}' não está registado na sala '{canonical_name}'.")

        self.storage.remove_member(canonical_name, clean_kick)
        self.storage.log_audit_event(canonical_name, clean_actor, "kick", "success", f"Member '{clean_kick}' ejected by '{clean_actor}'")
        return {
            "status": "kicked",
            "room_name": canonical_name,
            "member_name": clean_kick,
            "kicked_by": clean_actor,
        }

    def get_room_audit_log(self, room_name: str, password: str = "", limit: int = 50) -> list[dict[str, Any]]:
        """Fetches the audit log of a room, requiring password if room is protected."""
        room = self.storage.get_room(room_name)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")
        canonical_name = room["name"]
        if not self.verify_room_access(canonical_name, password):
            raise PermissionError(f"Access denied to room '{canonical_name}': Invalid or missing password.")
        return self.storage.get_room_audit_log(canonical_name, limit)

    def list_my_rooms(self, agent_name: str) -> list[dict[str, Any]]:
        """Returns the list of rooms the member has joined with metadata."""
        clean_agent = agent_name.strip()
        if not clean_agent:
            return []
        room_names = self.storage.get_member_rooms(clean_agent)
        result = []
        for rname in room_names:
            room = self.storage.get_room(rname)
            if room:
                result.append({
                    "name": room["name"],
                    "topic": room.get("topic", ""),
                    "is_protected": bool(room.get("is_protected", False)),
                    "last_message_id": self.storage.get_max_message_id(room["name"]),
                })
        return result

    async def send_message(
        self,
        room_name: str,
        sender: str,
        content: str,
        role: str = "agent",
        password: str = "",
        member_token: str = "",
        message_type: str = "text",
        metadata: dict[str, Any] | None = None,
        human_token: str = "",
        to: str | list[str] = "all",
    ) -> dict[str, Any]:
        """
        Sends a message to the room.
        Validates member token for sender authentication.
        Enforces human session authentication for Human/Rui identities.
        Blocks sending if room is archived.
        Persists to SQLite, logs to file, broadcasts to WebSockets, and notifies waiting agents.
        """
        clean_sender = sender.strip()
        clean_content = content.strip()
        if not clean_sender:
            raise ValueError("Sender name cannot be empty.")
        if not clean_content:
            raise ValueError("Message content cannot be empty.")

        # Data Loss Prevention (DLP): Mask any active tokens in content before storing or broadcasting
        clean_content = self.storage.mask_tokens_in_text(clean_content, human_token=self.human_token)

        room = self.storage.get_room(room_name)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")
        canonical_name = room["name"]

        if room.get("is_archived", False):
            raise ValueError(f"A sala '{canonical_name}' foi arquivada pelo utilizador humano e está em modo apenas de leitura.")

        if not self.verify_room_access(canonical_name, password, requester_token=human_token):
            raise PermissionError(f"Access denied to room '{canonical_name}': Invalid or missing password.")

        # Sender Authentication: verify token or human authorization
        is_verified = False
        clean_role = (role or "agent").strip().lower()
        if clean_role not in ("agent", "human", "system"):
            clean_role = "agent"

        sender_norm = "".join(c for c in clean_sender.lower() if c.isalnum())
        is_reserved = sender_norm in self.RESERVED_HUMAN_NAMES or clean_sender.lower() in self.RESERVED_HUMAN_NAMES

        if clean_role == "human" or is_reserved:
            clean_ht = (human_token or "").strip()
            if not clean_ht or not secrets.compare_digest(clean_ht, self.human_token):
                raise PermissionError(
                    f"Acesso negado: Remetente '{clean_sender}' ou papel '{clean_role}' reservado exclusivamente ao utilizador humano com autenticação válida."
                )
            role = "human"
            is_verified = True
        elif clean_role == "system":
            clean_ht = (human_token or "").strip()
            if not clean_ht or not secrets.compare_digest(clean_ht, self.human_token):
                raise PermissionError("Acesso negado: Papel 'system' requer autenticação de administração.")
            role = "system"
            is_verified = True
        else:
            role = "agent"
            if member_token:
                ident = self.authenticate_agent(member_token, expected_callsign=clean_sender)
                clean_sender = ident["callsign"]
                is_verified = True
            else:
                valid, err = self.storage.verify_member_token(canonical_name, clean_sender, member_token)
                if not valid:
                    raise PermissionError(err)
                if valid:
                    is_verified = True

        # Agent Cycle Protection:
        if role == "agent" and hasattr(self.storage, "is_v3") and self.storage.is_v3():
            max_cycles = int(os.environ.get("AICHAT_MAX_AGENT_CYCLES", "10"))
            r_obj = self.storage.v3.get_room_by_name(canonical_name)
            if r_obj:
                consecutive = self.storage.v3.count_consecutive_agent_messages(r_obj["id"])
                if consecutive >= max_cycles:
                    recent_msgs = self.storage.v3.get_messages(r_obj["id"], limit=1)
                    already_warned = (
                        recent_msgs and
                        recent_msgs[-1].get("role") == "system" and
                        "Proteção de ciclo ativada" in recent_msgs[-1].get("content", "")
                    )
                    if not already_warned:
                        warn_text = (
                            f"⚠️ Proteção de ciclo ativada: limite de {max_cycles} mensagens consecutivas entre agentes "
                            f"atingido na sala '{canonical_name}' sem intervenção humana. "
                            f"Conversação entre agentes pausada até intervenção do utilizador humano."
                        )
                        humans = self.storage.v3.get_room_humans(r_obj["id"])
                        human_targets = [f"@{h['name']}" for h in humans] if humans else [{"target_kind": "principal", "target_id": 0, "target_name": "nobody"}]
                        sys_msg = self.storage.v3.add_message(
                            room_name_or_id=r_obj["id"],
                            sender="System",
                            role="system",
                            content=warn_text,
                            is_verified=True,
                            to=human_targets,
                        )
                        try:
                            await self._broadcast_to_websockets(canonical_name, {
                                "type": "new_message",
                                "message": sys_msg,
                            })
                            self._notify_listeners(canonical_name, message=sys_msg)
                        except Exception:
                            pass

                    raise ValueError(
                        f"Proteção de ciclo ativada: limite de {max_cycles} mensagens consecutivas entre agentes "
                        f"atingido na sala '{canonical_name}' sem intervenção humana. "
                        f"Conversação entre agentes pausada até intervenção do utilizador humano."
                    )

        # Save to database and log files
        msg = self.storage.add_message(
            room_name=canonical_name,
            sender=clean_sender,
            role=role,
            content=clean_content,
            is_verified=is_verified,
            message_type=message_type,
            metadata=metadata,
            to=to,
        )

        if hasattr(self.storage, "is_v3") and self.storage.is_v3():
            sender_id = msg.get("sender_id")
            if sender_id and msg.get("sender_kind") == "agent":
                self.storage.v3.record_agent_activity(sender_id)
                if self.storage.v3.clear_stalled_alert(sender_id):
                    room_id = msg.get("room_id")
                    humans = self.storage.v3.get_room_humans(room_id) if room_id else []
                    human_targets = [f"@{h['name']}" for h in humans]
                    rec_msg = self.storage.v3.add_message(
                        room_name_or_id=room_id,
                        sender="System",
                        role="system",
                        content=f"✅ @{clean_sender} voltou a escutar.",
                        is_verified=True,
                        to=human_targets,
                        message_type="notice",
                    )
                    try:
                        await self._broadcast_to_websockets(canonical_name, {"type": "new_message", "message": rec_msg})
                    except Exception:
                        pass

        # Print to console with clear timestamp, badge, and verification tag
        time_str = datetime.now().strftime("%H:%M:%S")
        role_emoji = "🤖" if role == "agent" else ("👤" if role == "human" else "📢")
        ver_tag = " [VERIFIED]" if is_verified else ""
        print(f"[{time_str}] [#{canonical_name}] {role_emoji} {clean_sender}{ver_tag}: {clean_content}")

        # Broadcast to WebSockets
        await self._broadcast_to_websockets(canonical_name, {
            "type": "new_message",
            "message": msg,
        })

        # Wake up any agents long-polling for new messages
        self._notify_listeners(canonical_name, message=msg)

        return msg

    def archive_room(self, room_name: str, requester_role: str = "human") -> dict[str, Any]:
        """Archives a room. Restricted strictly to human users."""
        if requester_role != "human":
            raise PermissionError("Apenas o utilizador humano tem permissão para arquivar salas.")
        room = self.storage.get_room(room_name)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")
        self.storage.archive_room(room["name"])
        self._notify_activity(room["name"], "room")
        return {"status": "archived", "room_name": room["name"]}

    def unarchive_room(self, room_name: str, requester_role: str = "human") -> dict[str, Any]:
        """Restores an archived room. Restricted strictly to human users."""
        if requester_role != "human":
            raise PermissionError("Apenas o utilizador humano tem permissão para desarquivar salas.")
        room = self.storage.get_room(room_name)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")
        self.storage.unarchive_room(room["name"])
        self._notify_activity(room["name"], "room")
        return {"status": "unarchived", "room_name": room["name"]}

    async def toggle_reaction(
        self,
        message_id: int,
        room_name: str,
        sender: str,
        emoji: str,
    ) -> dict[str, Any]:
        """Toggles an emoji reaction on a message, logs reaction event, and broadcasts update."""
        room = self.storage.get_room(room_name)
        canonical_name = room["name"] if room else room_name
        msg = self.storage.get_message_by_id(message_id)
        if not msg:
            raise ValueError(f"Mensagem #{message_id} não encontrada.")
        if msg["room_name"].strip().lower() != canonical_name.strip().lower():
            raise PermissionError(f"Acesso negado: A mensagem #{message_id} pertence à sala '{msg['room_name']}', não à sala '{canonical_name}'.")

        res = self.storage.toggle_reaction(message_id, canonical_name, sender, emoji)
        await self._broadcast_to_websockets(canonical_name, {
            "type": "reaction_updated",
            "data": res,
        })

        # Record reaction event for long-polling agents
        async with self._lock:
            self._reaction_seq += 1
            event_item = {
                "seq": self._reaction_seq,
                "room": canonical_name,
                "message_id": message_id,
                "sender": sender,
                "emoji": emoji,
                "action": res["action"],
                "reactions": res["reactions"],
                "created_at": datetime.now().isoformat(),
            }
            self._reaction_events.append(event_item)
            if len(self._reaction_events) > 200:
                self._reaction_events = self._reaction_events[-200:]

        # Wake up any agents long-polling for updates
        self._notify_listeners(canonical_name)
        return res

    async def call_human(
        self,
        room_name: str,
        sender: str,
        question: str,
        options: list[str] | None = None,
        member_token: str = "",
        password: str = "",
        to: str | list[Any] | None = None,
        target_human: str | int | None = None,
    ) -> dict[str, Any]:
        """Calls human user(s) for a decision with optional predefined choices."""
        opts = options or []
        metadata = {
            "status": "pending",
            "question": question.strip(),
            "options": opts,
            "decision": None,
            "decided_by": None,
            "decided_at": None,
        }
        formatted_opts = ""
        if opts:
            formatted_opts = "\n\n**Opções propostas:**\n" + "\n".join(f"- **{i+1}.** {opt}" for i, opt in enumerate(opts))

        content = f"🚨 **[DECISÃO HUMANA SOLICITADA]**\n\n{question.strip()}{formatted_opts}"

        # Determine target recipients
        is_v3 = hasattr(self.storage, "is_v3") and self.storage.is_v3()
        final_to: Any = "all"
        if is_v3:
            room = self.storage.v3.get_room(room_name)
            if not room:
                raise ValueError(f"Room '{room_name}' does not exist.")
            target_candidate = target_human or to
            if target_candidate and target_candidate not in ("humans", ["humans"], "@humans"):
                # Directed to a specific human
                p_target = self.storage.v3._resolve_principal(target_candidate)
                if not p_target:
                    raise ValueError(f"Humano '{target_candidate}' não encontrado.")
                if p_target.get("kind") != "human":
                    raise ValueError(f"'{target_candidate}' não é um utilizador humano.")
                if not self.storage.v3.authorize(p_target, "read_room", {"room_id": room["id"]}):
                    raise ValueError(f"O humano '{p_target['name']}' não tem acesso à sala '{room['name']}'.")
                final_to = [f"@{p_target['name']}"]
            else:
                # Open call to all humans with room access
                humans = self.storage.v3.get_room_humans(room["id"])
                final_to = [f"@{h['name']}" for h in humans] if humans else [{"target_kind": "principal", "target_id": 0, "target_name": "nobody"}]
        else:
            final_to = "all"

        msg = await self.send_message(
            room_name=room_name,
            sender=sender,
            content=content,
            role="agent",
            password=password,
            member_token=member_token,
            message_type="decision_request",
            metadata=metadata,
            to=final_to,
        )
        try:
            task = self.storage.create_task(
                room_name=room_name,
                title=f"Decisão: {question.strip()[:60]}",
                description=f"Pergunta: {question.strip()}" + (f"\nOpções: {', '.join(opts)}" if opts else ""),
                status="waiting_human",
                priority="urgent",
                message_id=msg["id"],
                created_by=sender,
            )
            await self._broadcast_to_websockets(room_name, {"type": "task_created", "room": room_name, "task": task})
        except Exception:
            pass
        return msg

    async def resolve_human_decision(
        self,
        message_id: int,
        room_name: str,
        decision: str,
        decider: str | dict[str, Any] = "",
        human_token: str = "",
    ) -> dict[str, Any]:
        """Human submits their decision, resolving the request and posting a confirmation."""
        import secrets
        is_v3 = hasattr(self.storage, "is_v3") and self.storage.is_v3()
        clean_ht = (human_token or "").strip()
        if not is_v3:
            if clean_ht and not secrets.compare_digest(clean_ht, self.human_token):
                raise PermissionError("Acesso negado: Apenas o utilizador humano com autenticação válida pode tomar decisões.")
            decider_name = decider if isinstance(decider, str) and decider else self.human_name
            decider_param: Any = decider_name
        else:
            if isinstance(decider, dict):
                decider_name = decider.get("display_name") or decider.get("name") or "Humano"
                decider_param = decider
            elif isinstance(decider, int) or (isinstance(decider, str) and decider.isdigit()):
                decider_p = self.storage.v3.get_principal_by_id(int(decider))
                decider_name = (decider_p.get("display_name") or decider_p.get("name")) if decider_p else str(decider)
                decider_param = decider
            elif decider:
                decider_p = self.storage.v3.get_principal_by_name(str(decider))
                decider_name = (decider_p.get("display_name") or decider_p.get("name")) if decider_p else str(decider)
                decider_param = decider_p["id"] if decider_p else decider
            else:
                decider_name = "Humano"
                decider_param = decider_name

        meta = self.storage.resolve_decision(message_id, decision, decider=decider_param)
        if not meta:
            raise ValueError(f"Mensagem #{message_id} não encontrada.")
        if not room_name:
            msg_obj = self.storage.get_message_by_id(message_id)
            if msg_obj:
                room_name = msg_obj["room_name"]
        room = self.storage.get_room(room_name)
        canonical_name = room["name"] if room else room_name
        await self._broadcast_to_websockets(canonical_name, {
            "type": "decision_resolved",
            "message_id": message_id,
            "metadata": meta,
        })
        # Auto-resolve any task linked to this message_id
        try:
            conn = self.storage._get_connection()
            cursor = conn.execute("SELECT id FROM tasks WHERE message_id = ?", (message_id,))
            rows = cursor.fetchall()
            for r in rows:
                updated_t = self.storage.update_task(
                    r[0],
                    actor=decider_name,
                    status="done",
                    description=f"Decisão do humano: {decision}",
                )
                await self._broadcast_to_websockets(canonical_name, {
                    "type": "task_updated",
                    "room": canonical_name,
                    "task": updated_t,
                })
        except Exception:
            pass

        resp_msg = await self.send_message(
            room_name=canonical_name,
            sender=decider_name,
            content=f"👤 **[DECISÃO DO HUMANO]**:\n\nOpção escolhida: **{decision}**",
            role="human",
            human_token=self.human_token,
        )
        return {"metadata": meta, "message": resp_msg}

    async def create_poll(
        self,
        room_name: str,
        creator: str,
        question: str,
        options: list[str],
        member_token: str = "",
        human_token: str = "",
        password: str = "",
        role: str = "agent",
    ) -> dict[str, Any]:
        """Creates a poll and posts it to the room."""
        import secrets
        room = self.storage.get_room(room_name)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")
        if room.get("is_archived", False):
            raise ValueError(f"A sala '{room['name']}' está arquivada.")

        clean_ht = (human_token or "").strip()
        is_auth_human = bool(clean_ht and secrets.compare_digest(clean_ht, self.human_token))
        sender_norm = "".join(c for c in creator.lower() if c.isalnum())
        is_reserved = sender_norm in self.RESERVED_HUMAN_NAMES or creator.strip().lower() in self.RESERVED_HUMAN_NAMES

        if is_reserved or role.strip().lower() == "human":
            if not is_auth_human:
                raise PermissionError(f"Acesso negado: Criador '{creator}' requer autenticação válida do utilizador humano.")
            effective_role = "human"
            effective_ht = self.human_token
            effective_tok = ""
        else:
            effective_role = "agent"
            effective_ht = ""
            effective_tok = member_token

        poll = self.storage.create_poll(room["name"], creator, question, options)
        opts_str = "\n".join(f"- **{i+1}.** {opt}" for i, opt in enumerate(options))
        content = f"📊 **[VOTAÇÃO ABERTA #{poll['id']}]**\n\n**{question.strip()}**\n\n{opts_str}\n\n*Usa cast_vote(poll_id={poll['id']}, option_index=...) ou vota na Web UI.*"
        msg = await self.send_message(
            room_name=room["name"],
            sender=creator,
            content=content,
            role=effective_role,
            password=password,
            member_token=effective_tok,
            human_token=effective_ht,
            message_type="poll",
            metadata={"poll_id": poll["id"]},
        )
        await self._broadcast_to_websockets(room["name"], {
            "type": "poll_created",
            "poll": poll,
            "message_id": msg["id"],
        })
        return poll

    async def cast_vote(
        self,
        poll_id: int,
        voter: str,
        option_index: int,
    ) -> dict[str, Any]:
        """Casts or updates a vote on an active poll."""
        poll = self.storage.cast_vote(poll_id, voter, option_index)
        await self._broadcast_to_websockets(poll["room_name"], {
            "type": "poll_updated",
            "poll": poll,
        })
        return poll

    async def close_poll(
        self,
        poll_id: int,
        closer: str,
        is_human: bool = False,
        member_token: str = "",
        human_token: str = "",
        password: str = "",
    ) -> dict[str, Any]:
        """Closes an active poll."""
        import secrets
        p_current = self.storage.get_poll(poll_id)
        if not p_current:
            raise ValueError(f"Poll #{poll_id} não existe.")
        if p_current.get("is_closed"):
            raise ValueError(f"A votação #{poll_id} já se encontra encerrada.")

        is_v3 = hasattr(self.storage, "is_v3") and self.storage.is_v3()
        closer_p = None
        if is_v3:
            closer_p = self.storage.v3._resolve_principal(closer)
            if not closer_p:
                raise PermissionError(f"Principal '{closer}' não encontrado.")
            if not self.storage.v3.authorize(closer_p, "manage_poll", {"creator_id": p_current.get("creator_id")}):
                raise PermissionError("Apenas o criador da votação ou um administrador pode encerrá-la.")
            role_to_use = closer_p.get("kind", "human")
            tok_to_use = member_token if role_to_use == "agent" else ""
            ht_to_use = self.human_token if role_to_use == "human" else ""
            poll = self.storage.v3.close_poll(poll_id, closer_name_or_id=closer_p["id"])
        else:
            clean_ht = (human_token or "").strip()
            if is_human:
                if clean_ht and not secrets.compare_digest(clean_ht, self.human_token):
                    raise PermissionError("Acesso negado: encerramento como humano requer autenticação válida.")
                role_to_use = "human"
                tok_to_use = ""
                ht_to_use = self.human_token
            else:
                if p_current["creator"].strip().lower() != closer.strip().lower():
                    raise PermissionError("Apenas o criador da votação ou o humano podem encerrá-la.")
                valid, err = self.storage.verify_member_token(p_current["room_name"], closer, member_token)
                if not valid or not member_token:
                    raise PermissionError(f"Acesso negado: É obrigatório fornecer o member_token do criador para encerrar a votação.")
                role_to_use = "agent"
                tok_to_use = member_token
                ht_to_use = ""

            poll = self.storage.close_poll(poll_id)

        if "results" in poll:
            tot = poll.get("total_votes", 0) or 1
            results_str = "\n".join(
                f"- {r['option']}: **{r['votes']} votos ({round(r['votes']/tot*100)}%)**"
                for r in poll["results"]
            )
        else:
            results_str = "\n".join(f"- {opt['text']}: **{opt['votes']} votos ({opt['percentage']}%)**" for opt in poll["options"])

        sender_to_use = (closer_p.get("name") or closer) if is_v3 and closer_p else closer

        await self.send_message(
            room_name=poll["room_name"],
            sender=sender_to_use,
            content=f"🏁 **[VOTAÇÃO ENCERRADA #{poll['id']}]**\n\n**{poll['question']}**\n\n**Resultado Final:**\n{results_str}\nTotal de votos: {poll['total_votes']}",
            role=role_to_use,
            password=password,
            member_token=tok_to_use,
            human_token=ht_to_use,
        )
        await self._broadcast_to_websockets(poll["room_name"], {
            "type": "poll_closed",
            "poll": poll,
        })
        return poll

    def get_poll(self, poll_id: int) -> dict[str, Any] | None:
        """Retrieves poll state."""
        return self.storage.get_poll(poll_id)

    def read_messages(
        self,
        room_name: str,
        password: str = "",
        since_id: int = 0,
        before_id: int = 0,
        limit: int = 50,
        message_id: int | None = None,
        requester_token: str = "",
    ) -> list[dict[str, Any]]:
        """Reads recent messages from room, or fetches a single message by message_id."""
        if not self.verify_room_access(room_name, password, requester_token=requester_token):
            raise PermissionError(f"Access denied to room '{room_name}': Invalid or missing password.")

        if message_id is not None and message_id > 0:
            msg = self.storage.get_message_by_id(message_id)
            if msg and msg["room_name"].strip().lower() == room_name.strip().lower():
                return [msg]
            return []

        return self.storage.get_messages(room_name=room_name, since_id=since_id, before_id=before_id, limit=limit)

    def _resolve_target_rooms(self, room_name: str, agent_name: str, password: str = "") -> list[str]:
        """Resolves target room names from input string ('subscribed', '', comma-separated, or single room)."""
        clean_req = (room_name or "").strip()
        if not clean_req or clean_req.lower() == "subscribed":
            if not agent_name:
                raise ValueError("Para escutar em modo 'subscribed', o agent_name é obrigatório.")
            rooms = self.storage.get_member_rooms(agent_name)
            if not rooms:
                raise ValueError(f"Agente '{agent_name}' não tem salas subscritas. Usa join_room primeiro.")
            return rooms
        elif "," in clean_req:
            r_names = [r.strip() for r in clean_req.split(",") if r.strip()]
            resolved = []
            for rn in r_names:
                r_obj = self.storage.get_room(rn)
                if not r_obj:
                    raise ValueError(f"Room '{rn}' does not exist.")
                if not self.verify_room_access(r_obj["name"], password):
                    raise PermissionError(f"Access denied to room '{r_obj['name']}': Invalid or missing password.")
                resolved.append(r_obj["name"])
            return resolved
        else:
            r_obj = self.storage.get_room(clean_req)
            if not r_obj:
                raise ValueError(f"Room '{clean_req}' does not exist.")
            if not self.verify_room_access(r_obj["name"], password):
                raise PermissionError(f"Access denied to room '{r_obj['name']}': Invalid or missing password.")
            return [r_obj["name"]]

    def _scan_unread_messages(
        self,
        room_name: str,
        eff_since: int,
        principal: dict[str, Any] | None,
        is_v3: bool,
        clean_agent: str,
    ) -> tuple[list[dict[str, Any]], int, list[int]]:
        """
        Scans all unread messages for a room starting from eff_since across all pages up to max_id.
        Returns:
            (matched_messages, last_scanned_id, skipped_message_ids)
        """
        max_id = self.storage.get_max_message_id(room_name)
        if max_id == 0 or (eff_since >= max_id and eff_since > 0):
            return [], eff_since, []

        matched: list[dict[str, Any]] = []
        skipped_ids: list[int] = []
        curr_since = eff_since
        last_scanned = eff_since

        r_obj = self.storage.v3.get_room_by_name(room_name) if (is_v3 and principal) else None
        r_id = r_obj["id"] if r_obj else None

        while True:
            page = self.storage.get_messages(
                room_name,
                since_id=curr_since,
                limit=50,
                from_beginning=(curr_since == 0),
            )
            if not page:
                break

            for m in page:
                mid = m["id"]
                if mid > last_scanned:
                    last_scanned = mid

                if is_v3 and principal:
                    if self.storage.v3.is_message_for_principal(m, principal, r_id):
                        matched.append(m)
                    else:
                        skipped_ids.append(mid)
                else:
                    if not clean_agent or m["sender"].strip().lower() != clean_agent:
                        matched.append(m)
                    else:
                        skipped_ids.append(mid)

            curr_since = page[-1]["id"]
            if curr_since >= max_id or len(page) < 50:
                break

        return matched, last_scanned, skipped_ids

    async def wait_for_new_messages(
        self,
        room_name: str = "subscribed",
        agent_name: str = "",
        since_id: int = 0,
        timeout_seconds: float = 600.0,
        password: str = "",
        on_progress: Any = None,
    ) -> dict[str, Any]:
        """
        Long-polling tool for agents:
        - room_name: Specific room name, 'subscribed' (or empty) to watch all joined rooms, or comma-separated list.
        - agent_name: Your agent's name. Own messages are ignored.
        - since_id: Message ID to listen from. If 0 (default), waits for new messages arriving from now on.
        - timeout_seconds: Max seconds to wait (1 to 3600, default 600).
        - on_progress: Optional async callback (elapsed, total, msg) called every 45s to report progress to MCP client.
        Wakes up on new messages OR new reactions to messages in target rooms.
        """
        target_rooms = self._resolve_target_rooms(room_name, agent_name, password)
        clean_agent = agent_name.strip().lower() if agent_name else ""
        is_v3 = hasattr(self.storage, "is_v3") and self.storage.is_v3()
        principal = self.storage.v3.get_principal_by_name(agent_name) if (is_v3 and agent_name) else None

        # Map each room to its effective since_id
        room_since_ids: dict[str, int] = {}
        for r in target_rooms:
            max_id = self.storage.get_max_message_id(r)
            if is_v3 and principal:
                r_obj = self.storage.v3.get_room_by_name(r)
                if r_obj:
                    has_cur = self.storage.v3.has_read_cursor(principal["id"], r_obj["id"])
                    cursor = self.storage.v3.get_read_cursor(principal["id"], r_obj["id"])
                    if since_id > 0:
                        room_since_ids[r] = since_id
                    elif has_cur:
                        room_since_ids[r] = cursor
                    else:
                        # First time connecting to this room: initialize cursor to max_id and wait for future messages
                        self.storage.v3.update_read_cursor(principal["id"], r_obj["id"], max_id)
                        room_since_ids[r] = max_id
                else:
                    room_since_ids[r] = max_id
            else:
                if len(target_rooms) == 1 and since_id > 0:
                    room_since_ids[r] = since_id
                else:
                    room_since_ids[r] = max_id

        # Record the reaction sequence at start
        start_reaction_seq = self._reaction_seq

        # Check for unread messages already available (paginating all pages from cursor)
        immediate_msgs: list[dict[str, Any]] = []
        immediate_skipped: list[int] = []
        for r in target_rooms:
            eff_since = room_since_ids[r]
            max_id = self.storage.get_max_message_id(r)
            if eff_since < max_id or (len(target_rooms) == 1 and since_id > 0):
                matched, last_scanned, skipped = self._scan_unread_messages(
                    r, eff_since, principal, is_v3, clean_agent
                )
                immediate_msgs.extend(matched)
                immediate_skipped.extend(skipped)
                if is_v3 and principal and last_scanned > eff_since:
                    self.storage.v3.update_read_cursor(principal["id"], r, last_scanned)
                    room_since_ids[r] = last_scanned
                elif not is_v3 and last_scanned > eff_since:
                    room_since_ids[r] = last_scanned

        if immediate_msgs:
            immediate_msgs.sort(key=lambda m: m["id"])
            distinct_rooms = {m["room_name"].lower() for m in immediate_msgs}
            first_room = immediate_msgs[0]["room_name"]

            role_reminder = None
            if is_v3 and principal:
                r_obj = self.storage.v3.get_room_by_name(first_room)
                if r_obj:
                    r_info = self.storage.v3.get_agent_role_in_room(principal["id"], r_obj["id"])
                    if r_info and r_info.get("reminder_text"):
                        role_reminder = r_info["reminder_text"]

            res = {
                "status": "new_messages",
                "room": first_room if len(distinct_rooms) == 1 else "subscribed",
                "count": len(immediate_msgs),
                "messages": immediate_msgs,
                "last_id": immediate_msgs[-1]["id"],
                "skipped_count": len(immediate_skipped),
                "skipped_ids": _limit_skipped_ids(immediate_skipped, 20),
                "skipped_ranges": _format_id_ranges(immediate_skipped),
            }
            if role_reminder:
                res["role_reminder"] = role_reminder
            return res

        # Create an event and register on all target rooms
        event = asyncio.Event()
        listener_info = {
            "agent_name": clean_agent or "Agent",
            "event": event,
            "started_at": datetime.now().isoformat(),
        }
        async with self._lock:
            for r in target_rooms:
                r_key = r.strip().lower()
                if r_key not in self._room_listeners:
                    self._room_listeners[r_key] = []
                self._room_listeners[r_key].append(listener_info)

        loop = asyncio.get_running_loop()
        start_time = loop.time()
        deadline = start_time + max(0.5, float(timeout_seconds))
        last_progress_time = start_time
        heartbeat_interval = 45.0

        try:
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    return {
                        "status": "timeout",
                        "rooms": target_rooms if len(target_rooms) > 1 else target_rooms[0],
                        "count": 0,
                        "messages": [],
                        "last_id": self.storage.get_max_message_id(target_rooms[0]) if len(target_rooms) == 1 else 0,
                        "skipped_count": len(immediate_skipped),
                        "skipped_ids": _limit_skipped_ids(immediate_skipped, 20),
                        "skipped_ranges": _format_id_ranges(immediate_skipped),
                        "hint": "No new messages received within the timeout period.",
                    }

                slice_timeout = min(heartbeat_interval, remaining)
                try:
                    await asyncio.wait_for(event.wait(), timeout=max(0.05, slice_timeout))
                    event.clear()
                except asyncio.TimeoutError:
                    # Heartbeat progress report to reset client 300s timeout
                    elapsed = loop.time() - start_time
                    if on_progress and (loop.time() - last_progress_time >= 40.0):
                        last_progress_time = loop.time()
                        try:
                            room_label = target_rooms[0] if len(target_rooms) == 1 else f"{len(target_rooms)} subscribed rooms"
                            await on_progress(elapsed, float(timeout_seconds), f"Waiting for messages in {room_label}... ({int(elapsed)}s elapsed)")
                        except Exception:
                            pass
                    continue

                # Event fired! Collect all new messages from ALL target_rooms across all unread pages
                all_found_messages = []
                event_skipped = []
                for r in target_rooms:
                    effective_since = room_since_ids[r]
                    matched, last_scanned, skipped = self._scan_unread_messages(
                        r, effective_since, principal, is_v3, clean_agent
                    )
                    all_found_messages.extend(matched)
                    event_skipped.extend(skipped)
                    if is_v3 and principal and last_scanned > effective_since:
                        self.storage.v3.update_read_cursor(principal["id"], r, last_scanned)
                        room_since_ids[r] = last_scanned
                    elif not is_v3 and last_scanned > effective_since:
                        room_since_ids[r] = last_scanned

                if all_found_messages:
                    all_found_messages.sort(key=lambda m: m["id"])
                    distinct_rooms = {m["room_name"].lower() for m in all_found_messages}
                    first_room = all_found_messages[0]["room_name"]

                    role_reminder = None
                    if is_v3 and principal:
                        r_obj = self.storage.v3.get_room_by_name(first_room)
                        if r_obj:
                            r_info = self.storage.v3.get_agent_role_in_room(principal["id"], r_obj["id"])
                            if r_info and r_info.get("reminder_text"):
                                role_reminder = r_info["reminder_text"]

                    res = {
                        "status": "new_messages",
                        "room": first_room if len(distinct_rooms) == 1 else "subscribed",
                        "count": len(all_found_messages),
                        "messages": all_found_messages,
                        "last_id": all_found_messages[-1]["id"],
                        "skipped_count": len(event_skipped),
                        "skipped_ids": _limit_skipped_ids(event_skipped, 20),
                        "skipped_ranges": _format_id_ranges(event_skipped),
                    }
                    if role_reminder:
                        res["role_reminder"] = role_reminder
                    return res

                # If no new messages, check for new reaction events in target rooms
                target_room_set = {r.strip().lower() for r in target_rooms}
                new_reactions = [
                    ev for ev in self._reaction_events
                    if ev["seq"] > start_reaction_seq
                    and ev["room"].strip().lower() in target_room_set
                    and (not clean_agent or ev["sender"].strip().lower() != clean_agent)
                ]
                if new_reactions:
                    start_reaction_seq = self._reaction_seq
                    reactions_payload = []
                    for ev in new_reactions:
                        msg_obj = self.storage.get_message_by_id(ev["message_id"])
                        reactions_payload.append({
                            "message_id": ev["message_id"],
                            "room": ev["room"],
                            "sender": ev["sender"],
                            "emoji": ev["emoji"],
                            "action": ev["action"],
                            "all_reactions": ev["reactions"],
                            "message": msg_obj,
                        })
                    return {
                        "status": "new_reactions",
                        "room": new_reactions[0]["room"] if len(target_rooms) == 1 else "subscribed",
                        "count": len(reactions_payload),
                        "reactions": reactions_payload,
                        "last_id": self.storage.get_max_message_id(target_rooms[0]) if len(target_rooms) == 1 else 0,
                    }
        finally:
            if is_v3 and principal and principal.get("kind") == "agent":
                try:
                    self.storage.v3.set_agent_listening(principal["id"], False)
                except Exception:
                    pass
            async with self._lock:
                for r in target_rooms:
                    r_key = r.strip().lower()
                    if r_key in self._room_listeners:
                        self._room_listeners[r_key] = [
                            li for li in self._room_listeners[r_key]
                            if (li.get("event") if isinstance(li, dict) else li) != event
                        ]

    async def wait_for_work(
        self,
        principal_or_agent: dict[str, Any] | int | str = "",
        timeout_seconds: float = 600.0,
        ack: int | str | None = None,
        format: str = "json",
        room: str = "",
        on_progress: Any = None,
        **kwargs: Any,
    ) -> dict[str, Any] | str:
        """
        Universal wait mechanism for agents (v3.1 Camada 1):
        - Manages liveliness (listening_now = 1 while waiting, 0 when leaving).
        - If previously stalled, emits recovery message '✅ @{callsign} voltou a escutar.'
        - Handles reliable delivery via ACK confirmation.
        - Implicit confirmation: subsequent wait confirms previously delivered batch within 30 min.
        - Redelivers unconfirmed batch only if agent failed to wait within 30 minutes.
        - If timeout_seconds=0, performs immediate check without suspending.
        - Formats payload as JSON or plaintext with opaque batch_id.
        """
        if not principal_or_agent:
            principal_or_agent = kwargs.get("agent_name", "") or kwargs.get("agent", "")
        if not room:
            room = kwargs.get("room_name", "") or kwargs.get("room", "")

        is_v3 = hasattr(self.storage, "is_v3") and self.storage.is_v3()
        if not is_v3:
            clean_name = str(principal_or_agent) if not isinstance(principal_or_agent, dict) else principal_or_agent.get("name", "")
            return await self.wait_for_new_messages(
                room_name=room or "subscribed",
                agent_name=clean_name,
                timeout_seconds=timeout_seconds,
                on_progress=on_progress,
            )

        if isinstance(principal_or_agent, dict):
            principal = principal_or_agent
        elif isinstance(principal_or_agent, int) or (isinstance(principal_or_agent, str) and str(principal_or_agent).isdigit()):
            principal = self.storage.v3.get_principal_by_id(int(principal_or_agent))
        else:
            principal = self.storage.v3.get_principal_by_name(str(principal_or_agent))

        if not principal:
            raise ValueError(f"Principal '{principal_or_agent}' não encontrado.")

        pid = principal["id"]
        callsign = principal["name"]
        is_agent = (principal.get("kind") == "agent")

        thresholds = self.storage.v3.get_system_thresholds()
        max_timeout = float(thresholds.get("max_wake_timeout", 1500))
        effective_timeout = max(0.0, min(float(timeout_seconds), max_timeout))

        if is_agent:
            self.storage.v3.record_agent_activity(pid)
            if self.storage.v3.clear_stalled_alert(pid):
                user_rooms = self.storage.v3.list_rooms_for_principal(principal)
                for ur in user_rooms:
                    humans = self.storage.v3.get_room_humans(ur["id"])
                    human_targets = [f"@{h['name']}" for h in humans]
                    rec_msg = self.storage.v3.add_message(
                        room_name_or_id=ur["id"],
                        sender="System",
                        role="system",
                        content=f"✅ @{callsign} voltou a escutar.",
                        is_verified=True,
                        to=human_targets,
                        message_type="notice",
                    )
                    try:
                        await self._broadcast_to_websockets(ur["name"], {"type": "new_message", "message": rec_msg})
                    except Exception:
                        pass

        if is_agent and ack is not None and str(ack).strip() not in ("", "0"):
            self.storage.v3.confirm_batch(pid, ack_id=ack)

        def _build_payload(msgs: list[dict[str, Any]], redelivered: bool, is_timeout: bool = False) -> dict[str, Any] | str:
            batch_id = f"batch_{callsign}_{uuid.uuid4().hex[:10]}" if msgs else ""
            if is_agent and msgs and not redelivered:
                self.storage.v3.set_unconfirmed_batch(pid, [m["id"] for m in msgs], batch_id=batch_id)

            target_room = msgs[0]["room_name"] if msgs else (room or "geral")

            role_reminder = None
            r_info = None
            r_obj = self.storage.v3.get_room_by_name(target_room)
            if r_obj:
                r_info = self.storage.v3.get_agent_role_in_room(pid, r_obj["id"])
            if not r_info and principal.get("default_role_id"):
                r_info = self.storage.v3.get_role_by_id(principal["default_role_id"])
            if r_info:
                role_reminder = {
                    "role_key": r_info.get("role_key", ""),
                    "display_name": r_info.get("display_name", ""),
                    "reminder_text": r_info.get("reminder_text", ""),
                }

            next_action = ""
            try:
                assigned_tasks = self.storage.v3.list_tasks(assignee=callsign, status="in_progress")
                if not assigned_tasks:
                    assigned_tasks = self.storage.v3.list_tasks(assignee=callsign, status="open")
                if assigned_tasks:
                    t0 = assigned_tasks[0]
                    next_action = f"Tens {len(assigned_tasks)} tarefa(s) pendente(s): #{t0['id']} ({t0.get('title', '')})"
            except Exception:
                pass
            if not next_action:
                if msgs:
                    next_action = "Responde às mensagens dirigidas"
                else:
                    next_action = "Sem tarefas pendentes"

            summary = ""
            if len(msgs) > 5:
                by_sender: dict[str, int] = {}
                for m in msgs:
                    s_name = m.get("sender") or m.get("sender_name") or "Alguém"
                    by_sender[s_name] = by_sender.get(s_name, 0) + 1
                summary_parts = [f"{cnt} mensagem/mensagens de {snd}" for snd, cnt in by_sender.items()]
                summary = "; ".join(summary_parts)

            status_str = "timeout" if is_timeout else "new_messages"
            data = {
                "status": status_str,
                "work_status": "timeout" if is_timeout else "work_available",
                "batch_id": batch_id or None,
                "redelivered": redelivered,
                "count": len(msgs),
                "messages": msgs,
                "summary": summary,
                "role_reminder": role_reminder,
                "next_action": next_action,
                "skipped_count": 0,
                "skipped_ranges": [],
            }

            if format == "text":
                lines = ["[AI-CHAT WAKE-UP]"]
                if role_reminder and role_reminder.get("reminder_text"):
                    lines.append(f"Papel: {role_reminder.get('display_name')} - {role_reminder.get('reminder_text')}")
                if is_timeout:
                    lines.append("Estado: Sem novo trabalho dentro do período de espera (timeout).")
                else:
                    lines.append(f"Trabalho disponível: {len(msgs)} mensagem(ns) nova(s)" + (" [REENTREGUE]" if redelivered else "") + ".")
                    if summary:
                        lines.append(f"Resumo: {summary}")
                    for m in msgs:
                        m_sender = m.get("sender") or m.get("sender_name") or "Desconhecido"
                        m_room = m.get("room_name") or target_room
                        m_content = m.get("content", "").replace("\n", " ")
                        if len(m_content) > 120:
                            m_content = m_content[:117] + "..."
                        lines.append(f"- [Msg #{m['id']} de {m_sender} em #{m_room}]: {m_content}")
                lines.append(f"Ação seguinte: {next_action}")
                if batch_id:
                    lines.append(f"Batch ID: {batch_id} (confirma com ack={batch_id})")
                return "\n".join(lines)

            return data

        if is_agent:
            unconfirmed_info = self.storage.v3.get_unconfirmed_batch_info(pid)
            unconfirmed_ids = unconfirmed_info.get("message_ids", [])
            if unconfirmed_ids:
                delivered_at = unconfirmed_info.get("delivered_at")
                now = datetime.now(timezone.utc)
                deliv_dt = None
                if delivered_at:
                    try:
                        deliv_dt = datetime.fromisoformat(delivered_at.replace("Z", "+00:00"))
                    except Exception:
                        pass
                age = (now - deliv_dt).total_seconds() if deliv_dt else 0.0

                # Implicit confirmation: if agent returns to wait within 30 minutes (< 1800s),
                # the new wait implicitly confirms the previous batch.
                # Redelivery only occurs if the agent failed to wait within the 30m window (age >= 1800s).
                if age < 1800.0:
                    self.storage.v3.confirm_batch(pid)
                else:
                    re_msgs = self.storage.v3.get_messages_by_ids(unconfirmed_ids)
                    if re_msgs:
                        return _build_payload(re_msgs, redelivered=True, is_timeout=False)

        def _scan_work() -> list[dict[str, Any]]:
            accessible_rooms = self.storage.v3.list_rooms_for_principal(principal)
            if room:
                accessible_rooms = [r for r in accessible_rooms if r["name"].lower() == room.lower() or str(r["id"]) == str(room)]

            found: list[dict[str, Any]] = []
            for r in accessible_rooms:
                cur = self.storage.v3.get_read_cursor(pid, r["id"])
                max_id = self.storage.v3.get_max_message_id(r["id"])
                if cur < max_id:
                    unread_candidates = self.storage.v3.get_messages(r["id"], since_id=cur, limit=100)
                    for cand in unread_candidates:
                        if self.storage.v3.is_message_for_principal(cand, principal, r["id"]):
                            found.append(cand)
            found.sort(key=lambda m: m["id"])
            return found

        immediate = _scan_work()
        if immediate:
            return _build_payload(immediate, redelivered=False, is_timeout=False)

        if effective_timeout <= 0:
            return _build_payload([], redelivered=False, is_timeout=True)

        if is_agent:
            self.storage.v3.set_agent_listening(pid, True)

        try:
            event = asyncio.Event()
            listener_info = {
                "agent_name": callsign,
                "event": event,
                "started_at": datetime.now().isoformat(),
            }
            accessible_rooms = self.storage.v3.list_rooms_for_principal(principal)
            target_rooms = [r["name"] for r in accessible_rooms] if not room else [room]

            async with self._lock:
                for r_name in target_rooms:
                    r_key = r_name.strip().lower()
                    self._room_listeners.setdefault(r_key, []).append(listener_info)

            loop = asyncio.get_running_loop()
            start_time = loop.time()
            deadline = start_time + effective_timeout
            last_progress_time = start_time
            heartbeat_interval = 45.0

            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    return _build_payload([], redelivered=False, is_timeout=True)

                slice_timeout = min(heartbeat_interval, remaining)
                try:
                    await asyncio.wait_for(event.wait(), timeout=max(0.05, slice_timeout))
                    event.clear()
                except asyncio.TimeoutError:
                    elapsed = loop.time() - start_time
                    if on_progress and (loop.time() - last_progress_time >= 40.0):
                        last_progress_time = loop.time()
                        try:
                            await on_progress(elapsed, effective_timeout, f"Waiting for work... ({int(elapsed)}s elapsed)")
                        except Exception:
                            pass
                    continue

                new_work = _scan_work()
                if new_work:
                    return _build_payload(new_work, redelivered=False, is_timeout=False)

        finally:
            if is_agent:
                self.storage.v3.set_agent_listening(pid, False)
                self.storage.v3.record_agent_activity(pid)
            async with self._lock:
                for r_name in target_rooms:
                    r_key = r_name.strip().lower()
                    if r_key in self._room_listeners and listener_info in self._room_listeners[r_key]:
                        self._room_listeners[r_key].remove(listener_info)

    async def check_and_alert_stalled_agents(self) -> None:
        """
        Scans for stalled agents and sends alert messages targeted strictly to humans in the room.
        Adheres to backoff schedule (0m -> 10m -> 30m -> 60m).
        """
        if not (hasattr(self.storage, "is_v3") and self.storage.is_v3()):
            return
        thresholds = self.storage.v3.get_system_thresholds()
        stalled = self.storage.v3.list_stalled_agents_to_alert(
            t_idle=thresholds["t_idle_seconds"],
            t_unread=thresholds["t_unread_seconds"],
        )
        for st in stalled:
            pid = st["principal_id"]
            callsign = st["name"]
            unread_count = st["unread_count"]
            unread_m = st["unread_minutes"]
            act_m = st["activity_minutes"]
            room_id = st["room_id"]
            room_name = st["room_name"]

            humans = self.storage.v3.get_room_humans(room_id)
            if not humans:
                all_humans = self.storage.v3.list_humans() if hasattr(self.storage.v3, "list_humans") else []
                humans = [h for h in all_humans if h.get("kind") in (None, "human")]
            human_targets = [f"@{h['name']}" for h in humans if h.get("name")]
            if not human_targets:
                continue
            msg_text = (
                f"⚠️ @{callsign} não está a escutar e tem {unread_count} "
                f"{'mensagem' if unread_count == 1 else 'mensagens'} por ler há {unread_m}m "
                f"(última atividade há {act_m}m). Precisa de wake-up manual."
            )
            msg = self.storage.v3.add_message(
                room_name_or_id=room_id,
                sender="System",
                role="system",
                content=msg_text,
                is_verified=True,
                to=human_targets,
                message_type="alert",
                metadata={"is_liveliness_alert": True, "stalled_agent": callsign},
            )
            self.storage.v3.record_stalled_alert(pid)
            try:
                await self._broadcast_to_websockets(room_name, {"type": "new_message", "message": msg})
            except Exception:
                pass

    async def liveness_monitor_loop(self) -> None:
        """Background loop running periodic checks for stalled agents."""
        while True:
            try:
                await self.check_and_alert_stalled_agents()
            except asyncio.CancelledError:
                break
            except Exception:
                pass
            await asyncio.sleep(30.0)

    def get_room_team_status(self, room_name: str, requester_principal: Any = None) -> list[dict[str, Any]]:
        """Returns team presence and liveliness status for room members without sensitive tokens."""
        if hasattr(self.storage, "is_v3") and self.storage.is_v3():
            return self.storage.v3.get_room_team_status(room_name)
        return []


    def check_new_messages(
        self,
        room_name: str = "subscribed",
        agent_name: str = "",
        since_id: int = 0,
        password: str = "",
    ) -> dict[str, Any]:
        """
        Instant non-blocking check for new messages or reactions across one room, 'subscribed' rooms, or a list of rooms.
        """
        target_rooms = self._resolve_target_rooms(room_name, agent_name, password)
        clean_agent = agent_name.strip().lower() if agent_name else ""
        is_v3 = hasattr(self.storage, "is_v3") and self.storage.is_v3()
        principal = self.storage.v3.get_principal_by_name(agent_name) if (is_v3 and agent_name) else None

        if agent_name:
            for r in target_rooms:
                self.record_presence(r, agent_name.strip(), client="mcp_poll")

        all_new: list[dict[str, Any]] = []
        all_skipped: list[int] = []
        last_id = 0

        for r in target_rooms:
            max_id = self.storage.get_max_message_id(r)
            last_id = max(last_id, max_id)
            effective_since = since_id if since_id > 0 else 0
            has_cur = False
            if is_v3 and principal and effective_since == 0:
                r_obj = self.storage.v3.get_room_by_name(r)
                if r_obj:
                    has_cur = self.storage.v3.has_read_cursor(principal["id"], r_obj["id"])
                    if has_cur:
                        effective_since = self.storage.v3.get_read_cursor(principal["id"], r_obj["id"])

            if effective_since > 0 or (is_v3 and principal and has_cur):
                matched, last_scanned, skipped = self._scan_unread_messages(
                    r, effective_since, principal, is_v3, clean_agent
                )
                all_new.extend(matched)
                all_skipped.extend(skipped)

        target_room_set = {r.strip().lower() for r in target_rooms}
        recent_reactions = [
            ev for ev in self._reaction_events
            if ev["room"].strip().lower() in target_room_set
            and (not clean_agent or ev["sender"].strip().lower() != clean_agent)
            and (since_id == 0 or ev.get("message_id", 0) > since_id or ev.get("seq", 0) > since_id)
        ]

        role_reminder = None
        if is_v3 and principal and target_rooms:
            r_obj = self.storage.v3.get_room_by_name(target_rooms[0])
            if r_obj:
                r_info = self.storage.v3.get_agent_role_in_room(principal["id"], r_obj["id"])
                if r_info and r_info.get("reminder_text"):
                    role_reminder = r_info["reminder_text"]

        if since_id > 0 and len(target_rooms) == 1:
            res = {
                "status": "success",
                "room": target_rooms[0],
                "has_new": len(all_new) > 0,
                "count": len(all_new),
                "messages": all_new,
                "has_new_reactions": len(recent_reactions) > 0,
                "recent_reactions": recent_reactions,
                "last_id": max(m["id"] for m in all_new) if all_new else since_id,
                "room_max_id": self.storage.get_max_message_id(target_rooms[0]),
                "skipped_count": len(all_skipped),
                "skipped_ids": _limit_skipped_ids(all_skipped, 20),
                "skipped_ranges": _format_id_ranges(all_skipped),
            }
            if role_reminder:
                res["role_reminder"] = role_reminder
            return res
        elif len(target_rooms) == 1:
            if is_v3:
                # In v3, do not return 20 recent messages when there are no new messages
                res = {
                    "status": "success",
                    "room": target_rooms[0],
                    "has_new": len(all_new) > 0,
                    "count": len(all_new),
                    "messages": all_new,
                    "has_new_reactions": len(recent_reactions) > 0,
                    "recent_reactions": recent_reactions,
                    "last_id": max(m["id"] for m in all_new) if all_new else last_id,
                    "room_max_id": last_id,
                    "skipped_count": len(all_skipped),
                    "skipped_ids": _limit_skipped_ids(all_skipped, 20),
                    "skipped_ranges": _format_id_ranges(all_skipped),
                    "hint": f"{len(all_new)} new messages." if all_new else "No new messages.",
                }
            else:
                recent = self.storage.get_messages(target_rooms[0], since_id=0, limit=20)
                res = {
                    "status": "success",
                    "room": target_rooms[0],
                    "has_new": len(all_new) > 0,
                    "count": len(all_new) if all_new else len(recent),
                    "messages": all_new if all_new else recent,
                    "has_new_reactions": len(recent_reactions) > 0,
                    "recent_reactions": recent_reactions,
                    "last_id": last_id,
                    "room_max_id": last_id,
                    "hint": f"Room currently has {len(recent)} recent messages up to ID #{last_id}.",
                }
            if role_reminder:
                res["role_reminder"] = role_reminder
            return res
        else:
            res = {
                "status": "success",
                "rooms": target_rooms,
                "has_new": len(all_new) > 0,
                "count": len(all_new),
                "messages": all_new,
                "has_new_reactions": len(recent_reactions) > 0,
                "recent_reactions": recent_reactions,
                "last_id": last_id,
                "skipped_count": len(all_skipped),
                "skipped_ids": _limit_skipped_ids(all_skipped, 20),
                "skipped_ranges": _format_id_ranges(all_skipped),
                "hint": f"Checked {len(target_rooms)} subscribed rooms.",
            }
            if role_reminder:
                res["role_reminder"] = role_reminder
            return res

    def _notify_listeners(self, room_name: str, message: dict[str, Any] | None = None) -> None:
        """Triggers all waiting asyncio events for this room, respecting selective wake-up."""
        room_key = room_name.strip().lower()
        listeners = self._room_listeners.get(room_key, [])
        is_v3 = hasattr(self.storage, "is_v3") and self.storage.is_v3()
        r_obj = self.storage.v3.get_room_by_name(room_name) if is_v3 else None
        for entry in list(listeners):
            try:
                if message and is_v3 and r_obj:
                    ag_name = entry.get("agent_name", "") if isinstance(entry, dict) else ""
                    if ag_name:
                        p = self.storage.v3.get_principal_by_name(ag_name)
                        if p and not self.storage.v3.is_message_for_principal(message, p, r_obj["id"]):
                            continue  # Observer or not targeted -> do not wake up!
                if isinstance(entry, dict) and "event" in entry:
                    entry["event"].set()
                elif hasattr(entry, "set"):
                    entry.set()
            except Exception:
                pass

    def _notify_activity(self, room_name: str, event_type: str) -> None:
        """Logs an activity event and wakes up any Sentinel / background listeners waiting on this room or 'all'."""
        self._activity_seq += 1
        seq = self._activity_seq
        now_iso = datetime.now().isoformat()
        room_clean = (room_name or "general").strip()
        ev = {
            "seq": seq,
            "room": room_clean,
            "event_type": event_type,
            "timestamp": now_iso,
        }
        self._activity_events.append(ev)
        if len(self._activity_events) > 200:
            self._activity_events = self._activity_events[-200:]

        room_key = room_clean.lower()
        target_keys = {room_key, "all"}
        for k in target_keys:
            listeners = self._activity_listeners.get(k, [])
            for entry in list(listeners):
                try:
                    if isinstance(entry, dict) and "event" in entry:
                        entry["triggered_event"] = {
                            "status": "activity",
                            "room": room_clean,
                            "event_type": event_type,
                            "seq": seq,
                            "timestamp": now_iso,
                            "hint": "Activity detected. Use your agent_token with read_messages or task tools to fetch details.",
                        }
                        entry["event"].set()
                except Exception:
                    pass

    async def wait_for_activity(
        self,
        room_name: str = "all",
        since_seq: int | None = None,
        timeout_seconds: float = 30.0,
        watcher_name: str = "",
        on_progress: Any = None,
    ) -> dict[str, Any]:
        """
        Tokenless wake-up notification for Sentinel and background watchers:
        - room_name: Target room name, 'all' (or empty) to watch entire chat, or comma-separated room list.
        - since_seq: Activity sequence number. If >= 0, returns immediately if activity happened since that sequence.
        - timeout_seconds: Maximum wait time in seconds (1 to 3600, default 30).
        - watcher_name: Optional name (e.g. 'Sentinel') for presence recording in who_is_listening.
        - on_progress: Optional async callback for MCP progress reporting.
        Returns:
            {"status": "activity", "room": ..., "event_type": ..., "seq": ..., "timestamp": ..., ...}
            or {"status": "timeout", "room": ..., "seq": ...}
        """
        clean_watcher = (watcher_name or "").strip()
        clean_req = (room_name or "all").strip().lower()

        # Record watcher presence if name provided
        if clean_watcher:
            presence_room = "general" if clean_req in ("all", "*", "") else [r.strip() for r in clean_req.split(",") if r.strip()][0]
            self.record_presence(presence_room, clean_watcher, client="sentinel")

        # Parse target keys
        if clean_req in ("all", "*", ""):
            listen_keys = ["all"]
        else:
            listen_keys = [r.strip().lower() for r in clean_req.split(",") if r.strip()]

        listener_info: dict[str, Any] = {
            "event": asyncio.Event(),
            "triggered_event": None,
            "started_at": datetime.now().isoformat(),
        }

        async with self._lock:
            # If since_seq is specified (>= 0), check if an activity event already happened
            if since_seq is not None and since_seq >= 0:
                for ev in self._activity_events:
                    if ev["seq"] > since_seq:
                        ev_room_key = ev["room"].lower()
                        if "all" in listen_keys or ev_room_key in listen_keys:
                            return {
                                "status": "activity",
                                "room": ev["room"],
                                "event_type": ev["event_type"],
                                "seq": ev["seq"],
                                "timestamp": ev["timestamp"],
                                "hint": "Activity detected. Use your agent_token with read_messages or task tools to fetch details.",
                            }

            for k in listen_keys:
                if k not in self._activity_listeners:
                    self._activity_listeners[k] = []
                self._activity_listeners[k].append(listener_info)

        loop = asyncio.get_running_loop()
        start_time = loop.time()
        deadline = start_time + max(0.5, float(timeout_seconds))
        last_progress_time = start_time
        heartbeat_interval = 45.0

        try:
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    return {
                        "status": "timeout",
                        "room": room_name,
                        "seq": self._activity_seq,
                        "hint": "No activity detected within the timeout period.",
                    }

                slice_timeout = min(heartbeat_interval, remaining)
                try:
                    await asyncio.wait_for(listener_info["event"].wait(), timeout=max(0.05, slice_timeout))
                    if listener_info.get("triggered_event"):
                        return listener_info["triggered_event"]
                except asyncio.TimeoutError:
                    elapsed = loop.time() - start_time
                    if on_progress and (loop.time() - last_progress_time >= 40.0):
                        last_progress_time = loop.time()
                        try:
                            await on_progress(elapsed, float(timeout_seconds), f"Watching for activity in {room_name}... ({int(elapsed)}s elapsed)")
                        except Exception:
                            pass
                    continue
        finally:
            async with self._lock:
                for k in listen_keys:
                    if k in self._activity_listeners:
                        self._activity_listeners[k] = [
                            li for li in self._activity_listeners[k] if li is not listener_info
                        ]

    # WebSocket registration and broadcast
    async def register_websocket(
        self,
        room_name: str,
        websocket: Any,
        user_name: str = "WebUser",
        is_human: bool = False,
    ) -> None:
        """Registers a connected WebSocket for a room with identity metadata."""
        room_key = room_name.strip().lower()
        async with self._lock:
            if room_key not in self._active_websockets:
                self._active_websockets[room_key] = {}
            self._active_websockets[room_key][websocket] = {
                "name": user_name,
                "is_human": is_human,
                "connected_at": datetime.now().isoformat(),
            }

    async def unregister_websocket(self, room_name: str, websocket: Any) -> None:
        """Unregisters a WebSocket upon disconnect."""
        room_key = room_name.strip().lower()
        async with self._lock:
            if room_key in self._active_websockets:
                self._active_websockets[room_key].pop(websocket, None)

    async def _broadcast_to_websockets(self, room_name: str, payload: dict[str, Any]) -> None:
        """Pushes data to all active WebSockets connected to this room and notifies wake-up listeners."""
        # 1. Notify wake-up / activity listeners (Sentinel, etc.)
        raw_type = payload.get("type", "")
        if raw_type and raw_type != "presence_updated":
            if "message" in raw_type:
                cat = "message"
            elif "poll" in raw_type:
                cat = "poll"
            elif "reaction" in raw_type:
                cat = "reaction"
            elif "decision" in raw_type:
                cat = "decision"
            elif "task" in raw_type:
                cat = "task"
            elif "room" in raw_type:
                cat = "room"
            else:
                cat = raw_type
            self._notify_activity(room_name, cat)

        # 2. Push to connected WebSockets
        room_key = room_name.strip().lower()
        sockets_map = self._active_websockets.get(room_key, {})
        if not sockets_map:
            return
        sockets = list(sockets_map.keys())
        dead_sockets = []
        for ws in sockets:
            try:
                await ws.send_json(payload)
            except Exception:
                dead_sockets.append(ws)

        if dead_sockets:
            async with self._lock:
                for ws in dead_sockets:
                    self._active_websockets.get(room_key, {}).pop(ws, None)

    # -------------------------------------------------------------
    # Real-Time Room Presence Tracking (v2.5)
    # -------------------------------------------------------------
    def record_presence(
        self,
        room_name: str,
        name: str,
        client: str = "sentinel",
        is_human: bool = False,
    ) -> None:
        """Records presence heartbeat for an HTTP / Sentinel / MCP poller."""
        if not name or not room_name:
            return
        clean_name = name.strip()
        room_key = room_name.strip().lower()
        now_dt = datetime.now()
        now_ts = time.time()
        self._recent_http_polls[(room_key, clean_name.lower())] = {
            "name": clean_name,
            "room": room_name.strip(),
            "timestamp": now_ts,
            "last_seen": now_dt.isoformat(),
            "client": client,
            "is_human": is_human,
        }
        try:
            self.storage.update_member_last_seen(room_name, clean_name)
        except Exception:
            pass

    def who_is_listening(self, room_name: str, password: str = "", requester_token: str = "") -> dict[str, Any]:
        """
        Returns all active listeners in the room within the active threshold (60s).
        Enforces room password check for protected rooms.
        """
        canonical_name = self.get_canonical_room_name(room_name, password, requester_token=requester_token)
        room_key = canonical_name.lower()
        now_ts = time.time()
        now_iso = datetime.now().isoformat()

        # Map by lowercase name to avoid duplicates
        active_map: dict[str, dict[str, Any]] = {}

        # 1. Connected WebSockets (Web UI)
        ws_entries = self._active_websockets.get(room_key, {})
        for ws, info in ws_entries.items():
            name = info.get("name") or "Humano (Web UI)"
            is_human = info.get("is_human", True)
            active_map[name.lower()] = {
                "name": name,
                "role": "human" if is_human else "agent",
                "client": "web_ui",
                "status": "connected",
                "last_seen": now_iso,
            }

        # 2. Long-polling MCP listeners (wait_for_new_messages)
        listeners = self._room_listeners.get(room_key, [])
        for entry in listeners:
            if isinstance(entry, dict):
                agent_name = entry.get("agent_name") or "Agent"
                active_map[agent_name.lower()] = {
                    "name": agent_name,
                    "role": "agent",
                    "client": "mcp_listener",
                    "status": "listening",
                    "last_seen": now_iso,
                    "started_at": entry.get("started_at", now_iso),
                }

        # 3. Recent HTTP pollers (Sentinel / REST polls within 60s)
        for (r_k, n_low), poll_info in list(self._recent_http_polls.items()):
            if r_k == room_key or r_k == "all":
                elapsed = now_ts - poll_info["timestamp"]
                if elapsed <= 60.0:
                    name = poll_info["name"]
                    is_h = poll_info.get("is_human", False)
                    if n_low not in active_map:
                        active_map[n_low] = {
                            "name": name,
                            "role": "human" if is_h else "agent",
                            "client": poll_info.get("client", "sentinel"),
                            "status": "active",
                            "last_seen": poll_info["last_seen"],
                            "idle_seconds": round(elapsed, 1),
                        }

        sorted_listeners = sorted(
            active_map.values(),
            key=lambda x: (0 if x["role"] == "human" else 1, x["name"].lower()),
        )

        return {
            "status": "success",
            "room": canonical_name,
            "total_listening": len(sorted_listeners),
            "listeners": sorted_listeners,
        }

    # -------------------------------------------------------------
    # Task Planner Lifecycle & Security (v2.5)
    # -------------------------------------------------------------
    async def create_task(
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
        member_token: str = "",
        human_token: str = "",
        password: str = "",
        created_by: str = "",
        parent_task_id: int | None = None,
        dependencies: list[int] | None = None,
        progress_percent: int = 0,
    ) -> dict[str, Any]:
        """Creates a task in a room and broadcasts the event."""
        canonical_name = self.get_canonical_room_name(room_name, password, requester_token=human_token)
        clean_created_by = created_by.strip()
        clean_ht = (human_token or "").strip()
        is_human = bool(clean_ht and secrets.compare_digest(clean_ht, self.human_token))

        if is_human:
            effective_creator = clean_created_by or self.human_name
        elif clean_created_by:
            valid, err = self.storage.verify_member_token(canonical_name, clean_created_by, member_token)
            if not valid:
                raise PermissionError(f"Acesso negado: {err}")
            effective_creator = clean_created_by
        else:
            effective_creator = "Agent"

        task = self.storage.create_task(
            room_name=canonical_name,
            title=title,
            description=description,
            assignee=assignee,
            waiting_for_agent=waiting_for_agent,
            priority=priority,
            status=status,
            order_index=order_index,
            message_id=message_id,
            uses_gpu=uses_gpu,
            gpu_est_min=gpu_est_min,
            start_at=start_at,
            due_at=due_at,
            resource=resource,
            created_by=effective_creator,
            parent_task_id=parent_task_id,
            dependencies=dependencies,
            progress_percent=progress_percent,
        )
        await self._broadcast_to_websockets(canonical_name, {
            "type": "task_created",
            "room": canonical_name,
            "task": task,
        })
        return task

    async def update_task(
        self,
        task_id: int,
        member_token: str = "",
        human_token: str = "",
        password: str = "",
        actor: str = "",
        **fields,
    ) -> dict[str, Any]:
        """Updates a task, verifying authorization and password for private rooms."""
        existing = self.storage.get_task_by_id(task_id)
        if not existing:
            raise ValueError(f"Tarefa #{task_id} não encontrada.")

        room_name = existing["room_name"]
        canonical_name = self.get_canonical_room_name(room_name, password, requester_token=human_token)

        clean_ht = (human_token or "").strip()
        is_human = bool(clean_ht and secrets.compare_digest(clean_ht, self.human_token))

        clean_actor = actor.strip()
        if is_human:
            effective_actor = clean_actor or self.human_name
        else:
            creator_name = existing.get("creator_name") or (existing.get("created_by") if isinstance(existing.get("created_by"), str) else "") or ""
            assignee_name = existing.get("assignee_name") or (existing.get("assignee") if isinstance(existing.get("assignee"), str) else "") or ""
            expected_owners = [str(o).strip() for o in (assignee_name, creator_name) if o and str(o).strip()]
            if expected_owners and clean_actor:
                if clean_actor.lower() in [o.lower() for o in expected_owners]:
                    valid, err = self.storage.verify_member_token(canonical_name, clean_actor, member_token)
                    if not valid:
                        raise PermissionError(f"Acesso negado: {err}")
                else:
                    # Exception: If claiming an unassigned task
                    if not assignee_name and fields.get("assignee") == clean_actor:
                        valid, err = self.storage.verify_member_token(canonical_name, clean_actor, member_token)
                        if not valid:
                            raise PermissionError(f"Acesso negado: {err}")
                    else:
                        raise PermissionError(
                            f"Acesso negado: Apenas o responsável (@{assignee_name or 'não atribuído'}) ou o criador (@{creator_name or 'desconhecido'}) podem modificar esta tarefa."
                        )
            elif expected_owners and not clean_actor:
                token_matched = False
                for owner in expected_owners:
                    valid, _ = self.storage.verify_member_token(canonical_name, owner, member_token)
                    if valid and member_token:
                        token_matched = True
                        clean_actor = owner
                        break
                if not token_matched:
                    raise PermissionError(
                        f"Acesso negado: Para modificar a tarefa #{task_id}, indique o seu nome (actor) e o seu member_token."
                    )
            effective_actor = clean_actor or "Agent"

        updated = self.storage.update_task(task_id, actor=effective_actor, **fields)
        await self._broadcast_to_websockets(canonical_name, {
            "type": "task_updated",
            "room": canonical_name,
            "task": updated,
        })

        # Hand-off notification when completing a prerequisite task
        if updated.get("status") == "done" and existing.get("status") != "done":
            try:
                unblocked = self.storage.get_unblocked_tasks_on_completion(task_id)
                for ut in unblocked:
                    # Targeted notification strictly to assignee or waiting_for_agent or created_by
                    target = (ut.get("assignee_name") or ut.get("waiting_name") or ut.get("assignee") or ut.get("waiting_for_agent") or ut.get("creator_name") or ut.get("created_by") or "").strip()
                    if target:
                        target_callsign = target.lstrip("@")
                        msg_text = (
                            f"🔔 **[TAREFA DESBLOQUEADA]**:\n\n"
                            f"A tarefa pré-requisito #{task_id} ('{existing.get('title')}') foi concluída por {effective_actor}.\n"
                            f"A tarefa #{ut['id']} ('{ut.get('title')}') está agora desbloqueada e pronta para execução."
                        )
                        try:
                            await self.send_message(
                                room_name=ut.get("room_name") or canonical_name,
                                sender="System",
                                content=msg_text,
                                role="system",
                                human_token=self.human_token,
                                to=[f"@{target_callsign}"],
                            )
                        except Exception:
                            pass
            except Exception:
                pass

        return updated

    async def delete_task(
        self,
        task_id: int,
        member_token: str = "",
        human_token: str = "",
        password: str = "",
        actor: str = "",
    ) -> dict[str, Any]:
        """Deletes a task after verifying authorization."""
        existing = self.storage.get_task_by_id(task_id)
        if not existing:
            raise ValueError(f"Tarefa #{task_id} não encontrada.")

        room_name = existing["room_name"]
        canonical_name = self.get_canonical_room_name(room_name, password, requester_token=human_token)

        clean_ht = (human_token or "").strip()
        is_human = bool(clean_ht and secrets.compare_digest(clean_ht, self.human_token))

        if not is_human:
            clean_actor = actor.strip()
            creator_name = existing.get("creator_name") or (existing.get("created_by") if isinstance(existing.get("created_by"), str) else "") or ""
            assignee_name = existing.get("assignee_name") or (existing.get("assignee") if isinstance(existing.get("assignee"), str) else "") or ""
            expected_owners = [str(o).strip() for o in (assignee_name, creator_name) if o and str(o).strip()]
            if expected_owners and clean_actor:
                if clean_actor.lower() in [o.lower() for o in expected_owners]:
                    valid, err = self.storage.verify_member_token(canonical_name, clean_actor, member_token)
                    if not valid:
                        raise PermissionError(f"Acesso negado: {err}")
                else:
                    raise PermissionError("Acesso negado: Apenas o responsável ou criador podem eliminar esta tarefa.")
            elif expected_owners and not clean_actor:
                token_matched = False
                for owner in expected_owners:
                    valid, _ = self.storage.verify_member_token(canonical_name, owner, member_token)
                    if valid and member_token:
                        token_matched = True
                        break
                if not token_matched:
                    raise PermissionError("Acesso negado: Forneça member_token válido para eliminar a tarefa.")

        self.storage.delete_task(task_id)
        await self._broadcast_to_websockets(canonical_name, {
            "type": "task_deleted",
            "room": canonical_name,
            "task_id": task_id,
        })
        return {"status": "success", "task_id": task_id}

    async def add_task_dependency(self, task_id: int, depends_on_task_id: int) -> dict[str, Any]:
        """Adds a dependency between tasks with cycle detection."""
        self.storage.add_task_dependency(task_id, depends_on_task_id)
        task = self.storage.get_task_by_id(task_id)
        if task:
            await self._broadcast_to_websockets(task["room_name"], {
                "type": "task_updated",
                "room": task["room_name"],
                "task": task,
            })
        return {"status": "success", "task_id": task_id, "depends_on_task_id": depends_on_task_id}

    async def remove_task_dependency(self, task_id: int, depends_on_task_id: int) -> dict[str, Any]:
        """Removes a dependency between tasks."""
        res = self.storage.remove_task_dependency(task_id, depends_on_task_id)
        task = self.storage.get_task_by_id(task_id)
        if task:
            await self._broadcast_to_websockets(task["room_name"], {
                "type": "task_updated",
                "room": task["room_name"],
                "task": task,
            })
        return {"status": "success", "removed": res, "task_id": task_id, "depends_on_task_id": depends_on_task_id}

    def get_task_dependencies(self, task_id: int) -> list[int]:
        """Gets dependency IDs for a task."""
        return self.storage.get_task_dependencies(task_id)

    def list_tasks(
        self,
        room_name: str,
        status: str | None = None,
        assignee: str | None = None,
        hide_completed: bool = False,
        password: str = "",
        requester_token: str = "",
    ) -> list[dict[str, Any]]:
        """Lists tasks for a room, checking room password and supporting hide_completed."""
        canonical_name = self.get_canonical_room_name(room_name, password, requester_token=requester_token)
        return self.storage.list_tasks(
            canonical_name,
            status=status,
            assignee=assignee,
            hide_completed=hide_completed,
        )

    async def reorder_tasks(
        self,
        room_name: str,
        task_ids: list[int],
        member_token: str = "",
        human_token: str = "",
        password: str = "",
    ) -> list[dict[str, Any]]:
        """Reorders tasks in a room and broadcasts the update."""
        canonical_name = self.get_canonical_room_name(room_name, password, requester_token=human_token)
        tasks = self.storage.reorder_tasks(canonical_name, task_ids)
        await self._broadcast_to_websockets(canonical_name, {
            "type": "tasks_reordered",
            "room": canonical_name,
            "tasks": tasks,
        })
        return tasks

    # -------------------------------------------------------------
    # Calendar & Resource Management (v2.8)
    # -------------------------------------------------------------
    async def calendar_dispatcher_loop(self) -> None:
        """
        Background worker running on the Hub:
        Periodically checks for calendar events reaching start_at or end_at.
        Emits wake-up events to the room and broadcasts to WebSockets.
        """
        while True:
            try:
                now_iso = datetime.now().isoformat()
                # 1. Trigger events reaching start_at
                due_events = self.storage.get_due_calendar_events(now_iso)
                for ev in due_events:
                    self.storage.mark_event_start_notified(ev["id"])
                    room = ev["room_name"]
                    title = ev.get("title", "")
                    res = ev.get("resource", "")
                    target = ev.get("target_agent", "")

                    wake_start = bool(ev["wake_on_start"]) if "wake_on_start" in ev and ev["wake_on_start"] is not None else True
                    if wake_start:
                        self._notify_activity(room, event_type="calendar_event_start")
                    await self._broadcast_to_websockets(
                        room,
                        {
                            "type": "calendar_event_start",
                            "room": room,
                            "event": ev,
                            "notice": f"⏰ Evento agendado iniciado: '{title}'" + (f" (Recurso: {res})" if res else "") + (f" [@{target}]" if target else ""),
                        },
                    )

                # 2. Trigger events reaching end_at
                ending_events = self.storage.get_ending_calendar_events(now_iso)
                for ev in ending_events:
                    self.storage.mark_event_end_notified(ev["id"])
                    room = ev["room_name"]
                    title = ev.get("title", "")
                    res = ev.get("resource", "")

                    wake_end = bool(ev["wake_on_end"]) if "wake_on_end" in ev and ev["wake_on_end"] is not None else False
                    if wake_end:
                        self._notify_activity(room, event_type="calendar_event_end")
                    await self._broadcast_to_websockets(
                        room,
                        {
                            "type": "calendar_event_end",
                            "room": room,
                            "event": ev,
                            "notice": f"🏁 Evento concluído: '{title}'" + (f" (Recurso '{res}' libertado)" if res else ""),
                        },
                    )
            except asyncio.CancelledError:
                break
            except Exception:
                pass

            try:
                await asyncio.sleep(5)
            except asyncio.CancelledError:
                break

    async def create_calendar_event(
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
        member_token: str = "",
        human_token: str = "",
        password: str = "",
        created_by: str = "",
        force: bool = False,
        is_personal: bool = False,
    ) -> dict[str, Any]:
        """Creates a calendar event and broadcasts to room."""
        canonical_name = self.get_canonical_room_name(room_name, password, requester_token=human_token or member_token)
        clean_created_by = (created_by or "").strip()
        clean_ht = (human_token or "").strip()
        is_human = bool(clean_ht and secrets.compare_digest(clean_ht, self.human_token))

        if is_human:
            effective_creator = clean_created_by or self.human_name
        elif clean_created_by:
            valid, err = self.storage.verify_member_token(canonical_name, clean_created_by, member_token)
            if not valid:
                try:
                    ident = self.authenticate_agent(member_token)
                    effective_creator = ident["callsign"]
                except Exception:
                    effective_creator = clean_created_by
            else:
                effective_creator = clean_created_by
        else:
            effective_creator = "Agent"

        if force and not is_human:
            raise PermissionError("Acesso negado: Apenas utilizadores humanos podem forçar sobreposição de reservas de recursos (force=True).")
        allow_force = force and is_human

        event = self.storage.create_calendar_event(
            room_name=canonical_name,
            title=title,
            start_at=start_at,
            end_at=end_at,
            description=description,
            event_type=event_type,
            task_id=task_id,
            resource=resource,
            target_agent=target_agent,
            status=status,
            wake_on_start=wake_on_start,
            wake_on_end=wake_on_end,
            created_by=effective_creator,
            force=allow_force,
            is_personal=is_personal,
        )

        await self._broadcast_to_websockets(canonical_name, {
            "type": "calendar_event_created",
            "room": canonical_name,
            "event": event,
        })
        self._notify_activity(canonical_name, event_type="calendar")
        return event

    async def update_calendar_event(
        self,
        event_id: int,
        member_token: str = "",
        human_token: str = "",
        password: str = "",
        force: bool = False,
        **fields,
    ) -> dict[str, Any]:
        """Updates a calendar event, validating permissions and resource conflicts."""
        existing = self.storage.get_calendar_event_by_id(event_id)
        if not existing:
            raise ValueError(f"Evento #{event_id} não encontrado.")

        room_name = existing["room_name"]
        canonical_name = self.get_canonical_room_name(room_name, password, requester_token=human_token or member_token)

        clean_ht = (human_token or "").strip()
        is_human = bool(clean_ht and secrets.compare_digest(clean_ht, self.human_token))
        if force and not is_human:
            raise PermissionError("Acesso negado: Apenas utilizadores humanos podem forçar sobreposição de reservas de recursos (force=True).")
        allow_force = force and is_human

        updated = self.storage.update_calendar_event(
            event_id=event_id,
            force=allow_force,
            **fields,
        )

        await self._broadcast_to_websockets(canonical_name, {
            "type": "calendar_event_updated",
            "room": canonical_name,
            "event": updated,
        })
        self._notify_activity(canonical_name, event_type="calendar")
        return updated

    async def delete_calendar_event(
        self,
        event_id: int,
        member_token: str = "",
        human_token: str = "",
        password: str = "",
        force: bool = False,
    ) -> dict[str, Any]:
        """Deletes a calendar event and broadcasts to room."""
        existing = self.storage.get_calendar_event_by_id(event_id)
        if not existing:
            raise ValueError(f"Evento #{event_id} não encontrado.")

        room_name = existing["room_name"]
        canonical_name = self.get_canonical_room_name(room_name, password, requester_token=human_token or member_token)

        self.storage.delete_calendar_event(event_id)
        await self._broadcast_to_websockets(canonical_name, {
            "type": "calendar_event_deleted",
            "room": canonical_name,
            "event_id": event_id,
        })
        self._notify_activity(canonical_name, event_type="calendar")
        return {"status": "success", "event_id": event_id}

    def list_calendar_events(
        self,
        room_name: str = "all",
        start_from: str = "",
        start_to: str = "",
        resource: str = "",
        status: str = "",
        include_completed: bool = True,
        password: str = "",
        requester_token: str = "",
        filter_type: str = "",
        requester_principal: Any = None,
    ) -> list[dict[str, Any]]:
        """Lists calendar events with optional filtering."""
        if room_name and room_name not in ("all", "*"):
            canonical_name = self.get_canonical_room_name(room_name, password, requester_token=requester_token)
        else:
            canonical_name = "all"

        events = self.storage.list_calendar_events(
            room_name=canonical_name,
            start_from=start_from,
            start_to=start_to,
            resource=resource,
            status=status,
            include_completed=include_completed,
            filter_type=filter_type,
            requester_id_or_name=requester_principal or requester_token,
        )

        if canonical_name != "all":
            return events

        # Verified human supervisor has master access to all calendar events
        is_supervisor = bool(
            (requester_token and secrets.compare_digest(requester_token.strip(), self.human_token))
            or (password and secrets.compare_digest(password.strip(), self.human_token))
        )
        if is_supervisor:
            return events

        # Filter out events from protected rooms that caller cannot access
        allowed_rooms: dict[str, bool] = {}
        filtered = []
        for ev in events:
            if ev.get("is_personal"):
                filtered.append(ev)
                continue
            r = ev.get("room_name")
            if not r:
                filtered.append(ev)
                continue
            if r not in allowed_rooms:
                try:
                    allowed_rooms[r] = self.verify_room_access(r, password=password, requester_token=requester_token)
                except Exception:
                    allowed_rooms[r] = False
            if allowed_rooms[r]:
                filtered.append(ev)
        return filtered

    def get_resource_status(self, resources: list[str] | None = None) -> list[dict[str, Any]]:
        """Returns hardware resource availability."""
        return self.storage.get_resource_status(resources=resources)
