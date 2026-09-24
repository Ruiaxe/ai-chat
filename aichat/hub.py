import asyncio
import hashlib
import os
import secrets
import time
from datetime import datetime
from typing import Any

from aichat.storage import ChatStorage


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
        )
        return room

    def verify_room_access(self, room_name: str, password: str = "") -> bool:
        """Checks if access to the room is granted."""
        room = self.storage.get_room(room_name)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")

        if not room["is_protected"]:
            return True

        # Room is protected, verify password
        if not password:
            return False
        return self._verify_password(password, room["password_hash"], room["salt"])

    def get_canonical_room_name(self, room_name: str, password: str = "") -> str:
        """Resolves room, checks existence and password access, and returns canonical name."""
        room = self.storage.get_room(room_name)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")
        if not self.verify_room_access(room_name, password):
            raise PermissionError(f"Access denied to room '{room_name}': Invalid or missing password.")
        return room["name"]

    def list_rooms(self, include_archived: bool = True) -> list[dict[str, Any]]:
        """Lists all existing rooms with metadata."""
        return self.storage.list_rooms(include_archived=include_archived)

    def get_room_info(self, room_name: str, password: str = "") -> dict[str, Any]:
        """Gets room information, verifying password if protected."""
        room = self.storage.get_room(room_name)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")

        if room["is_protected"] and not self.verify_room_access(room_name, password):
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
    ) -> dict[str, Any]:
        """Rotates a member's token for a room, validating current token or room password."""
        import secrets
        clean_member = member_name.strip()
        room = self.storage.get_room(room_name)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")
        canonical_name = room["name"]

        mem = self.storage.get_member(canonical_name, clean_member)
        if not mem:
            raise ValueError(f"O membro '{clean_member}' não está registado na sala '{canonical_name}'.")

        authorized = False
        if mem.get("token") and current_token:
            if secrets.compare_digest(current_token.strip(), mem["token"]):
                authorized = True
        if not authorized and room["is_protected"] and password:
            if self.verify_room_access(canonical_name, password):
                authorized = True
        if not authorized and not mem.get("token"):
            authorized = True

        if not authorized:
            self.storage.log_audit_event(canonical_name, clean_member, "token_rotate", "failure", "Unauthorized token rotation attempt")
            raise PermissionError("Acesso negado: Para renovar o token, forneça o current_token atual ou a senha da sala.")

        new_token = self.storage.rotate_member_token(canonical_name, clean_member)
        self.storage.log_audit_event(canonical_name, clean_member, "token_rotate", "success", "Token rotated securely")
        return {
            "status": "rotated",
            "room_name": canonical_name,
            "member_name": clean_member,
            "member_token": new_token,
        }

    def change_room_password(
        self,
        room_name: str,
        old_password: str,
        new_password: str,
        actor_name: str = "",
        supervisor_token: str = "",
    ) -> dict[str, Any]:
        """Changes room password after verifying old password or supervisor token."""
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
        elif not room["is_protected"]:
            authorized = True
        elif old_password and self.verify_room_access(canonical_name, old_password):
            authorized = True

        if not authorized:
            self.storage.log_audit_event(canonical_name, clean_actor, "password_change", "failure", "Invalid old password or supervisor credentials")
            raise PermissionError("Acesso negado: Senha anterior incorreta ou credencial de supervisor inválida.")

        clean_new = new_password.strip()
        is_protected = bool(clean_new)
        pwd_hash = ""
        salt = ""
        if is_protected:
            pwd_hash, salt = self._hash_password(clean_new)

        self.storage.update_room_password(canonical_name, pwd_hash, salt, is_protected)
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

        room = self.storage.get_room(room_name)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")
        canonical_name = room["name"]

        if room.get("is_archived", False):
            raise ValueError(f"A sala '{canonical_name}' foi arquivada pelo utilizador humano e está em modo apenas de leitura.")

        if not self.verify_room_access(canonical_name, password):
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
            valid, err = self.storage.verify_member_token(canonical_name, clean_sender, member_token)
            if not valid:
                raise PermissionError(err)
            if valid and member_token:
                is_verified = True

        # Save to database and log files
        msg = self.storage.add_message(
            room_name=canonical_name,
            sender=clean_sender,
            role=role,
            content=clean_content,
            is_verified=is_verified,
            message_type=message_type,
            metadata=metadata,
        )

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
        self._notify_listeners(canonical_name)

        return msg

    def archive_room(self, room_name: str, requester_role: str = "human") -> dict[str, Any]:
        """Archives a room. Restricted strictly to human users."""
        if requester_role != "human":
            raise PermissionError("Apenas o utilizador humano tem permissão para arquivar salas.")
        room = self.storage.get_room(room_name)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")
        self.storage.archive_room(room["name"])
        return {"status": "archived", "room_name": room["name"]}

    def unarchive_room(self, room_name: str, requester_role: str = "human") -> dict[str, Any]:
        """Restores an archived room. Restricted strictly to human users."""
        if requester_role != "human":
            raise PermissionError("Apenas o utilizador humano tem permissão para desarquivar salas.")
        room = self.storage.get_room(room_name)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")
        self.storage.unarchive_room(room["name"])
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
    ) -> dict[str, Any]:
        """Calls the human user for a decision with optional predefined choices."""
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
        msg = await self.send_message(
            room_name=room_name,
            sender=sender,
            content=content,
            role="agent",
            member_token=member_token,
            message_type="decision_request",
            metadata=metadata,
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
        decider: str = "Rui",
        human_token: str = "",
    ) -> dict[str, Any]:
        """Human submits their decision, resolving the request and posting a confirmation."""
        import secrets
        clean_ht = (human_token or "").strip()
        if clean_ht and not secrets.compare_digest(clean_ht, self.human_token):
            raise PermissionError("Acesso negado: Apenas o utilizador humano com autenticação válida pode tomar decisões.")
        meta = self.storage.resolve_decision(message_id, decision, decider=decider)
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
                    actor=decider,
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
            sender=decider,
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
    ) -> dict[str, Any]:
        """Closes an active poll."""
        import secrets
        p_current = self.storage.get_poll(poll_id)
        if not p_current:
            raise ValueError(f"Poll #{poll_id} não existe.")
        if p_current.get("is_closed"):
            raise ValueError(f"A votação #{poll_id} já se encontra encerrada.")

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
        results_str = "\n".join(f"- {opt['text']}: **{opt['votes']} votos ({opt['percentage']}%)**" for opt in poll["options"])

        await self.send_message(
            room_name=poll["room_name"],
            sender=closer,
            content=f"🏁 **[VOTAÇÃO ENCERRADA #{poll['id']}]**\n\n**{poll['question']}**\n\n**Resultado Final:**\n{results_str}\nTotal de votos: {poll['total_votes']}",
            role=role_to_use,
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
        limit: int = 50,
        message_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """Reads recent messages from room, or fetches a single message by message_id."""
        if not self.verify_room_access(room_name, password):
            raise PermissionError(f"Access denied to room '{room_name}': Invalid or missing password.")

        if message_id is not None and message_id > 0:
            msg = self.storage.get_message_by_id(message_id)
            if msg and msg["room_name"].strip().lower() == room_name.strip().lower():
                return [msg]
            return []

        return self.storage.get_messages(room_name=room_name, since_id=since_id, limit=limit)

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

        # Map each room to its effective since_id
        room_since_ids: dict[str, int] = {}
        for r in target_rooms:
            max_id = self.storage.get_max_message_id(r)
            if len(target_rooms) == 1 and since_id > 0:
                room_since_ids[r] = since_id
            else:
                room_since_ids[r] = max_id

        # Record the reaction sequence at start
        start_reaction_seq = self._reaction_seq

        # If since_id was explicitly provided for a single room and unread messages already exist, return them immediately
        if len(target_rooms) == 1 and since_id > 0:
            current_msgs = self.storage.get_messages(target_rooms[0], since_id=since_id, limit=50)
            external_msgs = [
                m for m in current_msgs
                if not clean_agent or m["sender"].strip().lower() != clean_agent
            ]
            if external_msgs:
                return {
                    "status": "new_messages",
                    "room": target_rooms[0],
                    "count": len(external_msgs),
                    "messages": external_msgs,
                    "last_id": max(m["id"] for m in current_msgs),
                }

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

                # Event fired! Collect all new messages from ALL target_rooms
                all_found_messages = []
                last_room_found = ""
                for r in target_rooms:
                    effective_since = room_since_ids[r]
                    new_msgs = self.storage.get_messages(r, since_id=effective_since, limit=50)
                    external_new = [
                        m for m in new_msgs
                        if not clean_agent or m["sender"].strip().lower() != clean_agent
                    ]
                    if external_new:
                        all_found_messages.extend(external_new)
                        last_room_found = r
                    if new_msgs:
                        room_since_ids[r] = max(m["id"] for m in new_msgs)

                if all_found_messages:
                    all_found_messages.sort(key=lambda m: m["id"])
                    distinct_rooms = {m["room_name"].lower() for m in all_found_messages}
                    return {
                        "status": "new_messages",
                        "room": all_found_messages[0]["room_name"] if len(distinct_rooms) == 1 else "subscribed",
                        "count": len(all_found_messages),
                        "messages": all_found_messages,
                        "last_id": all_found_messages[-1]["id"],
                    }

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
            async with self._lock:
                for r in target_rooms:
                    r_key = r.strip().lower()
                    if r_key in self._room_listeners:
                        self._room_listeners[r_key] = [
                            li for li in self._room_listeners[r_key]
                            if (li.get("event") if isinstance(li, dict) else li) != event
                        ]

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
        if agent_name:
            for r in target_rooms:
                self.record_presence(r, agent_name.strip(), client="mcp_poll")

        all_new: list[dict[str, Any]] = []
        last_id = 0

        for r in target_rooms:
            max_id = self.storage.get_max_message_id(r)
            last_id = max(last_id, max_id)
            effective_since = since_id if since_id > 0 else 0
            if effective_since > 0:
                msgs = self.storage.get_messages(r, since_id=effective_since, limit=50)
                external = [
                    m for m in msgs
                    if not clean_agent or m["sender"].strip().lower() != clean_agent
                ]
                all_new.extend(external)

        target_room_set = {r.strip().lower() for r in target_rooms}
        recent_reactions = [
            ev for ev in self._reaction_events
            if ev["room"].strip().lower() in target_room_set
            and (not clean_agent or ev["sender"].strip().lower() != clean_agent)
            and (since_id == 0 or ev.get("message_id", 0) > since_id or ev.get("seq", 0) > since_id)
        ]

        if since_id > 0 and len(target_rooms) == 1:
            return {
                "status": "success",
                "room": target_rooms[0],
                "has_new": len(all_new) > 0,
                "count": len(all_new),
                "messages": all_new,
                "has_new_reactions": len(recent_reactions) > 0,
                "recent_reactions": recent_reactions,
                "last_id": max(m["id"] for m in all_new) if all_new else since_id,
                "room_max_id": self.storage.get_max_message_id(target_rooms[0]),
            }
        elif len(target_rooms) == 1:
            recent = self.storage.get_messages(target_rooms[0], since_id=0, limit=20)
            return {
                "status": "success",
                "room": target_rooms[0],
                "has_new": False,
                "count": len(recent),
                "messages": recent,
                "has_new_reactions": len(recent_reactions) > 0,
                "recent_reactions": recent_reactions,
                "last_id": last_id,
                "room_max_id": last_id,
                "hint": f"Room currently has {len(recent)} recent messages up to ID #{last_id}.",
            }
        else:
            return {
                "status": "success",
                "rooms": target_rooms,
                "has_new": len(all_new) > 0,
                "count": len(all_new),
                "messages": all_new,
                "has_new_reactions": len(recent_reactions) > 0,
                "recent_reactions": recent_reactions,
                "last_id": last_id,
                "hint": f"Checked {len(target_rooms)} subscribed rooms.",
            }

    def _notify_listeners(self, room_name: str) -> None:
        """Triggers all waiting asyncio events for this room."""
        room_key = room_name.strip().lower()
        listeners = self._room_listeners.get(room_key, [])
        for entry in list(listeners):
            try:
                if isinstance(entry, dict) and "event" in entry:
                    entry["event"].set()
                elif hasattr(entry, "set"):
                    entry.set()
            except Exception:
                pass

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
        """Pushes data to all active WebSockets connected to this room."""
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

    def who_is_listening(self, room_name: str, password: str = "") -> dict[str, Any]:
        """
        Returns all active listeners in the room within the active threshold (60s).
        Enforces room password check for protected rooms.
        """
        canonical_name = self.get_canonical_room_name(room_name, password)
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
            if r_k == room_key:
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
        member_token: str = "",
        human_token: str = "",
        password: str = "",
        created_by: str = "",
    ) -> dict[str, Any]:
        """Creates a task in a room and broadcasts the event."""
        canonical_name = self.get_canonical_room_name(room_name, password)
        clean_created_by = created_by.strip()
        clean_ht = (human_token or "").strip()
        is_human = bool(clean_ht and secrets.compare_digest(clean_ht, self.human_token))

        if is_human:
            effective_creator = clean_created_by or "Rui"
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
            created_by=effective_creator,
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
        canonical_name = self.get_canonical_room_name(room_name, password)

        clean_ht = (human_token or "").strip()
        is_human = bool(clean_ht and secrets.compare_digest(clean_ht, self.human_token))

        clean_actor = actor.strip()
        if is_human:
            effective_actor = clean_actor or "Rui"
        else:
            expected_owners = [o for o in (existing.get("assignee"), existing.get("created_by")) if o]
            if expected_owners and clean_actor:
                if clean_actor.lower() in [o.lower() for o in expected_owners]:
                    valid, err = self.storage.verify_member_token(canonical_name, clean_actor, member_token)
                    if not valid:
                        raise PermissionError(f"Acesso negado: {err}")
                else:
                    # Exception: If claiming an unassigned task
                    if not existing.get("assignee") and fields.get("assignee") == clean_actor:
                        valid, err = self.storage.verify_member_token(canonical_name, clean_actor, member_token)
                        if not valid:
                            raise PermissionError(f"Acesso negado: {err}")
                    else:
                        raise PermissionError(
                            f"Acesso negado: Apenas o responsável (@{existing.get('assignee')}) ou o criador (@{existing.get('created_by')}) podem modificar esta tarefa."
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
        canonical_name = self.get_canonical_room_name(room_name, password)

        clean_ht = (human_token or "").strip()
        is_human = bool(clean_ht and secrets.compare_digest(clean_ht, self.human_token))

        if not is_human:
            clean_actor = actor.strip()
            expected_owners = [o for o in (existing.get("assignee"), existing.get("created_by")) if o]
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

    def list_tasks(
        self,
        room_name: str,
        status: str | None = None,
        assignee: str | None = None,
        hide_completed: bool = False,
        password: str = "",
    ) -> list[dict[str, Any]]:
        """Lists tasks for a room, checking room password and supporting hide_completed."""
        canonical_name = self.get_canonical_room_name(room_name, password)
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
        canonical_name = self.get_canonical_room_name(room_name, password)
        tasks = self.storage.reorder_tasks(canonical_name, task_ids)
        await self._broadcast_to_websockets(canonical_name, {
            "type": "tasks_reordered",
            "room": canonical_name,
            "tasks": tasks,
        })
        return tasks
