import asyncio
import hashlib
import secrets
from datetime import datetime
from typing import Any

from aichat.storage import ChatStorage


class ChatHub:
    """Core hub managing room business logic, authentication, pub/sub events, and WebSockets."""

    def __init__(self, storage: ChatStorage | None = None):
        self.storage = storage or ChatStorage()
        # Active WebSocket connections per room: {room_name: set(WebSocket)}
        self._active_websockets: dict[str, set[Any]] = {}
        # Waiting listeners for long polling: {room_name: list[asyncio.Event]}
        self._room_listeners: dict[str, list[asyncio.Event]] = {}
        self._lock = asyncio.Lock()

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

    def list_rooms(self) -> list[dict[str, Any]]:
        """Lists all existing rooms with metadata."""
        return self.storage.list_rooms()

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

        room = self.storage.get_room(room_name)
        if not room:
            raise ValueError(f"Room '{room_name}' does not exist.")
        canonical_name = room["name"]

        if not self.verify_room_access(canonical_name, password):
            raise PermissionError(f"Access denied to room '{canonical_name}': Invalid or missing password.")

        token = self.storage.add_or_update_member(canonical_name, clean_member, role, token=member_token or None, generate_token=True)
        return {
            "status": "joined",
            "room_name": canonical_name,
            "member_name": clean_member,
            "role": role,
            "member_token": token,
        }

    def leave_room(self, room_name: str, member_name: str) -> dict[str, Any]:
        """Removes a member from a room."""
        room = self.storage.get_room(room_name)
        canonical_name = room["name"] if room else room_name
        self.storage.remove_member(canonical_name, member_name)
        return {
            "status": "left",
            "room_name": canonical_name,
            "member_name": member_name,
        }

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
    ) -> dict[str, Any]:
        """
        Sends a message to the room.
        Validates member token for sender authentication.
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

        if not self.verify_room_access(canonical_name, password):
            raise PermissionError(f"Access denied to room '{canonical_name}': Invalid or missing password.")

        # Sender Authentication: verify token if registered
        is_verified = False
        valid, err = self.storage.verify_member_token(canonical_name, clean_sender, member_token)
        if not valid:
            raise PermissionError(err)
        if valid and member_token:
            is_verified = True
        elif role in ("human", "system"):
            is_verified = True

        # Save to database and log files
        msg = self.storage.add_message(
            room_name=canonical_name,
            sender=clean_sender,
            role=role,
            content=clean_content,
            is_verified=is_verified,
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

    def read_messages(
        self,
        room_name: str,
        password: str = "",
        since_id: int = 0,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Reads recent messages from room after verifying password."""
        if not self.verify_room_access(room_name, password):
            raise PermissionError(f"Access denied to room '{room_name}': Invalid or missing password.")

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
        async with self._lock:
            for r in target_rooms:
                r_key = r.strip().lower()
                if r_key not in self._room_listeners:
                    self._room_listeners[r_key] = []
                self._room_listeners[r_key].append(event)

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

                # Event fired! Check all target_rooms for new messages since their respective effective_since_id
                for r in target_rooms:
                    effective_since = room_since_ids[r]
                    new_msgs = self.storage.get_messages(r, since_id=effective_since, limit=50)
                    external_new = [
                        m for m in new_msgs
                        if not clean_agent or m["sender"].strip().lower() != clean_agent
                    ]
                    if external_new:
                        return {
                            "status": "new_messages",
                            "room": r,
                            "count": len(external_new),
                            "messages": external_new,
                            "last_id": max(m["id"] for m in new_msgs),
                        }
                    if new_msgs:
                        room_since_ids[r] = max(m["id"] for m in new_msgs)
        finally:
            async with self._lock:
                for r in target_rooms:
                    r_key = r.strip().lower()
                    if r_key in self._room_listeners and event in self._room_listeners[r_key]:
                        self._room_listeners[r_key].remove(event)

    def check_new_messages(
        self,
        room_name: str = "subscribed",
        agent_name: str = "",
        since_id: int = 0,
        password: str = "",
    ) -> dict[str, Any]:
        """
        Instant non-blocking check for new messages across one room, 'subscribed' rooms, or a list of rooms.
        """
        target_rooms = self._resolve_target_rooms(room_name, agent_name, password)
        clean_agent = agent_name.strip().lower() if agent_name else ""

        all_new: list[dict[str, Any]] = []
        last_id = 0

        for r in target_rooms:
            max_id = self.storage.get_max_message_id(r)
            last_id = max(last_id, max_id)
            if len(target_rooms) == 1 and since_id > 0:
                chk_since = since_id
            else:
                chk_since = since_id if (since_id > 0 and len(target_rooms) == 1) else 0

            if chk_since > 0:
                msgs = self.storage.get_messages(r, since_id=chk_since, limit=50)
                external = [
                    m for m in msgs
                    if not clean_agent or m["sender"].strip().lower() != clean_agent
                ]
                all_new.extend(external)

        if since_id > 0 and len(target_rooms) == 1:
            return {
                "status": "success",
                "room": target_rooms[0],
                "has_new": len(all_new) > 0,
                "count": len(all_new),
                "messages": all_new,
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
                "last_id": last_id,
                "hint": f"Checked {len(target_rooms)} subscribed rooms.",
            }

    def _notify_listeners(self, room_name: str) -> None:
        """Triggers all waiting asyncio events for this room."""
        room_key = room_name.strip().lower()
        listeners = self._room_listeners.get(room_key, [])
        for ev in list(listeners):
            ev.set()

    # WebSocket registration and broadcast
    async def register_websocket(self, room_name: str, websocket: Any) -> None:
        """Registers a connected WebSocket for a room."""
        room_key = room_name.strip().lower()
        async with self._lock:
            if room_key not in self._active_websockets:
                self._active_websockets[room_key] = set()
            self._active_websockets[room_key].add(websocket)

    async def unregister_websocket(self, room_name: str, websocket: Any) -> None:
        """Unregisters a WebSocket upon disconnect."""
        room_key = room_name.strip().lower()
        async with self._lock:
            if room_key in self._active_websockets:
                self._active_websockets[room_key].discard(websocket)

    async def _broadcast_to_websockets(self, room_name: str, payload: dict[str, Any]) -> None:
        """Pushes data to all active WebSockets connected to this room."""
        room_key = room_name.strip().lower()
        sockets = list(self._active_websockets.get(room_key, set()))
        if not sockets:
            return
        dead_sockets = []
        for ws in sockets:
            try:
                await ws.send_json(payload)
            except Exception:
                dead_sockets.append(ws)

        if dead_sockets:
            async with self._lock:
                for ws in dead_sockets:
                    self._active_websockets.get(room_key, set()).discard(ws)
