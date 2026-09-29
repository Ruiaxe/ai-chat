import json
import os
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP, Context

from aichat.hub import ChatHub

mcp = FastMCP("ai-chat-room")
# Allow loopback with or without explicit port in Host header
mcp.settings.transport_security.allowed_hosts.extend(["127.0.0.1", "localhost", "[::1]"])
if os.environ.get("AICHAT_TESTING") == "1":
    mcp.settings.transport_security.allowed_hosts.extend(["testserver", "testserver:*"])

hub = ChatHub()


import contextvars

current_auth_token: contextvars.ContextVar[str | None] = contextvars.ContextVar("current_auth_token", default=None)
current_principal: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar("current_principal", default=None)

STDIO_MODE = False
stdio_agent_token: str | None = None


def init_stdio_mode(token: str | None = None) -> None:
    """Initializes FastMCP for stdio bridge mode with a specific agent token."""
    global STDIO_MODE, stdio_agent_token
    STDIO_MODE = True
    if token:
        stdio_agent_token = token.strip()
        current_auth_token.set(token.strip())


def _authenticate(agent_token: str = "", member_token: str = "", expected_callsign: str = "") -> tuple[dict[str, Any] | None, str | None]:
    """
    Validates caller against v3 storage or v2 registry.
    In v3:
      - Rejects calls with identity arguments (agent_token, member_token, expected_callsign).
      - Authenticates caller strictly from current_principal context (set by ASGI Authorization header middleware)
        or stdio bridge mode.
      - Never reads AICHAT_AGENT_TOKEN directly in HTTP mode.
    """
    is_v3 = hasattr(hub.storage, "is_v3") and hub.storage.is_v3()

    # In v3 mode: reject if caller passed identity parameters in tool arguments
    if is_v3:
        if (agent_token and agent_token.strip()) or (member_token and member_token.strip()) or (expected_callsign and expected_callsign.strip()):
            return None, json.dumps({
                "status": "error",
                "error": "No AI Chat v3, o envio de tokens ou nomes de identidade nos argumentos foi descontinuado. Configure o cabeçalho 'Authorization: Bearer <token>' na ligação MCP."
            }, indent=2)

    # 1. From active principal context (e.g. set by ASGI Authorization header middleware)
    p = current_principal.get()
    if p:
        ident = {
            "callsign": p.get("name"),
            "role": p.get("default_role_key") or ("admin" if p.get("access_role") == "admin" else "user"),
            "is_human": p.get("kind") == "human",
            "status": p.get("status", "active"),
            "principal": p,
        }
        return ident, None

    # 2. From token in context (set by ASGI middleware or stdio bridge) or stdio mode
    if is_v3:
        token = (current_auth_token.get() or "").strip()
        if not token and STDIO_MODE and stdio_agent_token:
            token = stdio_agent_token.strip()

        if not token:
            return None, json.dumps({
                "status": "error",
                "error": "Access denied: Missing Authorization header. Pass 'Authorization: Bearer <token>' in connection headers."
            }, indent=2)

        p, err = hub.storage.v3.authenticate_agent_token(token)
        if not p:
            p = hub.storage.v3.authenticate_human_session(token)
        if p:
            ident = {
                "callsign": p.get("name"),
                "role": p.get("default_role_key") or ("admin" if p.get("access_role") == "admin" else "user"),
                "is_human": p.get("kind") == "human",
                "status": p.get("status", "active"),
                "principal": p,
            }
            return ident, None
        return None, json.dumps({
            "status": "error",
            "error": f"Authentication failed: {err or 'Credenciais inválidas'}"
        }, indent=2)

    # v2 backward compatibility fallback:
    token = (
        agent_token or
        member_token or
        (current_auth_token.get() or "") or
        os.environ.get("AICHAT_AGENT_TOKEN", "") or
        os.environ.get("AI_CHAT_AGENT_TOKEN", "")
    ).strip()

    if not token:
        return None, json.dumps({
            "status": "error",
            "error": "Access denied: Missing agent_token. Pass 'Authorization: Bearer <token>' in connection headers or set AICHAT_AGENT_TOKEN in environment."
        }, indent=2)

    try:
        ident = hub.authenticate_agent(token, expected_callsign=expected_callsign)
        return ident, None
    except Exception as e:
        return None, json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def register_agent(callsign: str) -> str:
    """
    Registers a new agent with a unique callsign in the AI Chat Hub.
    Note: Your access token is generated securely on the server and must be delivered directly by supervisor Rui.
    """
    try:
        res = hub.self_register_agent(callsign)
        return json.dumps({
            "status": "registered_pending_token",
            "callsign": res["callsign"],
            "message": f"Agente '{res['callsign']}' registado no servidor. O teu token pessoal de acesso foi gerado e deve ser solicitado diretamente ao supervisor Rui. Uma vez obtido o token, inclui-o como agent_token em todas as chamadas futuras."
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def get_my_identity(agent_token: str = "", member_token: str = "") -> str:
    """
    Verifies your authentication token and returns your official registered callsign and role.
    """
    ident, err = _authenticate(agent_token, member_token)
    if err:
        return err
    return json.dumps({
        "status": "success",
        "callsign": ident["callsign"],
        "role": ident["role"],
        "is_human": ident.get("is_human", False),
        "agent_status": ident.get("status", "active"),
    }, indent=2)


@mcp.tool()
def create_room(room_name: str, password: str = "", topic: str = "", agent_token: str = "", member_token: str = "") -> str:
    """
    Creates a new collaborative chat room. Requires authorized agent_token.
    Optionally set a password to protect the room from unauthorized access.
    """
    ident, err = _authenticate(agent_token, member_token)
    if err:
        return err
    try:
        if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
            p = ident.get("principal")
            if not hub.storage.v3.authorize(p, "admin"):
                return json.dumps({
                    "status": "error",
                    "error": "Acesso negado: Apenas administradores podem criar salas."
                }, indent=2)
            room = hub.storage.v3.create_room(name=room_name, topic=topic, created_by_id=p["id"] if p else None)
        else:
            room = hub.create_room(name=room_name, password=password, topic=topic)
        return json.dumps({
            "status": "success",
            "message": f"Room '{room_name}' created successfully.",
            "room": room,
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def list_rooms(agent_token: str = "", member_token: str = "") -> str:
    """
    Lists chat rooms with metadata. Returns only rooms the caller is authorized to access.
    """
    ident, err = _authenticate(agent_token, member_token)
    if err:
        return err
    try:
        if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
            p = ident.get("principal")
            rooms = hub.storage.v3.list_rooms_for_principal(p) if p else []
        else:
            rooms = hub.list_rooms()
        return json.dumps({
            "status": "success",
            "count": len(rooms),
            "rooms": rooms,
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def join_room(room_name: str, agent_name: str = "", password: str = "", member_token: str = "", agent_token: str = "") -> str:
    """
    Joins an existing chat room as a participant.
    Requires authorized agent_token (or member_token).
    Callsign is automatically resolved from your authenticated token.
    """
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(agent_token, member_token, expected_callsign=agent_name)
    if err:
        return err
    callsign = ident["callsign"]
    try:
        res = hub.join_room(room_name=room_name, member_name=callsign, role="agent", password=password, member_token=token)
        return json.dumps({
            "status": "success",
            "message": f"Agent '{callsign}' joined room '{room_name}'.",
            "details": res,
            "member_token": res.get("member_token", token),
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def leave_room(room_name: str, agent_name: str = "", member_token: str = "", agent_token: str = "") -> str:
    """Leaves a chat room. Requires authorized agent_token."""
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(agent_token, member_token, expected_callsign=agent_name)
    if err:
        return err
    callsign = ident["callsign"]
    try:
        res = hub.leave_room(room_name=room_name, member_name=callsign, member_token=token)
        return json.dumps({"status": "success", "details": res}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def rotate_member_token(room_name: str, agent_name: str = "", current_token: str = "", password: str = "", member_token: str = "", agent_token: str = "", supervisor_token: str = "") -> str:
    """
    [RESTRICTED] Token management is restricted to supervisor Rui. Agents cannot rotate tokens.
    """
    token = (supervisor_token or agent_token or member_token or current_token).strip()
    try:
        res = hub.rotate_member_token(room_name=room_name, member_name=agent_name, supervisor_token=token)
        return json.dumps({
            "status": "success",
            "message": f"Token for agent '{agent_name}' in room '{room_name}' rotated successfully by supervisor.",
            "details": res,
            "member_token": res.get("member_token", ""),
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def change_room_password(room_name: str, old_password: str = "", new_password: str = "", agent_name: str = "", agent_token: str = "", member_token: str = "", supervisor_token: str = "") -> str:
    """
    [RESTRICTED] Room password management is restricted to supervisor Rui. Agents cannot change room passwords.
    """
    token = (supervisor_token or agent_token or member_token).strip()
    try:
        res = hub.change_room_password(room_name=room_name, old_password=old_password, new_password=new_password, actor_name=agent_name or "Rui", supervisor_token=token)
        return json.dumps({
            "status": "success",
            "message": f"Password for room '{room_name}' changed successfully.",
            "details": res,
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def kick_member(room_name: str, member_to_kick: str, requester_name: str = "", room_password: str = "", agent_token: str = "", member_token: str = "") -> str:
    """
    Ejects a member from a room.
    Requires authorized agent_token and room password (or supervisor authorization).
    """
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(token, expected_callsign=requester_name)
    if err:
        return err
    callsign = ident["callsign"]
    try:
        res = hub.kick_member(room_name=room_name, member_to_kick=member_to_kick, actor_name=callsign, room_password=room_password)
        return json.dumps({
            "status": "success",
            "message": f"Member '{member_to_kick}' ejected from room '{room_name}'.",
            "details": res,
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def get_room_audit_log(room_name: str, password: str = "", limit: int = 50, agent_token: str = "", member_token: str = "") -> str:
    """
    Retrieves the historical audit log of security events. Requires authorized agent_token.
    """
    ident, err = _authenticate(agent_token, member_token)
    if err:
        return err
    try:
        events = hub.get_room_audit_log(room_name=room_name, password=password, limit=limit)
        return json.dumps({
            "status": "success",
            "room_name": room_name,
            "count": len(events),
            "events": events,
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def list_my_rooms(agent_name: str = "", agent_token: str = "", member_token: str = "") -> str:
    """
    Lists all chat rooms that this agent has joined. Requires authorized agent_token.
    """
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(token, expected_callsign=agent_name)
    if err:
        return err
    callsign = ident["callsign"]
    try:
        rooms = hub.list_my_rooms(agent_name=callsign)
        return json.dumps({
            "status": "success",
            "agent_name": callsign,
            "count": len(rooms),
            "rooms": rooms,
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def send_message(
    room_name: str,
    content: str,
    sender_name: str = "",
    password: str = "",
    member_token: str = "",
    agent_token: str = "",
    to: str = "all",
) -> str:
    """
    Sends a message to the specified chat room.
    Requires authorized agent_token (or member_token).
    Sender callsign is automatically bound and verified from your authenticated token.
    - to: Target recipient ('all', '@role_key', '@callsign', or comma-separated list). Default is 'all'.
    """
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(token, expected_callsign=sender_name)
    if err:
        return err
    callsign = ident["callsign"]

    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        p = ident.get("principal")
        room = hub.storage.v3.get_room(room_name)
        if not room:
            return json.dumps({"status": "error", "error": f"Room '{room_name}' does not exist."}, indent=2)
        if room.get("is_archived"):
            return json.dumps({"status": "error", "error": f"Room '{room_name}' is archived."}, indent=2)
        if not hub.storage.v3.authorize(p, "write_room", {"room_id": room["id"]}):
            return json.dumps({"status": "error", "error": f"Access denied: write permission not granted for room '{room_name}' or room is archived."}, indent=2)

        role = "human" if ident.get("is_human") else "agent"
        if role == "agent":
            max_cycles = int(os.environ.get("AICHAT_MAX_AGENT_CYCLES", "10"))
            consecutive = hub.storage.v3.count_consecutive_agent_messages(room["id"])
            if consecutive >= max_cycles:
                recent_msgs = hub.storage.v3.get_messages(room["id"], limit=1)
                already_warned = (
                    recent_msgs and
                    recent_msgs[-1].get("role") == "system" and
                    "Proteção de ciclo ativada" in recent_msgs[-1].get("content", "")
                )
                if not already_warned:
                    warn_text = (
                        f"⚠️ Proteção de ciclo ativada: limite de {max_cycles} mensagens consecutivas entre agentes "
                        f"atingido na sala '{room['name']}' sem intervenção humana. "
                        f"Conversação entre agentes pausada até intervenção do utilizador humano."
                    )
                    humans = hub.storage.v3.get_room_humans(room["id"])
                    human_targets = [f"@{h['name']}" for h in humans] if humans else "all"
                    sys_msg = hub.storage.v3.add_message(
                        room_name_or_id=room["id"],
                        sender="System",
                        role="system",
                        content=warn_text,
                        is_verified=True,
                        to=human_targets,
                    )
                    try:
                        await hub._broadcast_to_websockets(room["name"], {
                            "type": "new_message",
                            "message": sys_msg,
                        })
                        hub._notify_listeners(room["name"], message=sys_msg)
                    except Exception:
                        pass
                return json.dumps({
                    "status": "error",
                    "error": (
                        f"Proteção de ciclo ativada: limite de {max_cycles} mensagens consecutivas entre agentes "
                        f"atingido na sala '{room_name}' sem intervenção humana. "
                        f"Conversação entre agentes pausada até intervenção do utilizador humano."
                    )
                }, indent=2)

        try:
            msg = hub.storage.v3.add_message(
                room_name_or_id=room["id"],
                sender=callsign,
                role=role,
                content=content,
                is_verified=True,
                sender_id=p["id"] if p else None,
                to=to,
            )
            try:
                await hub._broadcast_to_websockets(room["name"], {
                    "type": "new_message",
                    "message": msg,
                })
                hub._notify_listeners(room["name"], message=msg)
            except Exception:
                pass
            return json.dumps({
                "status": "success",
                "message_id": msg["id"],
                "room": room["name"],
                "sender": callsign,
                "to": msg.get("to", ["all"]),
                "recipients": msg.get("recipients", []),
                "is_verified": True,
                "created_at": msg["created_at"],
            }, indent=2)
        except Exception as e:
            return json.dumps({"status": "error", "error": str(e)}, indent=2)

    try:
        msg = await hub.send_message(
            room_name=room_name,
            sender=callsign,
            content=content,
            role="agent" if not ident.get("is_human") else "human",
            password=password,
            member_token=token,
            human_token=hub.human_token if ident.get("is_human") else "",
            to=to,
        )
        return json.dumps({
            "status": "success",
            "message_id": msg["id"],
            "room": room_name,
            "sender": callsign,
            "is_verified": msg.get("is_verified", False),
            "created_at": msg["created_at"],
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def read_messages(
    room_name: str,
    password: str = "",
    since_id: int = 0,
    before_id: int = 0,
    limit: int = 50,
    message_id: int = 0,
    agent_token: str = "",
    member_token: str = "",
) -> str:
    """
    Reads recent messages from a room, or fetches a specific message by message_id.
    Requires authorized agent_token (or member_token).
    - since_id: Only fetch messages newer than this ID.
    - before_id: Only fetch messages older than this ID (for backward pagination).
    - message_id: If specified (> 0), fetches that specific message with its current reactions and status.
    Each message includes 'reactions': [{'emoji': '👍', 'count': 1, 'users': ['Rui']}].
    """
    ident, err = _authenticate(agent_token, member_token)
    if err:
        return err

    room = None
    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        p = ident.get("principal")
        room = hub.storage.v3.get_room(room_name)
        if not room:
            return json.dumps({"status": "error", "error": f"Room '{room_name}' does not exist."}, indent=2)
        if not hub.storage.v3.authorize(p, "read_room", {"room_id": room["id"]}):
            return json.dumps({"status": "error", "error": f"Access denied: read permission not granted for room '{room_name}'."}, indent=2)

    try:
        msgs = hub.read_messages(
            room_name=room_name,
            password=password,
            since_id=since_id,
            before_id=before_id,
            limit=limit,
            message_id=message_id if message_id > 0 else None,
        )
        if hasattr(hub.storage, "is_v3") and hub.storage.is_v3() and msgs and ident.get("principal") and room:
            last_id = msgs[-1]["id"]
            hub.storage.v3.update_read_cursor(ident["principal"]["id"], room["id"], last_id)

        return json.dumps({
            "status": "success",
            "room": room_name,
            "count": len(msgs),
            "messages": msgs,
            "last_id": msgs[-1]["id"] if msgs else since_id,
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def wait_for_new_messages(
    room_name: str = "subscribed",
    agent_name: str = "",
    since_id: int = 0,
    timeout_seconds: int = 600,
    password: str = "",
    agent_token: str = "",
    member_token: str = "",
    ctx: Context = None,
) -> str:
    """
    Long-polling notification tool for agents:
    Requires authorized agent_token (or member_token).
    Suspends and waits until another agent or the human sends a new message OR reacts with an emoji (e.g. 👍).
    - room_name: Specific room name, 'subscribed' (or empty) to watch all joined rooms, or comma-separated list.
    - agent_name: Your registered callsign (resolved automatically from token). Your own messages and reactions are ignored.
    - since_id: ID of the last message you processed. If 0 (default), waits for new messages arriving from now on.
    - timeout_seconds: Maximum seconds to wait before timing out (1 to 3600, default 600 = 10 minutes).
      Sends regular MCP progress heartbeats (every 45s) to prevent client timeouts (e.g. Claude Code 300s limit).
    - password: Room password if protected.
    Returns immediately if new messages/reactions already exist or as soon as one arrives.
    Returns status 'new_messages' on new messages, 'new_reactions' on emoji reactions, or 'timeout'.
    """
    ident, err = _authenticate(agent_token, member_token, expected_callsign=agent_name)
    if err:
        return err
    effective_agent = ident["callsign"]

    try:
        # Cap timeout between 1 and 3600 seconds (1 hour)
        safe_timeout = max(1, min(timeout_seconds, 3600))

        async def progress_cb(elapsed: float, total: float, msg: str):
            if ctx:
                try:
                    await ctx.report_progress(progress=elapsed, total=total, message=msg)
                except Exception:
                    pass

        result = await hub.wait_for_new_messages(
            room_name=room_name,
            agent_name=effective_agent,
            since_id=since_id,
            timeout_seconds=float(safe_timeout),
            password=password,
            on_progress=progress_cb,
        )
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def check_new_messages(
    room_name: str = "subscribed",
    agent_name: str = "",
    since_id: int = 0,
    password: str = "",
    agent_token: str = "",
    member_token: str = "",
) -> str:
    """
    Fast non-blocking check: immediately returns whether there are new messages.
    Requires authorized agent_token (or member_token).
    Does not suspend or wait. Ideal for fast polling or checking status before acting.
    - room_name: Specific room name, 'subscribed' (or empty) to check all joined rooms, or comma-separated list.
    - since_id: Only return messages with ID > since_id.
    - agent_name: Filter out messages sent by this agent (bound from token).
    """
    ident, err = _authenticate(agent_token, member_token, expected_callsign=agent_name)
    if err:
        return err
    effective_agent = ident["callsign"]

    try:
        result = hub.check_new_messages(
            room_name=room_name,
            agent_name=effective_agent,
            since_id=since_id,
            password=password,
        )
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def wake_up_call(
    room_name: str = "all",
    since_seq: int | None = None,
    timeout_seconds: int = 60,
    watcher_name: str = "Sentinel",
    ctx: Context = None,
) -> str:
    """
    Lightweight wake-up notification tool for Sentinel and background scripts.
    DOES NOT require agent_token or room password.
    Returns a lightweight ping when ANY activity occurs in the subscribed channel(s):
    - messages (new messages)
    - polls (creation, votes, closes)
    - reactions (emoji reactions)
    - tasks (creation, updates, deletions, reordering)
    - decisions (human decisions resolved)
    - room lifecycle (archived, unarchived)

    Parameters:
    - room_name: Channel name (e.g. 'klarity'), comma-separated channels ('general,klarity'), or 'all' to monitor all rooms.
    - since_seq: Previous activity sequence number. If provided, returns immediately if activity occurred since then.
    - timeout_seconds: Maximum seconds to wait (1 to 3600, default 60). Sends progress heartbeats to keep connection active.
    - watcher_name: Optional name for presence tracking (default 'Sentinel').

    Returns:
    JSON string with {"status": "activity", "room": ..., "event_type": ..., "seq": ..., "timestamp": ...} on activity,
    or {"status": "timeout", "room": ..., "seq": ...} when no activity occurred.
    """
    try:
        safe_timeout = max(1, min(timeout_seconds, 3600))

        async def progress_cb(elapsed: float, total: float, msg: str):
            if ctx:
                try:
                    await ctx.report_progress(progress=elapsed, total=total, message=msg)
                except Exception:
                    pass

        result = await hub.wait_for_activity(
            room_name=room_name,
            since_seq=since_seq,
            timeout_seconds=float(safe_timeout),
            watcher_name=watcher_name or "Sentinel",
            on_progress=progress_cb,
        )
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def get_room_transcript(room_name: str, password: str = "", agent_token: str = "", member_token: str = "") -> str:
    """
    Returns the complete human-readable transcript file of the room.
    Requires authorized agent_token (or member_token).
    Useful for reviewing the entire history of an agent team session.
    """
    ident, err = _authenticate(agent_token, member_token)
    if err:
        return err
    try:
        if not hub.verify_room_access(room_name, password):
            return json.dumps({"status": "error", "error": "Access denied: incorrect password."})
        transcript = hub.storage.read_text_transcript(room_name)
        return transcript
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)})


@mcp.tool()
async def react_to_message(
    message_id: int,
    room_name: str,
    emoji: str,
    sender_name: str = "",
    agent_name: str = "",
    member_token: str = "",
    agent_token: str = "",
) -> str:
    """
    Adds or removes an emoji reaction on a message (e.g. '👍', '🚀', '❤️', '👀', '🎉', '👎').
    Requires authorized agent_token (or member_token).
    Calling again with the same emoji toggles (removes) it.
    """
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(token, expected_callsign=sender_name or agent_name)
    if err:
        return err
    callsign = ident["callsign"]

    try:
        res = await hub.toggle_reaction(
            message_id=message_id,
            room_name=room_name,
            sender=callsign,
            emoji=emoji,
        )
        return json.dumps({"status": "success", "data": res}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def call_human(
    room_name: str,
    question: str,
    sender_name: str = "",
    agent_name: str = "",
    options: list[str] = [],
    member_token: str = "",
    agent_token: str = "",
    password: str = "",
    to: str = "",
    target_human: str = "",
) -> str:
    """
    Calls the human user for an important decision, impasse resolution, or architectural choice.
    Requires authorized agent_token (or member_token).
    Renders high-visibility alert cards, desktop notifications, and quick-action choice buttons in the human's Web UI.
    - options: Optional list of proposed choices (e.g. ['Option A: Vector DB', 'Option B: SQLite']).
    - password: Room password if calling in a password-protected room.
    - to: Optional target recipient (e.g. 'humans' or '@Alice').
    - target_human: Optional specific human username or ID to target.
    """
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(token, expected_callsign=sender_name or agent_name)
    if err:
        return err
    callsign = ident["callsign"]

    try:
        msg = await hub.call_human(
            room_name=room_name,
            sender=callsign,
            question=question,
            options=options,
            member_token=token,
            password=password,
            to=to or None,
            target_human=target_human or None,
        )
        return json.dumps({
            "status": "success",
            "message_id": msg["id"],
            "room": room_name,
            "sender": callsign,
            "question": question,
            "options": options,
            "created_at": msg["created_at"],
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def create_poll(
    room_name: str,
    question: str,
    options: list[str],
    creator_name: str = "",
    agent_name: str = "",
    member_token: str = "",
    agent_token: str = "",
    password: str = "",
) -> str:
    """
    Creates a voting poll in the chat room for team decisions.
    Requires authorized agent_token (or member_token).
    - options: List of at least 2 choices to vote on.
    - password: Room password if creating a poll in a password-protected room.
    """
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(token, expected_callsign=creator_name or agent_name)
    if err:
        return err
    callsign = ident["callsign"]

    try:
        poll = await hub.create_poll(
            room_name=room_name,
            creator=callsign,
            question=question,
            options=options,
            member_token=token,
            password=password,
        )
        return json.dumps({"status": "success", "poll": poll}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def cast_vote(
    poll_id: int,
    option_index: int,
    voter_name: str = "",
    agent_name: str = "",
    member_token: str = "",
    agent_token: str = "",
) -> str:
    """
    Casts a vote on an active poll.
    Requires authorized agent_token (or member_token).
    - option_index: 0-indexed choice position.
    """
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(token, expected_callsign=voter_name or agent_name)
    if err:
        return err
    callsign = ident["callsign"]

    try:
        poll = await hub.cast_vote(
            poll_id=poll_id,
            voter=callsign,
            option_index=option_index,
        )
        return json.dumps({"status": "success", "poll": poll}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def get_poll(poll_id: int, agent_token: str = "", member_token: str = "") -> str:
    """
    Gets live poll status, vote counts per option, and percentages.
    Requires authorized agent_token (or member_token).
    """
    ident, err = _authenticate(agent_token, member_token)
    if err:
        return err
    try:
        poll = hub.get_poll(poll_id)
        if not poll:
            return json.dumps({"status": "error", "error": f"Poll #{poll_id} not found."})
        return json.dumps({"status": "success", "poll": poll}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def close_poll(
    poll_id: int,
    closer_name: str = "",
    agent_name: str = "",
    password: str = "",
    member_token: str = "",
    agent_token: str = "",
) -> str:
    """
    Closes an active poll (can only be closed by its creator or the human user).
    Requires authorized agent_token (or member_token).
    - password: Password of the room if it is protected.
    """
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(token, expected_callsign=closer_name or agent_name)
    if err:
        return err
    callsign = ident["callsign"]

    try:
        poll = await hub.close_poll(
            poll_id=poll_id,
            closer=callsign,
            password=password,
            is_human=ident.get("is_human", False),
            member_token=token,
        )
        return json.dumps({"status": "success", "poll": poll}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def archive_room(room_name: str, requester_name: str = "", requester_role: str = "agent") -> str:
    """
    Archives a chat room to read-only mode.
    WARNING: THIS TOOL IS STRICTLY RESTRICTED TO THE HUMAN USER VIA WEB UI. AGENTS CANNOT ARCHIVE ROOMS.
    """
    return json.dumps({
        "status": "error",
        "error": "Apenas o utilizador humano através da Web UI tem permissão para arquivar salas."
    }, indent=2)


# -----------------------------------------------------------------
# Task Planner & Presence MCP Tools (v2.5)
# -----------------------------------------------------------------
@mcp.tool()
async def create_task(
    room_name: str,
    title: str,
    description: str = "",
    assignee: str = "",
    waiting_for_agent: str = "",
    priority: str = "medium",
    status: str = "planned",
    uses_gpu: bool = False,
    gpu_est_min: int = 0,
    start_at: str = "",
    due_at: str = "",
    resource: str = "",
    message_id: int = 0,
    password: str = "",
    member_token: str = "",
    agent_token: str = "",
    creator_name: str = "",
    agent_name: str = "",
) -> str:
    """
    Creates a new task in the room's task planner.
    Requires authorized agent_token (or member_token).
    - room_name: Target chat room
    - title: Brief summary of the task
    - description: Detailed notes / acceptance criteria
    - assignee: Name of assigned agent or human
    - waiting_for_agent: If waiting for another agent, their name
    - priority: 'urgent', 'high', 'medium', or 'low' (default: 'medium')
    - status: 'planned', 'in_progress', 'waiting_human', 'waiting_agent', 'done', 'cancelled'
    - uses_gpu: True if task requires local GPU resources
    - gpu_est_min: Estimated GPU duration in minutes
    - start_at: Optional planned ISO start time (e.g. '2026-09-27T14:00:00')
    - due_at: Optional deadline ISO timestamp
    - resource: Optional hardware resource (e.g. 'RTX_3080', 'RTX_5070TI')
    - message_id: Optional ID of chat message requesting this task or decision
    - agent_token: Your registered token for authentication
    """
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(token, expected_callsign=creator_name or agent_name)
    if err:
        return err
    callsign = ident["callsign"]

    try:
        task = await hub.create_task(
            room_name=room_name,
            title=title,
            description=description,
            assignee=assignee,
            waiting_for_agent=waiting_for_agent,
            priority=priority,
            status=status,
            uses_gpu=uses_gpu,
            gpu_est_min=gpu_est_min,
            start_at=start_at,
            due_at=due_at,
            resource=resource,
            message_id=message_id if message_id > 0 else None,
            member_token=token,
            password=password,
            created_by=callsign,
        )
        return json.dumps({
            "status": "success",
            "message": f"Task #{task['id']} created.",
            "task": task,
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def update_task(
    task_id: int,
    status: str = "",
    assignee: str = "",
    waiting_for_agent: str = "",
    priority: str = "",
    title: str = "",
    description: str = "",
    order_index: int = 0,
    message_id: int = 0,
    uses_gpu: bool | None = None,
    gpu_est_min: int | None = None,
    start_at: str = "",
    due_at: str = "",
    resource: str = "",
    member_token: str = "",
    agent_token: str = "",
    actor_name: str = "",
    agent_name: str = "",
    password: str = "",
) -> str:
    """
    Updates an existing task in the room task planner.
    Requires authorized agent_token (or member_token).
    """
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(token, expected_callsign=actor_name or agent_name)
    if err:
        return err
    callsign = ident["callsign"]

    try:
        fields: dict[str, Any] = {}
        if status:
            fields["status"] = status
        if assignee:
            fields["assignee"] = assignee
        if waiting_for_agent:
            fields["waiting_for_agent"] = waiting_for_agent
        if priority:
            fields["priority"] = priority
        if title:
            fields["title"] = title
        if description:
            fields["description"] = description
        if order_index > 0:
            fields["order_index"] = order_index
        if message_id > 0:
            fields["message_id"] = message_id
        if uses_gpu is not None:
            fields["uses_gpu"] = uses_gpu
        if gpu_est_min is not None:
            fields["gpu_est_min"] = gpu_est_min
        if start_at:
            fields["start_at"] = start_at
        if due_at:
            fields["due_at"] = due_at
        if resource:
            fields["resource"] = resource

        task = await hub.update_task(
            task_id=task_id,
            member_token=token,
            password=password,
            actor=callsign,
            **fields,
        )
        return json.dumps({
            "status": "success",
            "message": f"Task #{task_id} updated.",
            "task": task,
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def list_tasks(
    room_name: str,
    status: str = "",
    assignee: str = "",
    hide_completed: bool = False,
    password: str = "",
    agent_token: str = "",
    member_token: str = "",
) -> str:
    """
    Lists tasks for a room from the task planner.
    Requires authorized agent_token (or member_token).
    - status: Optional filter ('planned', 'in_progress', 'waiting_human', 'waiting_agent', 'done', 'cancelled')
    - assignee: Optional filter by responsible agent/human
    - hide_completed: If True, excludes 'done' and 'cancelled' tasks
    - password: Password if room is protected
    """
    ident, err = _authenticate(agent_token, member_token)
    if err:
        return err
    try:
        tasks = hub.list_tasks(
            room_name=room_name,
            status=status or None,
            assignee=assignee or None,
            hide_completed=hide_completed,
            password=password,
        )
        return json.dumps({
            "status": "success",
            "room": room_name,
            "count": len(tasks),
            "tasks": tasks,
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def reorder_tasks(
    room_name: str,
    task_ids: list[int],
    agent_name: str = "",
    member_token: str = "",
    agent_token: str = "",
    password: str = "",
) -> str:
    """
    Sets a new execution order for tasks in a room by providing the task IDs in preferred sequence.
    Requires authorized agent_token (or member_token).
    """
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(token, expected_callsign=agent_name)
    if err:
        return err
    try:
        tasks = await hub.reorder_tasks(
            room_name=room_name,
            task_ids=task_ids,
            member_token=token,
            password=password,
        )
        return json.dumps({
            "status": "success",
            "message": f"Reordered {len(task_ids)} tasks in #{room_name}.",
            "tasks": tasks,
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def who_is_listening(room_name: str, password: str = "", agent_token: str = "", member_token: str = "") -> str:
    """
    Checks who is actively listening in the chat room right now.
    Requires authorized agent_token (or member_token).
    Returns listeners across Web UI, long-polling MCP listeners, and Sentinel HTTP pollers (within 60s).
    """
    ident, err = _authenticate(agent_token, member_token)
    if err:
        return err
    try:
        res = hub.who_is_listening(room_name=room_name, password=password)
        return json.dumps(res, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


# -----------------------------------------------------------------
# Calendar & Resource Booking Tools (v2.8)
# -----------------------------------------------------------------
@mcp.tool()
def list_calendar_events(
    room_name: str = "all",
    start_from: str = "",
    start_to: str = "",
    resource: str = "",
    status: str = "",
    include_completed: bool = True,
    hide_completed: bool = False,
    password: str = "",
    agent_token: str = "",
    member_token: str = "",
) -> str:
    """
    Lists calendar events for a specific room or across all rooms ('all').
    Requires authorized agent_token (or member_token).
    - room_name: Room name or 'all' to see all rooms
    - start_from: ISO datetime string filter (e.g. '2026-09-27T00:00:00')
    - start_to: ISO datetime string filter
    - resource: Filter by reserved hardware/resource (e.g. 'RTX_3080', 'RTX_5070TI')
    - status: 'scheduled', 'in_progress', 'completed', 'cancelled'
    - include_completed: If True, includes past completed/cancelled events
    - hide_completed: If True, excludes completed and cancelled events
    - password: Password if room is protected
    """
    ident, err = _authenticate(agent_token, member_token)
    if err:
        return err
    token = (agent_token or member_token).strip()
    if hide_completed:
        include_completed = False
    try:
        events = hub.list_calendar_events(
            room_name=room_name,
            start_from=start_from,
            start_to=start_to,
            resource=resource,
            status=status,
            include_completed=include_completed,
            password=password,
            requester_token=token,
        )
        return json.dumps({
            "status": "success",
            "room": room_name,
            "count": len(events),
            "events": events,
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def create_calendar_event(
    room_name: str,
    title: str,
    start_at: str,
    end_at: str = "",
    resource: str = "",
    description: str = "",
    event_type: str = "event",
    task_id: int = 0,
    target_agent: str = "",
    wake_on_start: bool = True,
    wake_on_end: bool = False,
    password: str = "",
    member_token: str = "",
    agent_token: str = "",
    creator_name: str = "",
    agent_name: str = "",
) -> str:
    """
    Schedules a new calendar event or GPU reservation in a room.
    The Hub calendar dispatcher automatically fires reactive wake-up events on start_at / end_at.
    If 'resource' is specified, reservations overlapping in time with existing active reservations
    for the same resource are categorically rejected with an error.
    Requires authorized agent_token (or member_token).
    - room_name: Target chat room
    - title: Event title or job summary
    - start_at: ISO 8601 start timestamp (e.g. '2026-09-27T15:00:00')
    - end_at: ISO 8601 end timestamp (optional; defaults to start_at + 1h if resource is set)
    - resource: Free text hardware resource (e.g. 'RTX_3080', 'RTX_5070TI', 'CPU_Runner')
    - description: Optional details or acceptance notes
    - event_type: 'event', 'gpu_lock', 'sync', 'maintenance'
    - task_id: Optional ID of linked Task Planner task
    - target_agent: Optional callsign of agent to ping on wake-up
    - wake_on_start: If True, Hub dispatches a wake-up activity notification to the room at start_at
    - wake_on_end: If True, Hub dispatches a wake-up activity notification to the room at end_at
    """
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(token, expected_callsign=creator_name or agent_name)
    if err:
        return err
    callsign = ident["callsign"]

    try:
        ev = await hub.create_calendar_event(
            room_name=room_name,
            title=title,
            start_at=start_at,
            end_at=end_at,
            description=description,
            event_type=event_type,
            task_id=task_id if task_id > 0 else None,
            resource=resource,
            target_agent=target_agent,
            wake_on_start=wake_on_start,
            wake_on_end=wake_on_end,
            member_token=token,
            password=password,
            created_by=callsign,
        )
        return json.dumps({
            "status": "success",
            "message": f"Calendar event #{ev['id']} scheduled.",
            "event": ev,
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def update_calendar_event(
    event_id: int,
    title: str = "",
    description: str = "",
    start_at: str = "",
    end_at: str = "",
    resource: str = "",
    event_type: str = "",
    target_agent: str = "",
    status: str = "",
    wake_on_start: bool | None = None,
    wake_on_end: bool | None = None,
    password: str = "",
    member_token: str = "",
    agent_token: str = "",
    actor_name: str = "",
    agent_name: str = "",
) -> str:
    """
    Updates an existing calendar event or resource reservation.
    Requires authorized agent_token (or member_token).
    """
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(token, expected_callsign=actor_name or agent_name)
    if err:
        return err
    try:
        fields: dict[str, Any] = {}
        if title:
            fields["title"] = title
        if description:
            fields["description"] = description
        if start_at:
            fields["start_at"] = start_at
        if end_at:
            fields["end_at"] = end_at
        if resource:
            fields["resource"] = resource
        if event_type:
            fields["event_type"] = event_type
        if target_agent:
            fields["target_agent"] = target_agent
        if status:
            fields["status"] = status
        if wake_on_start is not None:
            fields["wake_on_start"] = wake_on_start
        if wake_on_end is not None:
            fields["wake_on_end"] = wake_on_end

        ev = await hub.update_calendar_event(
            event_id=event_id,
            member_token=token,
            password=password,
            **fields,
        )
        return json.dumps({
            "status": "success",
            "message": f"Calendar event #{event_id} updated.",
            "event": ev,
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def delete_calendar_event(
    event_id: int,
    password: str = "",
    member_token: str = "",
    agent_token: str = "",
) -> str:
    """
    Cancels/deletes a calendar event and releases any associated resource lock.
    Requires authorized agent_token (or member_token).
    """
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(token)
    if err:
        return err
    try:
        res = await hub.delete_calendar_event(
            event_id=event_id,
            member_token=token,
            password=password,
        )
        return json.dumps(res, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def check_resource_availability(
    resource: str,
    start_at: str,
    end_at: str = "",
    agent_token: str = "",
    member_token: str = "",
) -> str:
    """
    Checks if a hardware or cluster resource (e.g. 'RTX_3080', 'RTX_5070TI') is available
    during a specified time interval, or if it has conflicting reservations.
    Requires authorized agent_token (or member_token).
    - resource: Resource name (case-insensitive)
    - start_at: ISO 8601 start timestamp
    - end_at: ISO 8601 end timestamp (optional, defaults to +1h)
    """
    ident, err = _authenticate(agent_token, member_token)
    if err:
        return err
    try:
        conflicts = hub.storage.check_resource_conflicts(
            resource=resource,
            start_at=start_at,
            end_at=end_at,
        )
        available = len(conflicts) == 0
        return json.dumps({
            "status": "success",
            "resource": resource,
            "available": available,
            "conflicts_count": len(conflicts),
            "conflicts": conflicts,
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.resource("chat://rooms")
def resource_rooms() -> str:
    """Resource listing all chat rooms."""
    rooms = hub.list_rooms()
    return json.dumps(rooms, indent=2)


@mcp.resource("chat://rooms/{room_name}")
def resource_room_messages(room_name: str) -> str:
    """Resource showing recent messages from a public room."""
    room = hub.storage.get_room(room_name)
    if not room:
        return f"Room '{room_name}' not found."
    if room["is_protected"]:
        return f"Room '{room_name}' is password protected. Use the read_messages tool with the password."
    msgs = hub.storage.get_messages(room_name, limit=50)
    return json.dumps(msgs, indent=2)


@mcp.prompt()
def collaborative_agent(room_name: str, my_agent_name: str, task_goal: str) -> str:
    """Prompt template for configuring an agent to collaborate in a chat room."""
    return f"""You are collaborating with other AI agents and human teammates in the chat room '{room_name}'.
Your name in this room is: '{my_agent_name}'.
The overall team objective is: {task_goal}

Collaboration Protocol:
1. Join the room using `join_room(room_name="{room_name}", agent_name="{my_agent_name}")`.
   Keep the returned `member_token` to authenticate your messages.
2. Check existing messages using `read_messages(room_name="{room_name}")` to catch up.
3. When you have an update, question, or handoff, call `send_message(room_name="{room_name}", sender_name="{my_agent_name}", content=..., member_token=...)`.
4. After sending your message, call `wait_for_new_messages(room_name="{room_name}", agent_name="{my_agent_name}", since_id=..., timeout_seconds=600)` to wait for other agents or the human to respond.
   Or use `room_name="subscribed"` to listen to all channels you have joined simultaneously.
5. Be concise, constructive, and do not repeat messages already stated.
"""


def prune_mcp_tool_parameters() -> None:
    """
    Removes agent_token, member_token, sender_name, and agent_name from all published MCP tool schemas.
    Authentication is handled at connection time (Authorization: Bearer header in HTTP/SSE or AICHAT_AGENT_TOKEN in stdio).
    """
    for name in list(mcp._tool_manager._tools.keys()):
        t = mcp._tool_manager.get_tool(name)
        if t and t.parameters and "properties" in t.parameters:
            for p in ["agent_token", "member_token", "sender_name", "agent_name"]:
                t.parameters["properties"].pop(p, None)
                if "required" in t.parameters and p in t.parameters["required"]:
                    t.parameters["required"].remove(p)


prune_mcp_tool_parameters()

