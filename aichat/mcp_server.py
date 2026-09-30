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
    """Initializes FastMCP for stdio bridge mode with a specific agent credential."""
    global STDIO_MODE, stdio_agent_token
    STDIO_MODE = True
    if token:
        stdio_agent_token = token.strip()
        current_auth_token.set(token.strip())


def _authenticate(**kwargs: Any) -> tuple[dict[str, Any] | None, str | None]:
    """
    Validates caller against v3 storage or v2 registry.
    In v3:
      - Rejects calls with identity arguments in tool calls.
      - Authenticates caller strictly from current_principal context or stdio bridge mode.
      - Automatically records agent activity timestamp on successful authentication.
    """
    is_v3 = hasattr(hub.storage, "is_v3") and hub.storage.is_v3()

    agent_token = kwargs.get("agent_token", "")
    member_token = kwargs.get("member_token", "")
    expected_callsign = kwargs.get("expected_callsign") or kwargs.get("sender_name") or kwargs.get("agent_name") or ""

    # In v3 mode: reject if caller passed identity parameters in tool arguments
    if is_v3:
        if (agent_token and str(agent_token).strip()) or (member_token and str(member_token).strip()) or (expected_callsign and str(expected_callsign).strip()):
            return None, json.dumps({
                "status": "error",
                "error": "No AI Chat v3, o envio de tokens ou nomes de identidade nos argumentos foi descontinuado. Configure o cabeçalho 'Authorization: Bearer <token>' na ligação MCP."
            }, indent=2)

    # 1. From active principal context
    p = current_principal.get()
    if p:
        tok = (current_auth_token.get() or "").strip()
        ident = {
            "callsign": p.get("name"),
            "role": p.get("default_role_key") or ("admin" if p.get("access_role") == "admin" else "user"),
            "is_human": p.get("kind") == "human",
            "status": p.get("status", "active"),
            "principal": p,
            "token": tok,
        }
        if is_v3 and not ident.get("is_human"):
            try:
                hub.storage.v3.record_agent_activity(ident["callsign"])
            except Exception:
                pass
        return ident, None

    # 2. From context or stdio bridge
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
                "token": token,
            }
            if not ident.get("is_human"):
                try:
                    hub.storage.v3.record_agent_activity(ident["callsign"])
                except Exception:
                    pass
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
    )
    if isinstance(token, str):
        token = token.strip()
    else:
        token = ""

    if not token:
        return None, json.dumps({
            "status": "error",
            "error": "Access denied: Missing agent_token. Pass 'Authorization: Bearer <token>' in connection headers or set AICHAT_AGENT_TOKEN in environment."
        }, indent=2)

    try:
        ident = hub.authenticate_agent(token, expected_callsign=str(expected_callsign) if expected_callsign else "")
        ident["token"] = token
        return ident, None
    except Exception as e:
        return None, json.dumps({"status": "error", "error": str(e)}, indent=2)


def _handle_deprecated(tool_name: str, message: str, room_name: str = "", actor: str = "unknown") -> str | None:
    """If running in v3, records call in audit log and returns standard deprecation error."""
    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        try:
            p = current_principal.get()
            actor_id = p.get("id") if p else None
            actor_name = p.get("name") if p else actor
            room = hub.storage.v3._resolve_room(room_name) if room_name else None
            rid = room["id"] if room else None
            hub.storage.v3.log_audit(
                actor_id=actor_id,
                actor_name=actor_name,
                action="mcp_deprecated_call",
                target_type="mcp_tool",
                room_id=rid,
                status="deprecated_call",
                details=f"Tool '{tool_name}' called: {message}",
            )
        except Exception:
            pass
        return json.dumps({
            "status": "error",
            "error": message,
        }, indent=2)
    return None


# -----------------------------------------------------------------
# Active Agent Core Tools
# -----------------------------------------------------------------
@mcp.tool()
def register_agent(callsign: str, **kwargs: Any) -> str:
    """
    Submits a registration request for an agent with a unique callsign.
    The request enters a pending state and must be approved by an administrator in the admin console.
    """
    try:
        res = hub.self_register_agent(callsign)
        if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
            return json.dumps({
                "status": "pending",
                "callsign": res["callsign"],
                "message": res.get("message", "Pedido de registo submetido. Aguarda aprovação de um administrador na consola (/admin)."),
            }, indent=2)
        return json.dumps({
            "status": "registered_pending_token",
            "callsign": res["callsign"],
            "message": f"Agente '{res['callsign']}' registado no servidor. O teu token pessoal de acesso foi gerado e deve ser solicitado diretamente ao supervisor Rui. Uma vez obtido o token, inclui-o como agent_token em todas as chamadas futuras.",
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def get_my_identity(**kwargs: Any) -> str:
    """
    Returns your official registered callsign, role, and status.
    """
    ident, err = _authenticate(**kwargs)
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
def list_rooms(**kwargs: Any) -> str:
    """
    Lists chat rooms with metadata. Returns rooms the caller is authorized to access.
    """
    ident, err = _authenticate(**kwargs)
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
def list_my_rooms(agent_name: str = "", **kwargs: Any) -> str:
    """
    Lists all chat rooms that this caller has access to or has joined.
    """
    ident, err = _authenticate(expected_callsign=agent_name, **kwargs)
    if err:
        return err
    callsign = ident["callsign"]
    try:
        if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
            p = ident.get("principal")
            rooms = hub.storage.v3.list_rooms_for_principal(p) if p else []
        else:
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
    to: str = "all",
    **kwargs: Any,
) -> str:
    """
    Sends a message to the specified chat room.
    Sender callsign is automatically bound from connection credentials.
    - to: Target recipient ('all', '@role_key', '@callsign', or comma-separated list). Default is 'all'.
    """
    ident, err = _authenticate(**kwargs)
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

            liv = hub.storage.v3.get_agent_liveliness(callsign)
            was_stalled = liv.get("state") == "stalled" or liv.get("stalled_alert_count", 0) > 0
            hub.storage.v3.record_agent_activity(callsign)
            if was_stalled:
                hub.storage.v3.clear_stalled_alert(callsign)
                humans = hub.storage.v3.get_room_humans(room["id"])
                if humans:
                    rec_targets = [f"@{h['name']}" for h in humans]
                    rec_msg = hub.storage.v3.add_message(
                        room_name_or_id=room["id"],
                        sender="System",
                        role="system",
                        content=f"✅ @{callsign} voltou a escutar.",
                        is_verified=True,
                        to=rec_targets,
                    )
                    try:
                        await hub._broadcast_to_websockets(room["name"], {
                            "type": "new_message",
                            "message": rec_msg,
                        })
                        hub._notify_listeners(room["name"], message=rec_msg)
                    except Exception:
                        pass

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
            password=kwargs.get("password", ""),
            member_token=ident.get("token", ""),
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
    since_id: int = 0,
    before_id: int = 0,
    limit: int = 50,
    message_id: int = 0,
    **kwargs: Any,
) -> str:
    """
    Reads recent messages from a room, or fetches a specific message by message_id.
    - since_id: Only fetch messages newer than this ID.
    - before_id: Only fetch messages older than this ID (for backward pagination).
    - message_id: If specified (> 0), fetches that specific message with its current reactions and status.
    Each message includes 'reactions': [{'emoji': '👍', 'count': 1, 'users': ['human']}].
    """
    ident, err = _authenticate(**kwargs)
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
            password=kwargs.get("password", ""),
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
async def wait_for_work(
    timeout_seconds: int = 600,
    ack: int = 0,
    format: str = "json",
    ctx: Context = None,
    **kwargs: Any,
) -> str:
    """
    Universal wait-for-work mechanism for agents.
    Suspends and waits until new directed messages or room work arrive for this agent.
    - timeout_seconds: Maximum seconds to wait (0 = immediate non-blocking check, default 600).
      Regular progress heartbeats (every 45s) are emitted to prevent harness timeouts.
    - ack: ID of the last message successfully processed by the agent. Confirms delivery.
    - format: 'json' (default, complete payload) or 'text' (compact summary).
    """
    ident, err = _authenticate(**kwargs)
    if err:
        return err
    effective_agent = ident["callsign"]

    try:
        safe_timeout = max(0, min(timeout_seconds, 3600))

        async def progress_cb(elapsed: float, total: float, msg: str):
            if ctx:
                try:
                    await ctx.report_progress(progress=elapsed, total=total, message=msg)
                except Exception:
                    pass

        res = await hub.wait_for_work(
            principal_or_agent=ident.get("principal") or effective_agent,
            timeout_seconds=float(safe_timeout),
            ack=ack,
            format=format,
            room=kwargs.get("room_name") or kwargs.get("room") or "subscribed",
            on_progress=progress_cb,
        )
        if isinstance(res, str):
            return res
        return json.dumps(res, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def wait_for_new_messages(
    room_name: str = "subscribed",
    since_id: int = 0,
    timeout_seconds: int = 600,
    ctx: Context = None,
    **kwargs: Any,
) -> str:
    """
    Waits for new messages in joined rooms (alias for wait_for_work).
    - room_name: Specific room name or 'subscribed' to watch all joined rooms.
    - since_id: Message ID to ack/check since.
    - timeout_seconds: Maximum seconds to wait before returning.
    """
    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        return await wait_for_work(
            timeout_seconds=timeout_seconds,
            ack=since_id,
            format="json",
            ctx=ctx,
            room_name=room_name,
            **kwargs,
        )

    # Legacy v2 fallback:
    ident, err = _authenticate(**kwargs)
    if err:
        return err
    effective_agent = ident["callsign"]

    try:
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
            password=kwargs.get("password", ""),
            on_progress=progress_cb,
        )
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def team_status(room_name: str, **kwargs: Any) -> str:
    """
    Returns the liveliness status of each member in the specified room.
    Shows state (🟢 a escutar, 🔵 a trabalhar, 💤 sem trabalho, 🔴 parado, ⚫ offline), role,
    and unread directed messages count.
    """
    ident, err = _authenticate(**kwargs)
    if err:
        return err

    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        p = ident.get("principal")
        room = hub.storage.v3.get_room(room_name)
        if not room:
            return json.dumps({"status": "error", "error": f"Room '{room_name}' does not exist."}, indent=2)
        if not hub.storage.v3.authorize(p, "read_room", {"room_id": room["id"]}):
            return json.dumps({"status": "error", "error": f"Access denied: read permission not granted for room '{room_name}'."}, indent=2)

    try:
        res = hub.get_room_team_status(room_name)
        if isinstance(res, list):
            return json.dumps({"status": "success", "room": room_name, "members": res}, indent=2)
        return json.dumps({"status": "success", **res}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def react_to_message(
    message_id: int,
    room_name: str,
    emoji: str,
    **kwargs: Any,
) -> str:
    """
    Adds or removes an emoji reaction on a message (e.g. '👍', '🚀', '❤️', '👀', '🎉', '👎').
    Calling again with the same emoji toggles (removes) it.
    """
    ident, err = _authenticate(**kwargs)
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
    options: list[str] = [],
    to: str = "",
    target_human: str = "",
    **kwargs: Any,
) -> str:
    """
    Calls human team members for an important decision, impasse resolution, or guidance.
    Renders high-visibility alert cards and quick-action choice buttons in the human Web UI.
    - options: Optional list of proposed choices.
    - to: Optional target recipient (e.g. 'humans' or '@Alice').
    - target_human: Optional specific human username to target.
    """
    ident, err = _authenticate(**kwargs)
    if err:
        return err
    callsign = ident["callsign"]

    try:
        eff_token = ident.get("token") or ""
        msg = await hub.call_human(
            room_name=room_name,
            sender=callsign,
            question=question,
            options=options,
            member_token=eff_token,
            password=kwargs.get("password", ""),
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
    **kwargs: Any,
) -> str:
    """
    Creates a voting poll in the chat room for team decisions.
    - options: List of at least 2 choices to vote on.
    """
    ident, err = _authenticate(**kwargs)
    if err:
        return err
    callsign = ident["callsign"]

    try:
        eff_token = ident.get("token") or ""
        poll = await hub.create_poll(
            room_name=room_name,
            creator=callsign,
            question=question,
            options=options,
            member_token=eff_token,
            password=kwargs.get("password", ""),
        )
        return json.dumps({"status": "success", "poll": poll}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def cast_vote(
    poll_id: int,
    option_index: int,
    **kwargs: Any,
) -> str:
    """
    Casts a vote on an active poll.
    - option_index: 0-indexed choice position.
    """
    ident, err = _authenticate(**kwargs)
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
def get_poll(poll_id: int, **kwargs: Any) -> str:
    """
    Gets live poll status, vote counts per option, and percentages.
    """
    ident, err = _authenticate(**kwargs)
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
    **kwargs: Any,
) -> str:
    """
    Closes an active poll (can only be closed by its creator or a human administrator).
    """
    ident, err = _authenticate(**kwargs)
    if err:
        return err
    callsign = ident["callsign"]

    try:
        eff_token = ident.get("token") or ""
        poll = await hub.close_poll(
            poll_id=poll_id,
            closer=callsign,
            password=kwargs.get("password", ""),
            is_human=ident.get("is_human", False),
            member_token=eff_token,
        )
        return json.dumps({"status": "success", "poll": poll}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


# -----------------------------------------------------------------
# Task Planner Tools
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
    **kwargs: Any,
) -> str:
    """
    Creates a new task in the room's task planner.
    - room_name: Target chat room
    - title: Brief summary of the task
    - description: Detailed notes / acceptance criteria
    - assignee: Name of assigned agent or human
    - waiting_for_agent: If waiting for another agent, their callsign
    - priority: 'urgent', 'high', 'medium', or 'low' (default: 'medium')
    - status: 'planned', 'in_progress', 'waiting_human', 'waiting_agent', 'done', 'cancelled'
    - uses_gpu: True if task requires local GPU resources
    - gpu_est_min: Estimated GPU duration in minutes
    - start_at: Optional planned ISO start time (e.g. '2026-09-27T14:00:00')
    - due_at: Optional deadline ISO timestamp
    - resource: Optional hardware resource (e.g. 'RTX_3080', 'RTX_5070TI')
    - message_id: Optional ID of chat message requesting this task
    """
    ident, err = _authenticate(**kwargs)
    if err:
        return err
    callsign = ident["callsign"]

    try:
        eff_token = ident.get("token") or ""
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
            member_token=eff_token,
            password=kwargs.get("password", ""),
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
    **kwargs: Any,
) -> str:
    """
    Updates an existing task in the room task planner.
    """
    ident, err = _authenticate(**kwargs)
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

        eff_token = ident.get("token") or ""
        task = await hub.update_task(
            task_id=task_id,
            member_token=eff_token,
            password=kwargs.get("password", ""),
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
    **kwargs: Any,
) -> str:
    """
    Lists tasks for a room from the task planner.
    - status: Optional filter ('planned', 'in_progress', 'waiting_human', 'waiting_agent', 'done', 'cancelled')
    - assignee: Optional filter by responsible agent or human
    - hide_completed: If True, excludes done and cancelled tasks
    """
    ident, err = _authenticate(**kwargs)
    if err:
        return err
    try:
        tasks = hub.list_tasks(
            room_name=room_name,
            status=status or None,
            assignee=assignee or None,
            hide_completed=hide_completed,
            password=kwargs.get("password", ""),
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
    **kwargs: Any,
) -> str:
    """
    Sets a new execution order for tasks in a room by providing the task IDs in preferred sequence.
    """
    ident, err = _authenticate(**kwargs)
    if err:
        return err
    try:
        eff_token = ident.get("token") or ""
        tasks = await hub.reorder_tasks(
            room_name=room_name,
            task_ids=task_ids,
            member_token=eff_token,
            password=kwargs.get("password", ""),
        )
        return json.dumps({
            "status": "success",
            "message": f"Reordered {len(task_ids)} tasks in #{room_name}.",
            "tasks": tasks,
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


# -----------------------------------------------------------------
# Calendar & Resource Booking Tools
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
    **kwargs: Any,
) -> str:
    """
    Lists calendar events for a specific room or across all rooms ('all').
    - room_name: Room name or 'all' to see all rooms
    - start_from: ISO datetime string filter (e.g. '2026-09-27T00:00:00')
    - start_to: ISO datetime string filter
    - resource: Filter by reserved hardware or resource (e.g. 'RTX_3080', 'RTX_5070TI')
    - status: 'scheduled', 'in_progress', 'completed', 'cancelled'
    - include_completed: If True, includes past completed or cancelled events
    - hide_completed: If True, excludes completed and cancelled events
    """
    ident, err = _authenticate(**kwargs)
    if err:
        return err
    token = ident.get("token", "")
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
            password=kwargs.get("password", ""),
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
    **kwargs: Any,
) -> str:
    """
    Schedules a new calendar event or GPU reservation in a room.
    The calendar dispatcher automatically fires reactive wake-up events on start_at / end_at.
    If 'resource' is specified, overlapping reservations for the same resource are rejected.
    - room_name: Target chat room
    - title: Event title or job summary
    - start_at: ISO 8601 start timestamp (e.g. '2026-09-27T15:00:00')
    - end_at: ISO 8601 end timestamp (optional; defaults to start_at + 1h if resource is set)
    - resource: Free text hardware resource (e.g. 'RTX_3080', 'RTX_5070TI', 'CPU_Runner')
    - description: Optional details or acceptance notes
    - event_type: 'event', 'gpu_lock', 'sync', 'maintenance'
    - task_id: Optional ID of linked Task Planner task
    - target_agent: Optional callsign of agent to ping on wake-up
    - wake_on_start: If True, dispatches a wake-up activity notification at start_at
    - wake_on_end: If True, dispatches a wake-up activity notification at end_at
    """
    ident, err = _authenticate(**kwargs)
    if err:
        return err
    callsign = ident["callsign"]

    try:
        eff_token = ident.get("token") or ""
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
            member_token=eff_token,
            password=kwargs.get("password", ""),
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
    **kwargs: Any,
) -> str:
    """
    Updates an existing calendar event or resource reservation.
    """
    ident, err = _authenticate(**kwargs)
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

        eff_token = ident.get("token") or ""
        ev = await hub.update_calendar_event(
            event_id=event_id,
            member_token=eff_token,
            password=kwargs.get("password", ""),
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
    **kwargs: Any,
) -> str:
    """
    Cancels/deletes a calendar event and releases any associated resource lock.
    """
    ident, err = _authenticate(**kwargs)
    if err:
        return err
    try:
        eff_token = ident.get("token") or ""
        res = await hub.delete_calendar_event(
            event_id=event_id,
            member_token=eff_token,
            password=kwargs.get("password", ""),
        )
        return json.dumps(res, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def check_resource_availability(
    resource: str,
    start_at: str,
    end_at: str = "",
    **kwargs: Any,
) -> str:
    """
    Checks if a hardware resource is available during a specified time interval, or if it has conflicting reservations.
    - resource: Resource name (case-insensitive)
    - start_at: ISO 8601 start timestamp
    - end_at: ISO 8601 end timestamp
    """
    ident, err = _authenticate(**kwargs)
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


# -----------------------------------------------------------------
# 12 Deprecated Tools (Stage 1: Explicit deprecation in v3, legacy in v2)
# -----------------------------------------------------------------
@mcp.tool()
def create_room(room_name: str, password: str = "", topic: str = "", **kwargs: Any) -> str:
    """Creates a new collaborative chat room (deprecated)."""
    dep = _handle_deprecated("create_room", "descontinuada: ação só para admins, na consola", room_name=room_name)
    if dep is not None:
        return dep
    # Legacy v2 fallback
    ident, err = _authenticate(password=password, **kwargs)
    if err:
        return err
    try:
        room = hub.create_room(name=room_name, password=password, topic=topic)
        return json.dumps({"status": "success", "message": f"Room '{room_name}' created successfully.", "room": room}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def join_room(room_name: str, agent_name: str = "", password: str = "", member_token: str = "", agent_token: str = "", **kwargs: Any) -> str:
    """Joins an existing chat room as a participant (deprecated)."""
    dep = _handle_deprecated("join_room", "descontinuada: ação só para admins, na consola", room_name=room_name)
    if dep is not None:
        return dep
    # Legacy v2 fallback
    token = (agent_token or member_token or kwargs.get("token", "")).strip()
    ident, err = _authenticate(agent_token=token, expected_callsign=agent_name, **kwargs)
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
def leave_room(room_name: str, agent_name: str = "", member_token: str = "", agent_token: str = "", **kwargs: Any) -> str:
    """Leaves a chat room (deprecated)."""
    dep = _handle_deprecated("leave_room", "descontinuada: ação só para admins, na consola", room_name=room_name)
    if dep is not None:
        return dep
    # Legacy v2 fallback
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(agent_token=token, expected_callsign=agent_name, **kwargs)
    if err:
        return err
    callsign = ident["callsign"]
    try:
        res = hub.leave_room(room_name=room_name, member_name=callsign, member_token=token)
        return json.dumps({"status": "success", "details": res}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def rotate_member_token(room_name: str, agent_name: str = "", current_token: str = "", password: str = "", member_token: str = "", agent_token: str = "", supervisor_token: str = "", **kwargs: Any) -> str:
    """Rotates member credential in a room (deprecated)."""
    dep = _handle_deprecated("rotate_member_token", "descontinuada: ação só para admins, na consola", room_name=room_name)
    if dep is not None:
        return dep
    # Legacy v2 fallback
    token = (supervisor_token or agent_token or member_token or current_token).strip()
    try:
        res = hub.rotate_member_token(room_name=room_name, member_name=agent_name, supervisor_token=token)
        return json.dumps({
            "status": "success",
            "message": f"Token for agent '{agent_name}' in room '{room_name}' rotated successfully.",
            "details": res,
            "member_token": res.get("member_token", ""),
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def change_room_password(room_name: str, old_password: str = "", new_password: str = "", agent_name: str = "", agent_token: str = "", member_token: str = "", supervisor_token: str = "", **kwargs: Any) -> str:
    """Changes room password (deprecated)."""
    dep = _handle_deprecated("change_room_password", "descontinuada: ação só para admins, na consola", room_name=room_name)
    if dep is not None:
        return dep
    # Legacy v2 fallback
    token = (supervisor_token or agent_token or member_token).strip()
    try:
        res = hub.change_room_password(room_name=room_name, old_password=old_password, new_password=new_password, actor_name=agent_name or "admin", supervisor_token=token)
        return json.dumps({"status": "success", "message": f"Password for room '{room_name}' changed successfully.", "details": res}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def kick_member(room_name: str, member_to_kick: str, requester_name: str = "", room_password: str = "", agent_token: str = "", member_token: str = "", **kwargs: Any) -> str:
    """Ejects a member from a room (deprecated)."""
    dep = _handle_deprecated("kick_member", "descontinuada: ação só para admins, na consola", room_name=room_name)
    if dep is not None:
        return dep
    # Legacy v2 fallback
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(agent_token=token, expected_callsign=requester_name, **kwargs)
    if err:
        return err
    callsign = ident["callsign"]
    try:
        res = hub.kick_member(room_name=room_name, member_to_kick=member_to_kick, actor_name=callsign, room_password=room_password)
        return json.dumps({"status": "success", "message": f"Member '{member_to_kick}' ejected from room '{room_name}'.", "details": res}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def archive_room(room_name: str, requester_name: str = "", requester_role: str = "agent", **kwargs: Any) -> str:
    """Archives a chat room (deprecated)."""
    dep = _handle_deprecated("archive_room", "descontinuada: ação só para admins, na consola", room_name=room_name)
    if dep is not None:
        return dep
    return json.dumps({"status": "error", "error": "Apenas o utilizador humano através da Web UI tem permissão para arquivar salas."}, indent=2)


@mcp.tool()
def get_room_audit_log(room_name: str, password: str = "", limit: int = 50, agent_token: str = "", member_token: str = "", **kwargs: Any) -> str:
    """Retrieves the audit log of security events (deprecated)."""
    dep = _handle_deprecated("get_room_audit_log", "descontinuada: ação só para admins, na consola", room_name=room_name)
    if dep is not None:
        return dep
    # Legacy v2 fallback
    ident, err = _authenticate(agent_token=agent_token, member_token=member_token, **kwargs)
    if err:
        return err
    try:
        events = hub.get_room_audit_log(room_name=room_name, password=password, limit=limit)
        return json.dumps({"status": "success", "room_name": room_name, "count": len(events), "events": events}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def get_room_transcript(room_name: str, password: str = "", agent_token: str = "", member_token: str = "", **kwargs: Any) -> str:
    """Returns the transcript file of a room (deprecated)."""
    dep = _handle_deprecated("get_room_transcript", "descontinuada: ação só para admins, na consola", room_name=room_name)
    if dep is not None:
        return dep
    # Legacy v2 fallback
    ident, err = _authenticate(agent_token=agent_token, member_token=member_token, **kwargs)
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
def check_new_messages(room_name: str = "subscribed", agent_name: str = "", since_id: int = 0, password: str = "", agent_token: str = "", member_token: str = "", **kwargs: Any) -> str:
    """Checks for new messages without blocking (deprecated)."""
    dep = _handle_deprecated("check_new_messages", "descontinuada: usa wait_for_work(timeout_seconds=0)", room_name=room_name)
    if dep is not None:
        return dep
    # Legacy v2 fallback
    ident, err = _authenticate(agent_token=agent_token, member_token=member_token, expected_callsign=agent_name, **kwargs)
    if err:
        return err
    effective_agent = ident["callsign"]
    try:
        result = hub.check_new_messages(room_name=room_name, agent_name=effective_agent, since_id=since_id, password=password)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def who_is_listening(room_name: str, password: str = "", agent_token: str = "", member_token: str = "", **kwargs: Any) -> str:
    """Checks active listeners in a room (deprecated)."""
    dep = _handle_deprecated("who_is_listening", "descontinuada: usa team_status", room_name=room_name)
    if dep is not None:
        return dep
    # Legacy v2 fallback
    ident, err = _authenticate(agent_token=agent_token, member_token=member_token, **kwargs)
    if err:
        return err
    try:
        res = hub.who_is_listening(room_name=room_name, password=password)
        return json.dumps(res, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def wake_up_call(room_name: str = "all", since_seq: int | None = None, timeout_seconds: int = 60, watcher_name: str = "Sentinel", ctx: Context = None, **kwargs: Any) -> str:
    """Listens for activity pings across channels (deprecated)."""
    dep = _handle_deprecated("wake_up_call", "descontinuada: usa wait_for_work", room_name=room_name)
    if dep is not None:
        return dep
    # Legacy v2 fallback
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


# -----------------------------------------------------------------
# MCP Resources & Prompts
# -----------------------------------------------------------------
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
    msgs = hub.storage.get_messages(room_name, limit=50)
    return json.dumps(msgs, indent=2)


@mcp.prompt()
def collaborative_agent(room_name: str, my_agent_name: str, task_goal: str) -> str:
    """Prompt template for configuring an agent to collaborate in a chat room."""
    return f"""You are collaborating with other AI agents and human teammates in the chat room '{room_name}'.
Your callsign in this room is: '{my_agent_name}'.
The overall team objective is: {task_goal}

Collaboration Protocol:
1. Check room messages using `read_messages(room_name="{room_name}")` to catch up on discussion.
2. Check team liveliness and who is present using `team_status(room_name="{room_name}")`.
3. When you have an update, question, or handoff, call `send_message(room_name="{room_name}", content=..., to=...)`.
4. After completing your turn, call `wait_for_work(timeout_seconds=600)` to wait for new work or messages.
5. If you need a decision from human teammates, use `call_human(room_name="{room_name}", question=..., options=...)`.
6. Be concise, constructive, and avoid duplicate messages.
"""


def prune_mcp_tool_parameters() -> None:
    """
    Removes credential, password, and sender identity arguments from all published MCP tool schemas.
    Authentication is handled strictly at connection time via Bearer headers or stdio credentials.
    """
    params_to_remove = [
        "agent_token",
        "member_token",
        "sender_name",
        "agent_name",
        "creator_name",
        "voter_name",
        "closer_name",
        "actor_name",
        "requester_name",
        "password",
        "room_password",
        "old_password",
        "new_password",
        "supervisor_token",
        "current_token",
    ]
    for name in list(mcp._tool_manager._tools.keys()):
        t = mcp._tool_manager.get_tool(name)
        if t and t.parameters and "properties" in t.parameters:
            for p in params_to_remove:
                t.parameters["properties"].pop(p, None)
                if "required" in t.parameters and p in t.parameters["required"]:
                    t.parameters["required"].remove(p)


prune_mcp_tool_parameters()
