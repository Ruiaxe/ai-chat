import asyncio
import json
import os
from pathlib import Path
import secrets
import sys
from typing import Any
from urllib.parse import urlparse

from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.endpoints import WebSocketEndpoint
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response, StreamingResponse
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketDisconnect

import edge_tts

from aichat.config import STATIC_DIR
from aichat.mcp_server import hub, mcp

INDEX_HTML = STATIC_DIR / "index.html"


def safe_int(val: Any, default: int = 0, min_val: int | None = None, max_val: int | None = None) -> int:
    """Safely converts value to int with bounds, avoiding unhandled 500 exceptions."""
    try:
        res = int(val)
    except (ValueError, TypeError):
        return default
    if min_val is not None and res < min_val:
        return min_val
    if max_val is not None and res > max_val:
        return max_val
    return res


def is_same_origin_scope(origin_str: str, scope: Scope) -> bool:
    """Verifies that the origin header matches the server's own origin."""
    if not origin_str:
        return True
    try:
        parsed = urlparse(origin_str)
        origin_netloc = (parsed.netloc or "").lower()
        if not origin_netloc:
            return False

        headers = Headers(scope=scope)
        host_header = (headers.get("host") or "").lower()
        if not host_header:
            server = scope.get("server")
            if server:
                host_header = f"{server[0]}:{server[1]}"

        # Exact match of host & port
        if origin_netloc == host_header:
            return True

        # Allow testserver ONLY during automated test runs
        is_testing = os.environ.get("AICHAT_TESTING") == "1"
        if is_testing and origin_netloc in ("testserver", "testserver:80") and host_header in ("testserver", "testserver:80"):
            return True

        # Match loopback aliases (127.0.0.1 and localhost) with matching port
        parsed_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        host_port = 80
        host_name = host_header
        if ":" in host_header:
            host_name, port_str = host_header.split(":", 1)
            try:
                host_port = int(port_str)
            except ValueError:
                pass
        else:
            host_port = 443 if scope.get("scheme") == "https" else 80

        if parsed_port == host_port and parsed.hostname in ("127.0.0.1", "localhost") and host_name in ("127.0.0.1", "localhost"):
            return True

        return False
    except Exception:
        return False


def is_same_origin(origin_str: str, request_or_ws: Any) -> bool:
    """Helper delegating to is_same_origin_scope using request or websocket scope."""
    scope = getattr(request_or_ws, "scope", None)
    if scope is not None:
        return is_same_origin_scope(origin_str, scope)
    return False


class SecurityHardeningMiddleware:
    """Pure ASGI middleware enforcing strict Origin validation and Content-Type requirements against CSRF/DNS-rebinding without interfering with SSE streams or WebSockets."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            method = scope.get("method", "").upper()
            if method in ("POST", "PATCH", "DELETE", "PUT"):
                headers = Headers(scope=scope)

                # 1. Validate Origin header on state-modifying requests
                origin = headers.get("origin", "").strip()
                if origin and not is_same_origin_scope(origin, scope):
                    response = JSONResponse({"error": "Forbidden: Cross-origin request rejected"}, status_code=403)
                    await response(scope, receive, send)
                    return

                # 2. Content-Type validation for JSON API endpoints
                path = scope.get("path", "")
                if method in ("POST", "PATCH") and path.startswith("/api/") and not path.startswith("/api/tts"):
                    raw_ct = headers.get("content-type", "").strip()
                    main_ct = raw_ct.split(";")[0].strip().lower() if raw_ct else ""
                    content_len_str = headers.get("content-length", "").strip()
                    is_chunked = headers.get("transfer-encoding", "").lower() == "chunked"
                    has_body = is_chunked or (content_len_str and content_len_str != "0")
                    if has_body or raw_ct:
                        if main_ct != "application/json":
                            response = JSONResponse(
                                {"error": f"Unsupported Media Type: expected application/json, got '{raw_ct}'"},
                                status_code=415
                            )
                            await response(scope, receive, send)
                            return

        await self.app(scope, receive, send)


def is_authenticated_human(request: Request) -> bool:
    """Verifies if request originates from authenticated human via valid session cookie or X-Human-Token header."""
    cookie_token = request.cookies.get("human_session", "").strip()
    header_token = request.headers.get("X-Human-Token", "").strip()
    return bool(
        (cookie_token and hub.verify_human_session(cookie_token)) or
        (header_token and secrets.compare_digest(header_token, hub.human_token))
    )


def set_human_session_cookie(response: Response, session_val: str) -> None:
    """Sets a persistent HttpOnly cookie with SameSite=Strict for human authentication."""
    response.set_cookie(
        key="human_session",
        value=session_val,
        max_age=86400 * 30,
        httponly=True,
        samesite="strict",
        path="/",
    )


# --- HTTP Endpoints ---

async def endpoint_index(request: Request) -> Response:
    """Serves the Web UI HTML application. Authenticates session via ?auth= query param (single-use code only)."""
    auth_param = request.query_params.get("auth", "").strip()
    if auth_param:
        if hub.consume_one_time_code(auth_param):
            response = RedirectResponse(url="/", status_code=303)
            session_id = hub.create_human_session()
            set_human_session_cookie(response, session_id)
            return response

    if INDEX_HTML.exists():
        html = INDEX_HTML.read_text(encoding="utf-8")
        return HTMLResponse(html)
    return HTMLResponse("<h1>AI Chat Hub</h1><p>index.html not found</p>", status_code=404)


async def endpoint_auth_status(request: Request) -> Response:
    """Checks human authentication status."""
    is_auth = is_authenticated_human(request)
    return JSONResponse({
        "authenticated": is_auth,
        "human_name": hub.human_name,
    })


async def endpoint_auth_login(request: Request) -> Response:
    """Authenticates human user with token or one-time code, setting persistent session cookie."""
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    token = (data.get("token") or "").strip()
    if not token:
        return JSONResponse({"error": "Token is required"}, status_code=400)

    is_valid = secrets.compare_digest(token, hub.human_token) or hub.consume_one_time_code(token)
    if not is_valid:
        return JSONResponse({"error": "Token inválido. Verifique a credencial de acesso humano."}, status_code=401)

    session_id = hub.create_human_session()
    response = JSONResponse({
        "success": True,
        "message": "Autenticado com sucesso",
        "human_name": hub.human_name,
    })
    set_human_session_cookie(response, session_id)
    return response


async def endpoint_auth_logout(request: Request) -> Response:
    """Clears human session cookie and invalidates session."""
    cookie_token = request.cookies.get("human_session", "").strip()
    if cookie_token:
        hub.invalidate_human_session(cookie_token)
    response = JSONResponse({"success": True, "message": "Sessão terminada"})
    response.delete_cookie(key="human_session", path="/")
    return response


async def endpoint_get_rooms(request: Request) -> Response:
    """Lists all rooms with metadata."""
    include_archived = request.query_params.get("include_archived", "true").lower() in ("true", "1")
    rooms = hub.list_rooms(include_archived=include_archived)
    return JSONResponse(rooms)


async def endpoint_create_room(request: Request) -> Response:
    """Creates a new room."""
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    name = data.get("name", "").strip()
    topic = data.get("topic", "").strip()
    password = data.get("password", "")

    if not name:
        return JSONResponse({"error": "Room name is required"}, status_code=400)

    try:
        room = hub.create_room(name=name, password=password, topic=topic)
        return JSONResponse(room, status_code=201)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_get_messages(request: Request) -> Response:
    """Gets recent messages for a room."""
    room_name = request.path_params["room_name"]
    password = request.query_params.get("password", "") or request.headers.get("x-room-password", "")
    since_id = safe_int(request.query_params.get("since_id"), default=0, min_val=0)
    before_id = safe_int(request.query_params.get("before_id"), default=0, min_val=0)
    limit = safe_int(request.query_params.get("limit"), default=50, min_val=1, max_val=1000)

    try:
        is_human = is_authenticated_human(request)
        effective_ht = hub.human_token if is_human else ""

        # Record presence only for verified tokens or authenticated human session
        agent_tok = (
            request.headers.get("x-agent-token", "") or
            request.headers.get("x-member-token", "") or
            request.query_params.get("agent_token", "") or
            request.query_params.get("token", "")
        ).strip()
        if agent_tok:
            try:
                ident = hub.authenticate_agent(agent_tok)
                hub.record_presence(room_name, ident["callsign"], client="http_poll", is_human=ident.get("is_human", False))
            except Exception:
                pass
        elif is_human:
            hub.record_presence(room_name, hub.human_name, client="web_ui", is_human=True)

        messages = hub.read_messages(
            room_name=room_name,
            password=password,
            since_id=since_id,
            before_id=before_id,
            limit=limit,
            requester_token=effective_ht,
        )
        return JSONResponse(messages)
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_post_message(request: Request) -> Response:
    """Posts a message to a room with strict authentication."""
    room_name = request.path_params["room_name"]
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    sender = (data.get("sender") or data.get("sender_name") or data.get("agent_name") or "").strip()
    if not sender:
        return JSONResponse({"error": "Sender cannot be empty"}, status_code=400)

    content = data.get("content", "").strip()
    password = data.get("password", "")
    member_token = data.get("member_token", "")

    is_human = is_authenticated_human(request)
    sender_norm = "".join(c for c in sender.lower() if c.isalnum())
    is_reserved = sender_norm in hub.RESERVED_HUMAN_NAMES or sender.lower() in hub.RESERVED_HUMAN_NAMES
    req_role = (data.get("role") or "").strip().lower()

    if req_role == "human" or is_reserved:
        if not is_human:
            return JSONResponse(
                {"error": f"Acesso negado: Remetente '{sender}' ou papel 'human' reservado exclusivamente ao utilizador humano autenticado."},
                status_code=403,
            )
        role = "human"
        effective_ht = hub.human_token
    else:
        role = "agent"
        effective_ht = ""

    if not content:
        return JSONResponse({"error": "Content cannot be empty"}, status_code=400)

    try:
        msg = await hub.send_message(
            room_name=room_name,
            sender=sender,
            content=content,
            role=role,
            password=password,
            member_token=member_token,
            human_token=effective_ht,
        )
        return JSONResponse(msg, status_code=201)
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        err_msg = str(ve)
        status_code = 404 if "does not exist" in err_msg.lower() else 400
        return JSONResponse({"error": err_msg}, status_code=status_code)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_download_log(request: Request) -> Response:
    """Downloads the text log of a room."""
    room_name = request.path_params["room_name"]
    password = request.query_params.get("password", "") or request.headers.get("x-room-password", "")
    is_human = is_authenticated_human(request)
    effective_ht = hub.human_token if is_human else ""

    try:
        if not hub.verify_room_access(room_name, password, requester_token=effective_ht):
            return JSONResponse({"error": "Access denied: incorrect password"}, status_code=403)

        log_path = hub.storage.get_room_log_file(room_name)
        if not log_path.exists():
            return PlainTextResponse(f"No log file found for room '{room_name}'.", status_code=404)

        return FileResponse(
            path=str(log_path),
            media_type="text/plain; charset=utf-8",
            filename=f"{room_name}.log",
        )
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=404)


async def endpoint_download_jsonl(request: Request) -> Response:
    """Downloads the structured JSONL log of a room."""
    room_name = request.path_params["room_name"]
    password = request.query_params.get("password", "")
    is_human = is_authenticated_human(request)
    effective_ht = hub.human_token if is_human else ""

    try:
        if not hub.verify_room_access(room_name, password, requester_token=effective_ht):
            return JSONResponse({"error": "Access denied: incorrect password"}, status_code=403)

        jsonl_path = hub.storage.get_room_jsonl_file(room_name)
        if not jsonl_path.exists():
            return PlainTextResponse(f"No JSONL file found for room '{room_name}'.", status_code=404)

        return FileResponse(
            path=str(jsonl_path),
            media_type="application/x-ndjson; charset=utf-8",
            filename=f"{room_name}.jsonl",
        )
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=404)


async def endpoint_room_sse_stream(request: Request) -> Response:
    """Server-Sent Events (SSE) stream for a room to allow live event consumption."""
    room_name = request.path_params["room_name"]
    password = request.query_params.get("password", "")
    is_human = is_authenticated_human(request)
    effective_ht = hub.human_token if is_human else ""

    try:
        if not hub.verify_room_access(room_name, password, requester_token=effective_ht):
            return JSONResponse({"error": "Access denied"}, status_code=403)
    except ValueError:
        return JSONResponse({"error": "Room not found"}, status_code=404)

    async def event_generator():
        last_id = 0
        while True:
            if await request.is_disconnected():
                break
            res = await hub.wait_for_new_messages(
                room_name=room_name,
                since_id=last_id,
                timeout_seconds=20.0,
                password=password,
            )
            if res.get("status") == "new_messages" and res.get("messages"):
                for m in res["messages"]:
                    yield f"event: message\ndata: {json.dumps(m)}\n\n"
                    last_id = max(last_id, m["id"])
            else:
                yield ": keepalive\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


async def endpoint_toggle_reaction(request: Request) -> Response:
    """Toggles an emoji reaction on a message."""
    message_id = int(request.path_params["message_id"])
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    room_name = data.get("room_name", "").strip()
    sender = data.get("sender", "Human").strip()
    emoji = data.get("emoji", "").strip()
    if not emoji:
        return JSONResponse({"error": "Emoji is required"}, status_code=400)
    try:
        res = await hub.toggle_reaction(message_id, room_name, sender, emoji)
        return JSONResponse(res)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_resolve_decision(request: Request) -> Response:
    """Resolves a pending human decision request."""
    if not is_authenticated_human(request):
        return JSONResponse({"error": "Acesso negado: Apenas o utilizador humano autenticado pode tomar decisões."}, status_code=403)
    message_id = int(request.path_params["message_id"])
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    room_name = data.get("room_name", "").strip()
    decision = data.get("decision", "").strip()
    decider = data.get("decider", "Rui").strip()
    if not decision:
        return JSONResponse({"error": "Decision is required"}, status_code=400)
    try:
        res = await hub.resolve_human_decision(
            message_id, room_name, decision, decider, human_token=hub.human_token
        )
        return JSONResponse(res)
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_create_poll(request: Request) -> Response:
    """Creates a poll in a room."""
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    room_name = data.get("room_name", "").strip()
    creator = data.get("creator", "Human").strip()
    question = data.get("question", "").strip()
    options = data.get("options", [])
    member_token = data.get("member_token", "").strip()
    if not question or len(options) < 2:
        return JSONResponse({"error": "Question and at least 2 options are required"}, status_code=400)

    is_human = is_authenticated_human(request)
    try:
        poll = await hub.create_poll(
            room_name=room_name,
            creator=creator,
            question=question,
            options=options,
            member_token=member_token,
            human_token=hub.human_token if is_human else "",
            role="human" if is_human else "agent",
        )
        return JSONResponse(poll, status_code=201)
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_cast_vote(request: Request) -> Response:
    """Casts a vote on a poll."""
    poll_id = int(request.path_params["poll_id"])
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    voter = data.get("voter", "Human").strip()
    option_index = int(data.get("option_index", 0))
    try:
        poll = await hub.cast_vote(poll_id, voter, option_index)
        return JSONResponse(poll)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_get_poll(request: Request) -> Response:
    """Gets poll details."""
    poll_id = int(request.path_params["poll_id"])
    poll = hub.get_poll(poll_id)
    if not poll:
        return JSONResponse({"error": "Poll not found"}, status_code=404)
    return JSONResponse(poll)


async def endpoint_close_poll(request: Request) -> Response:
    """Closes an active poll."""
    poll_id = int(request.path_params["poll_id"])
    try:
        data = await request.json()
    except Exception:
        data = {}
    closer = data.get("closer", "Human").strip()
    member_token = data.get("member_token", "").strip()
    is_human = is_authenticated_human(request)
    try:
        poll = await hub.close_poll(
            poll_id=poll_id,
            closer=closer,
            is_human=is_human,
            member_token=member_token,
            human_token=hub.human_token if is_human else "",
        )
        return JSONResponse(poll)
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_archive_room(request: Request) -> Response:
    """Archives a room. Restricted strictly to authenticated human users."""
    if not is_authenticated_human(request):
        return JSONResponse({"error": "Apenas o utilizador humano autenticado tem permissão para arquivar salas."}, status_code=403)
    room_name = request.path_params["room_name"]
    try:
        res = hub.archive_room(room_name, requester_role="human")
        await hub._broadcast_to_websockets(room_name, {"type": "room_archived", "room_name": room_name})
        return JSONResponse(res)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_unarchive_room(request: Request) -> Response:
    """Unarchives a room. Restricted strictly to authenticated human users."""
    if not is_authenticated_human(request):
        return JSONResponse({"error": "Apenas o utilizador humano autenticado tem permissão para desarquivar salas."}, status_code=403)
    room_name = request.path_params["room_name"]
    try:
        res = hub.unarchive_room(room_name, requester_role="human")
        await hub._broadcast_to_websockets(room_name, {"type": "room_unarchived", "room_name": room_name})
        return JSONResponse(res)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_rotate_token(request: Request) -> Response:
    """Rotates member token for a room."""
    room_name = request.path_params["room_name"]
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    member_name = (data.get("member_name") or data.get("agent_name") or "").strip()
    if not member_name:
        return JSONResponse({"error": "member_name is required"}, status_code=400)

    current_token = (data.get("current_token") or data.get("member_token") or "").strip()
    password = data.get("password", "") or request.headers.get("x-room-password", "")

    supervisor_token = hub.human_token if is_authenticated_human(request) else (data.get("supervisor_token") or request.headers.get("x-human-token", "")).strip()

    try:
        res = hub.rotate_member_token(
            room_name=room_name,
            member_name=member_name,
            current_token=current_token,
            password=password,
            supervisor_token=supervisor_token,
        )
        return JSONResponse(res, status_code=200)
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_change_password(request: Request) -> Response:
    """Changes password for a room."""
    room_name = request.path_params["room_name"]
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    old_password = data.get("old_password", "") or request.headers.get("x-room-password", "")
    new_password = data.get("new_password", "")
    actor_name = data.get("actor_name", "") or ("Rui" if is_authenticated_human(request) else "")
    supervisor_token = hub.human_token if is_authenticated_human(request) else data.get("supervisor_token", "")

    try:
        res = hub.change_room_password(
            room_name=room_name,
            old_password=old_password,
            new_password=new_password,
            actor_name=actor_name,
            supervisor_token=supervisor_token,
        )
        return JSONResponse(res, status_code=200)
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_kick_member(request: Request) -> Response:
    """Kicks/ejects a member from a room."""
    room_name = request.path_params["room_name"]
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    member_to_kick = (data.get("member_to_kick") or data.get("member_name") or "").strip()
    if not member_to_kick:
        return JSONResponse({"error": "member_to_kick is required"}, status_code=400)

    actor_name = data.get("actor_name", "") or ("Rui" if is_authenticated_human(request) else "")
    supervisor_token = hub.human_token if is_authenticated_human(request) else data.get("supervisor_token", "")
    room_password = data.get("room_password", "") or request.headers.get("x-room-password", "")

    try:
        res = hub.kick_member(
            room_name=room_name,
            member_to_kick=member_to_kick,
            actor_name=actor_name,
            supervisor_token=supervisor_token,
            room_password=room_password,
        )
        return JSONResponse(res, status_code=200)
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_get_audit(request: Request) -> Response:
    """Gets audit log for a room."""
    room_name = request.path_params["room_name"]
    password = request.query_params.get("password", "") or request.headers.get("x-room-password", "")
    limit = safe_int(request.query_params.get("limit"), default=50, min_val=1, max_val=200)

    try:
        events = hub.get_room_audit_log(room_name=room_name, password=password, limit=limit)
        return JSONResponse(events, status_code=200)
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_status(request: Request) -> Response:
    """Returns server health status."""
    return JSONResponse({
        "status": "healthy",
        "service": "ai-chat-mcp",
        "version": "0.1.0",
        "rooms_count": len(hub.list_rooms()),
    })


async def endpoint_tts(request: Request) -> Response:
    """Generates audio for text using Microsoft Edge TTS neural voices."""
    text = ""
    voice = "pt-PT-DuarteNeural"
    
    if request.method == "POST":
        try:
            body = await request.json()
            text = body.get("text", "").strip()
            voice = body.get("voice", voice).strip()
        except Exception:
            pass
    else:
        text = request.query_params.get("text", "").strip()
        voice = request.query_params.get("voice", voice).strip()

    if not text:
        return JSONResponse({"error": "Text parameter is required."}, status_code=400)

    # Sanitize text length
    if len(text) > 3000:
        text = text[:3000]

    try:
        communicate = edge_tts.Communicate(text, voice)
        async def audio_stream():
            async for chunk in communicate.stream():
                if chunk["type"] == "audio":
                    yield chunk["data"]
        return StreamingResponse(
            audio_stream(),
            media_type="audio/mpeg",
            headers={
                "Cache-Control": "no-cache",
                "Content-Disposition": "inline; filename=tts.mp3"
            }
        )
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_tts_voices(request: Request) -> Response:
    """Returns available Microsoft Edge neural voices for Portuguese and English."""
    try:
        all_voices = await edge_tts.list_voices()
        # Curate list of high quality voices
        preferred = [
            {"id": "pt-PT-DuarteNeural", "name": "Duarte (Português - Portugal)", "gender": "Male", "locale": "pt-PT"},
            {"id": "pt-PT-RaquelNeural", "name": "Raquel (Português - Portugal)", "gender": "Female", "locale": "pt-PT"},
            {"id": "pt-BR-FranciscaNeural", "name": "Francisca (Português - Brasil)", "gender": "Female", "locale": "pt-BR"},
            {"id": "pt-BR-AntonioNeural", "name": "Antônio (Português - Brasil)", "gender": "Male", "locale": "pt-BR"},
            {"id": "en-US-GuyNeural", "name": "Guy (English - US)", "gender": "Male", "locale": "en-US"},
            {"id": "en-US-AriaNeural", "name": "Aria (English - US)", "gender": "Female", "locale": "en-US"},
        ]
        return JSONResponse(preferred)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# --- Task Planner & Presence Endpoints (v2.5) ---

async def endpoint_get_presence(request: Request) -> Response:
    """Returns real-time active listeners in a room."""
    room_name = request.path_params["room_name"]
    password = request.query_params.get("password", "") or request.headers.get("x-room-password", "")
    is_human = is_authenticated_human(request)
    effective_ht = hub.human_token if is_human else ""
    try:
        presence = hub.who_is_listening(room_name=room_name, password=password, requester_token=effective_ht)
        return JSONResponse(presence)
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_get_tasks(request: Request) -> Response:
    """Lists tasks in a room with optional filters."""
    room_name = request.path_params["room_name"]
    password = request.query_params.get("password", "") or request.headers.get("x-room-password", "")
    status = request.query_params.get("status")
    assignee = request.query_params.get("assignee")
    hide_completed = request.query_params.get("hide_completed", "").lower() in ("true", "1", "yes")
    is_human = is_authenticated_human(request)
    effective_ht = hub.human_token if is_human else ""

    try:
        tasks = hub.list_tasks(
            room_name=room_name,
            status=status,
            assignee=assignee,
            hide_completed=hide_completed,
            password=password,
            requester_token=effective_ht,
        )
        return JSONResponse({"status": "success", "tasks": tasks, "count": len(tasks)})
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_create_task(request: Request) -> Response:
    """Creates a new task in a room."""
    room_name = request.path_params["room_name"]
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    title = (data.get("title") or "").strip()
    if not title:
        return JSONResponse({"error": "O título da tarefa é obrigatório."}, status_code=400)

    is_human = is_authenticated_human(request)
    human_tok = hub.human_token if is_human else ""
    member_tok = data.get("member_token", "")
    creator = "Rui" if is_human else (data.get("created_by") or data.get("creator") or "WebUser")

    try:
        task = await hub.create_task(
            room_name=room_name,
            title=title,
            description=data.get("description", ""),
            assignee=data.get("assignee", ""),
            waiting_for_agent=data.get("waiting_for_agent", ""),
            priority=data.get("priority", "medium"),
            status=data.get("status", "planned"),
            order_index=data.get("order_index"),
            message_id=data.get("message_id"),
            uses_gpu=bool(data.get("uses_gpu", False)),
            gpu_est_min=safe_int(data.get("gpu_est_min"), default=0, min_val=0),
            member_token=member_tok,
            human_token=human_tok,
            password=data.get("password", ""),
            created_by=creator,
        )
        return JSONResponse(task, status_code=201)
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_update_task(request: Request) -> Response:
    """Updates fields of an existing task."""
    task_id = int(request.path_params["task_id"])
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    is_human = is_authenticated_human(request)
    human_tok = hub.human_token if is_human else ""
    member_tok = data.get("member_token", "")
    actor = "Rui" if is_human else (data.get("actor") or data.get("assignee") or "")

    allowed_fields = [
        "title", "description", "status", "assignee", "waiting_for_agent",
        "priority", "order_index", "message_id", "uses_gpu", "gpu_est_min"
    ]
    kwargs = {k: v for k, v in data.items() if k in allowed_fields}

    try:
        task = await hub.update_task(
            task_id=task_id,
            member_token=member_tok,
            human_token=human_tok,
            password=data.get("password", ""),
            actor=actor,
            **kwargs,
        )
        return JSONResponse(task)
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_delete_task(request: Request) -> Response:
    """Deletes a task."""
    task_id = int(request.path_params["task_id"])
    is_human = is_authenticated_human(request)
    human_tok = hub.human_token if is_human else ""
    member_tok = request.headers.get("x-member-token", "")
    password = request.query_params.get("password", "")

    try:
        res = await hub.delete_task(
            task_id=task_id,
            member_token=member_tok,
            human_token=human_tok,
            password=password,
            actor="Rui" if is_human else "",
        )
        return JSONResponse(res)
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_reorder_tasks(request: Request) -> Response:
    """Reorders tasks in a room."""
    room_name = request.path_params["room_name"]
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    task_ids = data.get("task_ids", [])
    if not isinstance(task_ids, list):
        return JSONResponse({"error": "task_ids deve ser uma lista de inteiros"}, status_code=400)

    is_human = is_authenticated_human(request)
    human_tok = hub.human_token if is_human else ""
    member_tok = data.get("member_token", "")
    password = data.get("password", "")

    try:
        tasks = await hub.reorder_tasks(
            room_name=room_name,
            task_ids=task_ids,
            member_token=member_tok,
            human_token=human_tok,
            password=password,
        )
        return JSONResponse({"status": "success", "tasks": tasks})
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# --- Agent Registry Management Endpoints (v2.7) ---

async def endpoint_list_agents(request: Request) -> Response:
    """Lists registered agents. Secret tokens are only exposed to the authenticated human supervisor."""
    is_human = is_authenticated_human(request)
    agents = hub.list_registered_agents(requester_token=hub.human_token if is_human else "")
    return JSONResponse({"status": "success", "count": len(agents), "agents": agents})


async def endpoint_register_agent(request: Request) -> Response:
    """Provisions a new unique agent callsign in the closed registry. Restricted to supervisor Rui."""
    if not is_authenticated_human(request):
        return JSONResponse({"error": "Acesso negado: Apenas o supervisor humano Rui pode registar agentes."}, status_code=403)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    callsign = (data.get("callsign") or "").strip()
    if not callsign:
        return JSONResponse({"error": "callsign is required"}, status_code=400)
    role = (data.get("role") or "agent").strip()
    token = (data.get("token") or "").strip() or None
    is_system = bool(data.get("is_system", False))

    try:
        res = hub.register_agent_admin(
            callsign=callsign,
            token=token,
            role=role,
            is_system=is_system,
            supervisor_token=hub.human_token,
        )
        return JSONResponse({"status": "success", "agent": res}, status_code=201)
    except (ValueError, PermissionError) as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_self_register_agent(request: Request) -> Response:
    """Allows an agent or client to self-register with a unique callsign and obtain an agent_token."""
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    callsign = (data.get("callsign") or "").strip()
    if not callsign:
        return JSONResponse({"error": "callsign is required"}, status_code=400)

    try:
        res = hub.self_register_agent(callsign=callsign)
        return JSONResponse({"status": "success", "agent": res}, status_code=201)
    except (ValueError, PermissionError) as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_rotate_agent_token(request: Request) -> Response:
    """Rotates an agent's secret token in the closed registry. Restricted to supervisor Rui."""
    if not is_authenticated_human(request):
        return JSONResponse({"error": "Acesso negado: Apenas o supervisor humano Rui pode rodar tokens de agentes."}, status_code=403)
    callsign = request.path_params["callsign"]
    try:
        new_tok = hub.rotate_agent_token_admin(callsign=callsign, supervisor_token=hub.human_token)
        return JSONResponse({"status": "success", "callsign": callsign, "agent_token": new_tok})
    except (ValueError, PermissionError) as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_delete_agent(request: Request) -> Response:
    """Allows authenticated supervisor Rui to delete an agent."""
    if not is_authenticated_human(request):
        return JSONResponse({"error": "Acesso negado: Apenas o supervisor humano Rui pode remover agentes."}, status_code=403)
    callsign = request.path_params["callsign"]
    try:
        hub.delete_agent_admin(callsign=callsign, supervisor_token=hub.human_token)
        return JSONResponse({"status": "success", "deleted": callsign})
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_list_admin_rooms(request: Request) -> Response:
    """Lists all rooms including passwords for the authenticated supervisor."""
    if not is_authenticated_human(request):
        return JSONResponse({"error": "Acesso negado: Apenas o supervisor humano Rui pode aceder a este endpoint."}, status_code=403)
    try:
        rooms = hub.storage.list_rooms(include_archived=True, include_passwords=True)
        return JSONResponse({"status": "success", "count": len(rooms), "rooms": rooms})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_admin_set_room_password(request: Request) -> Response:
    """Allows authenticated supervisor Rui to set, change, or remove a room's password."""
    if not is_authenticated_human(request):
        return JSONResponse({"error": "Acesso negado: Apenas o supervisor humano Rui pode alterar senhas de salas."}, status_code=403)
    room_name = request.path_params["room_name"]
    try:
        data = await request.json()
    except Exception:
        data = {}
    password = data.get("password", "")
    try:
        res = hub.change_room_password(
            room_name=room_name,
            old_password="",
            new_password=password,
            actor_name="Rui",
            supervisor_token=hub.human_token,
        )
        return JSONResponse(res, status_code=200)
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# --- WebSocket Endpoint ---

async def websocket_room_endpoint(websocket: WebSocket) -> None:
    """Real-time WebSocket handler for chat rooms, validating origin, room password, and access."""
    room_name = websocket.path_params["room_name"]
    password = websocket.query_params.get("password", "")

    # D2: Validate WebSocket origin
    origin = websocket.headers.get("origin", "").strip()
    if origin and not is_same_origin(origin, websocket):
        await websocket.close(code=4403, reason="Forbidden: Cross-origin WebSocket rejected")
        return

    # Check if human is authenticated via valid session cookie or X-Human-Token header
    cookie_token = websocket.cookies.get("human_session", "").strip()
    header_token = websocket.headers.get("x-human-token", "").strip()
    is_human = bool(
        (cookie_token and hub.verify_human_session(cookie_token)) or
        (header_token and secrets.compare_digest(header_token, hub.human_token))
    )

    if not is_human:
        try:
            if not hub.verify_room_access(room_name, password):
                await websocket.close(code=4403, reason="Access denied: invalid or missing room password")
                return
        except ValueError:
            await websocket.close(code=4404, reason="Room not found")
            return

    await websocket.accept()
    user_name = "Rui (Humano)" if is_human else websocket.query_params.get("username", "WebUser")
    await hub.register_websocket(room_name, websocket, user_name=user_name, is_human=is_human)

    # Broadcast presence update on join
    try:
        p_info = hub.who_is_listening(room_name, requester_token=hub.human_token if is_human else "")
        await hub._broadcast_to_websockets(room_name, {"type": "presence_updated", "room": room_name, "presence": p_info})
    except Exception:
        pass

    try:
        while True:
            data = await websocket.receive_text()
            # Handle client-side heartbeat or direct message
            try:
                msg_obj = json.loads(data)
                if msg_obj.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
            except Exception:
                pass
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    finally:
        await hub.unregister_websocket(room_name, websocket)
        try:
            p_info = hub.who_is_listening(room_name)
            await hub._broadcast_to_websockets(room_name, {"type": "presence_updated", "room": room_name, "presence": p_info})
        except Exception:
            pass


from contextlib import asynccontextmanager

@asynccontextmanager
async def app_lifespan(app: Starlette):
    """Manages background tasks and Streamable HTTP session manager."""
    async with mcp.session_manager.run():
        yield


def create_app(allowed_hosts: list[str] | None = None) -> Starlette:
    """Builds and returns the combined Starlette ASGI application with security middleware."""
    if allowed_hosts is None:
        is_testing = os.environ.get("AICHAT_TESTING") == "1"
        allowed_hosts = ["127.0.0.1", "localhost"] + (["testserver"] if is_testing else [])
    else:
        allowed_hosts = [h.split(":")[0] for h in allowed_hosts]

    # FastMCP SSE app routes (/sse, /messages)
    mcp_sse = mcp.sse_app()
    # FastMCP Streamable HTTP app routes (/mcp)
    mcp_http = mcp.streamable_http_app()

    # Route POST /sse to the streamable HTTP endpoint in case client sends direct POST
    streamable_endpoint = mcp_http.routes[0].endpoint if mcp_http.routes else None

    routes = [
        Route("/", endpoint=endpoint_index, methods=["GET"]),
        Route("/api/status", endpoint=endpoint_status, methods=["GET"]),
        Route("/api/auth/status", endpoint=endpoint_auth_status, methods=["GET"]),
        Route("/api/auth/login", endpoint=endpoint_auth_login, methods=["POST"]),
        Route("/api/auth/logout", endpoint=endpoint_auth_logout, methods=["POST"]),
        Route("/api/tts", endpoint=endpoint_tts, methods=["GET", "POST"]),
        Route("/api/tts/voices", endpoint=endpoint_tts_voices, methods=["GET"]),
        Route("/api/rooms", endpoint=endpoint_get_rooms, methods=["GET"]),
        Route("/api/rooms", endpoint=endpoint_create_room, methods=["POST"]),
        Route("/api/rooms/{room_name}/messages", endpoint=endpoint_get_messages, methods=["GET"]),
        Route("/api/rooms/{room_name}/messages", endpoint=endpoint_post_message, methods=["POST"]),
        Route("/api/messages/{message_id:int}/reactions", endpoint=endpoint_toggle_reaction, methods=["POST"]),
        Route("/api/decisions/{message_id:int}/resolve", endpoint=endpoint_resolve_decision, methods=["POST"]),
        Route("/api/polls", endpoint=endpoint_create_poll, methods=["POST"]),
        Route("/api/polls/{poll_id:int}", endpoint=endpoint_get_poll, methods=["GET"]),
        Route("/api/polls/{poll_id:int}/vote", endpoint=endpoint_cast_vote, methods=["POST"]),
        Route("/api/polls/{poll_id:int}/close", endpoint=endpoint_close_poll, methods=["POST"]),
        Route("/api/rooms/{room_name}/archive", endpoint=endpoint_archive_room, methods=["POST"]),
        Route("/api/rooms/{room_name}/unarchive", endpoint=endpoint_unarchive_room, methods=["POST"]),
        Route("/api/rooms/{room_name}/rotate-token", endpoint=endpoint_rotate_token, methods=["POST"]),
        Route("/api/rooms/{room_name}/password", endpoint=endpoint_change_password, methods=["POST"]),
        Route("/api/rooms/{room_name}/kick", endpoint=endpoint_kick_member, methods=["POST"]),
        Route("/api/rooms/{room_name}/audit", endpoint=endpoint_get_audit, methods=["GET"]),
        Route("/api/rooms/{room_name}/presence", endpoint=endpoint_get_presence, methods=["GET"]),
        Route("/api/agents", endpoint=endpoint_list_agents, methods=["GET"]),
        Route("/api/agents/register", endpoint=endpoint_self_register_agent, methods=["POST"]),
        Route("/api/agents", endpoint=endpoint_register_agent, methods=["POST"]),
        Route("/api/agents/{callsign}", endpoint=endpoint_delete_agent, methods=["DELETE"]),
        Route("/api/agents/{callsign}/rotate", endpoint=endpoint_rotate_agent_token, methods=["POST"]),
        Route("/api/admin/rooms", endpoint=endpoint_list_admin_rooms, methods=["GET"]),
        Route("/api/admin/rooms/{room_name}/password", endpoint=endpoint_admin_set_room_password, methods=["POST"]),
        Route("/api/rooms/{room_name}/tasks", endpoint=endpoint_get_tasks, methods=["GET"]),
        Route("/api/rooms/{room_name}/tasks", endpoint=endpoint_create_task, methods=["POST"]),
        Route("/api/tasks/{task_id:int}", endpoint=endpoint_update_task, methods=["PATCH", "POST"]),
        Route("/api/tasks/{task_id:int}", endpoint=endpoint_delete_task, methods=["DELETE"]),
        Route("/api/rooms/{room_name}/tasks/reorder", endpoint=endpoint_reorder_tasks, methods=["POST"]),
        Route("/api/rooms/{room_name}/log", endpoint=endpoint_download_log, methods=["GET"]),
        Route("/api/rooms/{room_name}/jsonl", endpoint=endpoint_download_jsonl, methods=["GET"]),
        Route("/api/rooms/{room_name}/stream", endpoint=endpoint_room_sse_stream, methods=["GET"]),
        WebSocketRoute("/ws/{room_name}", endpoint=websocket_room_endpoint),
        # If client sends POST /sse, handle via Streamable HTTP
        *([Route("/sse", endpoint=streamable_endpoint, methods=["POST"])] if streamable_endpoint else []),
        # Mount FastMCP SSE routes: GET /sse and /messages
        *mcp_sse.routes,
        # Mount FastMCP Streamable HTTP routes: /mcp
        *mcp_http.routes,
    ]

    middleware = [
        Middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts),
        Middleware(SecurityHardeningMiddleware),
    ]

    return Starlette(debug=False, routes=routes, middleware=middleware, lifespan=app_lifespan)
