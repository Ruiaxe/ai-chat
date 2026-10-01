import asyncio
from datetime import datetime
import json
import os
from pathlib import Path
import secrets
import sys
import threading
import time
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
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from starlette.websockets import WebSocket, WebSocketDisconnect

import edge_tts

from aichat.config import STATIC_DIR, DATA_DIR, get_git_commit
from aichat.mcp_server import (
    current_auth_token,
    current_principal,
    current_client_ip,
    check_register_rate_limit,
    reset_register_rate_limits,
    hub,
    mcp,
)

INDEX_HTML = STATIC_DIR / "index.html"
ADMIN_HTML = STATIC_DIR / "admin.html"
SERVER_START_TIME = time.time()


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


def is_trust_proxy_enabled() -> bool:
    """Returns True if the server is configured to trust reverse proxy headers like X-Forwarded-For."""
    return os.environ.get("AICHAT_TRUST_PROXY", "").lower() in ("1", "true", "yes")


def extract_client_ip(
    request: Request | None = None,
    scope: Scope | None = None,
    headers: Headers | None = None,
) -> str:
    """
    Extracts the client IP address safely across middleware, login, and registration.
    Only trusts X-Forwarded-For if AICHAT_TRUST_PROXY is explicitly enabled.
    Otherwise, strictly uses the direct connection socket IP (client host).
    """
    direct_ip = "127.0.0.1"
    raw_headers = headers

    if request is not None:
        if request.client and request.client.host:
            direct_ip = request.client.host
        if raw_headers is None:
            raw_headers = request.headers
    elif scope is not None:
        client = scope.get("client")
        if client and len(client) > 0 and client[0]:
            direct_ip = client[0]
        if raw_headers is None:
            raw_headers = Headers(scope=scope)

    if is_trust_proxy_enabled() and raw_headers is not None:
        xff = raw_headers.get("x-forwarded-for")
        if xff:
            first_ip = xff.split(",")[0].strip()
            if first_ip:
                return first_ip

    return direct_ip


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


class CleanShutdownMiddleware:
    """Outermost ASGI middleware suppressing duplicate response start errors and handling graceful disconnects during shutdown."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    def __getattr__(self, name: str) -> Any:
        return getattr(self.app, name)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def safe_send(message: Message) -> None:
            nonlocal response_started
            msg_type = message.get("type")
            if msg_type == "http.response.start":
                if response_started:
                    # Ignore duplicate response start during disconnect or server error fallback
                    return
                response_started = True
            try:
                await send(message)
            except (RuntimeError, asyncio.CancelledError):
                pass

        try:
            await self.app(scope, receive, safe_send)
        except (RuntimeError, asyncio.CancelledError):
            pass



class V3AuthenticationMiddleware:
    """
    ASGI middleware managing authentication context for AI Chat v3:
    1. Extracts Bearer token, session cookie, or agent token.
    2. Identifies and validates the principal in v3 storage.
    3. Populates current_principal and current_auth_token contextvars for FastMCP tools and async endpoints.
    4. Enforces mandatory password change (must_change_password) on all human endpoints except allowed auth routes.
    """
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        client_ip = extract_client_ip(scope=scope, headers=headers)
        current_client_ip.set(client_ip)

        auth_header = headers.get("authorization", "").strip()
        bearer_tok = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""

        # Parse cookie
        cookie_header = headers.get("cookie", "")
        cookies: dict[str, str] = {}
        if cookie_header:
            for item in cookie_header.split(";"):
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookies[k.strip()] = v.strip()
        cookie_session = cookies.get("human_session", "").strip()

        is_v3 = hasattr(hub.storage, "is_v3") and hub.storage.is_v3()

        token_candidate = (
            bearer_tok or
            headers.get("x-agent-token", "") or
            headers.get("x-member-token", "")
        ).strip()

        # Query params for ws or sse (v2 backward compatibility ONLY)
        if not is_v3:
            query_string = scope.get("query_string", b"").decode("latin-1")
            if not token_candidate and query_string:
                from urllib.parse import parse_qs
                qs = parse_qs(query_string)
                token_candidate = (
                    (qs.get("agent_token", [""])[0]) or
                    (qs.get("token", [""])[0]) or
                    (qs.get("human_token", [""])[0])
                ).strip()

        principal = None
        auth_token = None

        if is_v3:
            # Check human session first if cookie provided
            if cookie_session:
                principal = hub.storage.v3.authenticate_human_session(cookie_session)
                if principal:
                    auth_token = cookie_session

            # Check token candidate (agent token or human session)
            if not principal and token_candidate:
                # Try agent token
                ag, _ = hub.storage.v3.authenticate_agent_token(token_candidate)
                if ag:
                    principal = ag
                    auth_token = token_candidate
                else:
                    # Maybe it's a human session token passed via Authorization header
                    h_p = hub.storage.v3.authenticate_human_session(token_candidate)
                    if h_p:
                        principal = h_p
                        auth_token = token_candidate

            if principal:
                current_principal.set(principal)
                current_auth_token.set(auth_token)
                if principal.get("kind") == "agent":
                    hub.storage.v3.record_agent_activity(principal["name"])

                # Check must_change_password enforcement
                if scope["type"] == "http" and principal.get("kind") == "human" and principal.get("must_change_password") == 1:
                    path = scope.get("path", "")
                    # Allowed endpoints during mandatory password change
                    allowed_prefixes = (
                        "/api/auth/status",
                        "/api/auth/change-password",
                        "/api/auth/logout",
                        "/api/status",
                        "/static",
                    )
                    is_allowed = (path == "/" or any(path.startswith(p) for p in allowed_prefixes))
                    if not is_allowed:
                        response = JSONResponse(
                            {
                                "error": "Alteração de palavra-passe obrigatória antes de continuar.",
                                "must_change_password": True,
                            },
                            status_code=403,
                        )
                        await response(scope, receive, send)
                        return
        else:
            # v2 fallback: if human session or agent token, set current_auth_token
            if cookie_session and hub.verify_human_session(cookie_session):
                current_auth_token.set(hub.human_token)
            elif token_candidate:
                current_auth_token.set(token_candidate)

        await self.app(scope, receive, send)


def is_authenticated_human(request: Request) -> bool:
    """Verifies if request originates from authenticated human via valid session cookie, X-Human-Token header, Bearer token, or query param."""
    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        cookie_token = request.cookies.get("human_session", "").strip()
        auth_header = request.headers.get("Authorization", "").strip()
        bearer_tok = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
        header_token = request.headers.get("X-Human-Token", "").strip()

        for tok in (cookie_token, header_token, bearer_tok):
            if tok:
                p = hub.storage.v3.authenticate_human_session(tok)
                if p and p.get("kind") == "human" and p.get("status") == "active":
                    return True
        return False

    cookie_token = request.cookies.get("human_session", "").strip()
    if cookie_token and hub.verify_human_session(cookie_token):
        return True

    header_token = request.headers.get("X-Human-Token", "").strip()
    if header_token and secrets.compare_digest(header_token, hub.human_token):
        return True

    auth_header = request.headers.get("Authorization", "").strip()
    if auth_header.lower().startswith("bearer "):
        bearer_tok = auth_header[7:].strip()
        if bearer_tok and secrets.compare_digest(bearer_tok, hub.human_token):
            return True

    query_token = (request.query_params.get("human_token") or request.query_params.get("token") or "").strip()
    if query_token and secrets.compare_digest(query_token, hub.human_token):
        return True

    return False


def get_request_auth(request: Request) -> dict[str, Any] | None:
    """
    Verifies caller identity. Allows authenticated human supervisor or active agents with valid tokens.
    Returns:
        {"type": "human", "name": ..., "is_human": True, "token": ..., "principal": ...}
    or:
        {"type": "agent", "name": ident["callsign"], "is_human": False, "token": agent_tok, "ident": ident, "principal": ...}
    Returns None if unauthenticated or agent is inactive/revoked.
    """
    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        cookie_token = request.cookies.get("human_session", "").strip()
        auth_header = request.headers.get("Authorization", "").strip()
        bearer_tok = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
        header_human_tok = request.headers.get("X-Human-Token", "").strip()

        # Check session tokens for human (cookie or Bearer / header)
        for s_tok in (cookie_token, header_human_tok, bearer_tok):
            if s_tok:
                p = hub.storage.v3.authenticate_human_session(s_tok)
                if p and p.get("kind") == "human" and p.get("status") == "active":
                    return {
                        "type": "human",
                        "name": p["name"],
                        "is_human": True,
                        "token": s_tok,
                        "principal": p,
                        "id": p["id"],
                        "role": p.get("access_role", "user"),
                    }

        # Check agent token (Bearer or header) - strictly NO query params
        agent_tok = (
            bearer_tok or
            request.headers.get("x-agent-token", "") or
            request.headers.get("x-member-token", "")
        ).strip()

        if agent_tok:
            try:
                ident = hub.authenticate_agent(agent_tok)
                return {
                    "type": "agent",
                    "name": ident["callsign"],
                    "is_human": ident.get("is_human", False),
                    "token": agent_tok,
                    "ident": ident,
                    "principal": ident.get("principal"),
                    "id": ident.get("id"),
                    "role": ident.get("role", "agent"),
                }
            except Exception:
                return None
        return None

    # v2 fallback
    if is_authenticated_human(request):
        return {
            "type": "human",
            "name": hub.human_name,
            "is_human": True,
            "token": hub.human_token,
        }

    # Check for agent token
    auth_header = request.headers.get("Authorization", "").strip()
    bearer_tok = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""

    agent_tok = (
        request.headers.get("x-agent-token", "") or
        request.headers.get("x-member-token", "") or
        bearer_tok or
        request.query_params.get("agent_token", "") or
        request.query_params.get("member_token", "") or
        request.query_params.get("token", "")
    ).strip()

    if not agent_tok:
        return None

    try:
        ident = hub.authenticate_agent(agent_tok)
        return {
            "type": "agent",
            "name": ident["callsign"],
            "is_human": ident.get("is_human", False),
            "token": agent_tok,
            "ident": ident,
        }
    except Exception:
        return None


def _get_legacy_room_password(request: Request) -> str:
    """Extracts password from query params, or legacy X-Room-Password header if in v2 mode."""
    pwd = (request.query_params.get("password") or "").strip()
    if not pwd and not (hasattr(hub.storage, "is_v3") and hub.storage.is_v3()):
        pwd = (request.headers.get("x-room-password") or "").strip()
    return pwd


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
    auth = get_request_auth(request)
    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        if auth and auth.get("is_human"):
            p = auth.get("principal", {})
            return JSONResponse({
                "authenticated": True,
                "human_name": p.get("name") or auth.get("name") or "User",
                "role": p.get("access_role", "user"),
                "must_change_password": bool(p.get("must_change_password")),
            })
        return JSONResponse({
            "authenticated": False,
            "human_name": os.environ.get("AICHAT_HUMAN_NAME", "User"),
        })

    is_auth = is_authenticated_human(request)
    return JSONResponse({
        "authenticated": is_auth,
        "human_name": hub.human_name,
    })


async def endpoint_auth_login(request: Request) -> Response:
    """Authenticates human user with username/password or token, setting persistent session cookie."""
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    username = (data.get("username") or "").strip()
    token = (data.get("password") or data.get("token") or "").strip()

    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        if not username or not token:
            return JSONResponse({"error": "Credenciais inválidas"}, status_code=401)

        client_ip = extract_client_ip(request=request)

        principal, err = hub.storage.v3.authenticate_human(username, token, client_ip=client_ip)
        if not principal:
            if err and ("bloqueada" in err.lower() or "bloqueio" in err.lower()):
                return JSONResponse({"error": err}, status_code=429)
            return JSONResponse({"error": "Credenciais inválidas"}, status_code=401)

        session_token = hub.storage.v3.create_human_session(principal["id"])
        response = JSONResponse({
            "success": True,
            "message": "Autenticado com sucesso",
            "human_name": principal["name"],
            "role": principal.get("access_role", "user"),
            "must_change_password": bool(principal.get("must_change_password")),
        })
        set_human_session_cookie(response, session_token)
        return response

    if username:
        clean_user = "".join(c for c in username.lower() if c.isalnum())
        expected_user = "".join(c for c in hub.human_name.lower() if c.isalnum())
        if clean_user != expected_user and clean_user != "rui":
            return JSONResponse({"error": "Nome de utilizador incorreto. Acesso restrito ao supervisor Rui."}, status_code=401)

    if not token:
        return JSONResponse({"error": "A palavra-passe ou token de acesso é obrigatório"}, status_code=400)

    is_valid = secrets.compare_digest(token, hub.human_token) or hub.consume_one_time_code(token)
    if not is_valid:
        return JSONResponse({"error": "Palavra-passe / token inválido. Verifique a credencial de acesso humano."}, status_code=401)

    session_id = hub.create_human_session()
    response = JSONResponse({
        "success": True,
        "message": "Autenticado com sucesso",
        "human_name": hub.human_name,
    })
    set_human_session_cookie(response, session_id)
    return response


async def endpoint_auth_change_password(request: Request) -> Response:
    """Changes human user password and clears must_change_password."""
    auth = get_request_auth(request)
    if not auth or not auth.get("is_human"):
        return JSONResponse({"error": "Acesso negado: Autenticação de utilizador humano obrigatória."}, status_code=401)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    new_password = (data.get("new_password") or "").strip()
    if not new_password or len(new_password) < 8:
        return JSONResponse({"error": "A nova palavra-passe deve ter pelo menos 8 caracteres."}, status_code=400)

    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        principal = auth.get("principal")
        if not principal or "id" not in principal:
            return JSONResponse({"error": "Perfil de utilizador inválido"}, status_code=400)

        current_password = (data.get("current_password") or "").strip()
        if current_password:
            client_ip = request.client.host if request.client else "127.0.0.1"
            valid_p, err = hub.storage.v3.authenticate_human(principal["name"], current_password, client_ip=client_ip)
            if not valid_p:
                return JSONResponse({"error": "A palavra-passe atual está incorreta."}, status_code=403)

        success = hub.storage.v3.change_human_password(principal["id"], new_password)
        if not success:
            return JSONResponse({"error": "Falha ao alterar a palavra-passe."}, status_code=500)
        return JSONResponse({"success": True, "message": "Palavra-passe alterada com sucesso."})

    return JSONResponse({"success": True, "message": "Palavra-passe alterada com sucesso."})


async def endpoint_auth_logout(request: Request) -> Response:
    """Clears human session cookie and invalidates session."""
    cookie_token = request.cookies.get("human_session", "").strip()
    if cookie_token:
        if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
            hub.storage.v3.revoke_human_session(cookie_token)
        else:
            hub.invalidate_human_session(cookie_token)
    response = JSONResponse({"success": True, "message": "Sessão terminada"})
    response.delete_cookie(key="human_session", path="/")
    return response


async def endpoint_get_rooms(request: Request) -> Response:
    """Lists all rooms with metadata. Requires authenticated human supervisor or active agent."""
    auth = get_request_auth(request)
    if not auth:
        return JSONResponse(
            {"error": "Acesso negado: Autenticação obrigatória. Inicie sessão como humano ou forneça um token de agente ativo."},
            status_code=401
        )
    include_archived = request.query_params.get("include_archived", "true").lower() in ("true", "1")
    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        p = auth.get("principal")
        rooms = hub.storage.v3.list_rooms_for_principal(p, include_archived=include_archived)
        return JSONResponse(rooms)
    rooms = hub.list_rooms(include_archived=include_archived)
    return JSONResponse(rooms)


async def endpoint_create_room(request: Request) -> Response:
    """Creates a new room."""
    auth = get_request_auth(request)
    if not auth:
        return JSONResponse({"error": "Acesso negado: Autenticação obrigatória."}, status_code=401)

    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        p = auth.get("principal")
        if not hub.storage.v3.authorize(p, "admin"):
            return JSONResponse({"error": "Acesso negado: Apenas administradores podem criar salas."}, status_code=403)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    name = data.get("name", "").strip()
    topic = data.get("topic", "").strip()
    password = data.get("password", "")
    auto_generate_password = bool(data.get("auto_generate_password") or data.get("generate_token"))
    if auto_generate_password and not password:
        password = secrets.token_hex(8)

    if not name:
        return JSONResponse({"error": "Room name is required"}, status_code=400)

    try:
        if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
            p = auth.get("principal")
            room = hub.storage.v3.create_room(name=name, topic=topic, created_by=p.get("id") if p else None)
            return JSONResponse(room, status_code=201)

        room = hub.create_room(name=name, password=password, topic=topic)
        if password:
            room["password"] = password
            room["auto_generated"] = auto_generate_password
        return JSONResponse(room, status_code=201)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_get_messages(request: Request) -> Response:
    """Gets recent messages for a room. Requires authenticated human supervisor or active agent."""
    auth = get_request_auth(request)
    if not auth:
        return JSONResponse(
            {"error": "Acesso negado: Autenticação obrigatória. Inicie sessão como humano ou forneça um token de agente ativo."},
            status_code=401
        )

    room_name = request.path_params["room_name"]
    password = request.query_params.get("password", "")
    since_id = safe_int(request.query_params.get("since_id"), default=0, min_val=0)
    before_id = safe_int(request.query_params.get("before_id"), default=0, min_val=0)
    limit = safe_int(request.query_params.get("limit"), default=50, min_val=1, max_val=1000)

    try:
        if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
            p = auth.get("principal")
            room = hub.storage.v3.get_room(room_name)
            if not room:
                return JSONResponse({"error": f"Room '{room_name}' does not exist."}, status_code=404)
            if not hub.storage.v3.authorize(p, "read_room", {"room_id": room["id"]}):
                return JSONResponse({"error": "Access denied"}, status_code=403)
            messages = hub.storage.v3.get_messages(
                room["id"],
                since_id=since_id,
                before_id=before_id,
                limit=limit,
            )
            if messages and p and "id" in p:
                try:
                    hub.storage.v3.update_read_cursor(room["id"], p["id"], messages[-1]["id"])
                except Exception:
                    pass
            return JSONResponse(messages)

        effective_ht = hub.human_token if auth["is_human"] else ""

        # Record presence only for verified tokens or authenticated human session
        if auth["is_human"]:
            hub.record_presence(room_name, hub.human_name, client="web_ui", is_human=True)
        else:
            hub.record_presence(room_name, auth["name"], client="http_poll", is_human=auth.get("is_human", False))

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
    auth = get_request_auth(request)
    if not auth:
        return JSONResponse(
            {"error": "Acesso negado: Autenticação obrigatória. Inicie sessão como humano ou forneça um token de agente ativo."},
            status_code=401,
        )

    room_name = request.path_params["room_name"]
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    sender = (data.get("sender") or data.get("sender_name") or data.get("agent_name") or "").strip()
    content = data.get("content", "").strip()
    password = data.get("password", "")
    member_token = data.get("member_token", "") or (auth["token"] if not auth["is_human"] else "")
    to = data.get("to") or data.get("recipients") or "all"

    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        p = auth.get("principal")
        room = hub.storage.v3.get_room(room_name)
        if not room:
            return JSONResponse({"error": f"Room '{room_name}' does not exist."}, status_code=404)
        if room.get("is_archived"):
            return JSONResponse({"error": f"A sala '{room['name']}' foi arquivada e está em modo apenas de leitura."}, status_code=400)
        if not hub.storage.v3.authorize(p, "write_room", {"room_id": room["id"]}):
            return JSONResponse({"error": "Access denied"}, status_code=403)
        if not content:
            return JSONResponse({"error": "Content cannot be empty"}, status_code=400)

        role = "human" if p.get("kind") == "human" else "agent"
        clean_sender = p.get("display_name") or p.get("username") or p.get("name") or "Agent"

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
                    human_targets = [f"@{h['name']}" for h in humans] if humans else [{"target_kind": "principal", "target_id": 0, "target_name": "nobody"}]
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
                return JSONResponse({
                    "error": (
                        f"Proteção de ciclo ativada: limite de {max_cycles} mensagens consecutivas entre agentes "
                        f"atingido na sala '{room['name']}' sem intervenção humana. "
                        f"Conversação entre agentes pausada até intervenção do utilizador humano."
                    )
                }, status_code=400)

        try:
            msg = hub.storage.v3.add_message(
                room_name_or_id=room["id"],
                sender=clean_sender,
                role=role,
                content=content,
                is_verified=True,
                sender_id=p["id"],
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
            return JSONResponse(msg, status_code=201)
        except ValueError as ve:
            return JSONResponse({"error": str(ve)}, status_code=400)

    is_human = auth["is_human"]
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
        if not sender:
            sender = hub.human_name
    else:
        role = "agent"
        effective_ht = ""
        if not sender:
            sender = auth["name"]

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
            to=to,
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
    auth = get_request_auth(request)
    if not auth:
        return JSONResponse({"error": "Acesso negado: Autenticação obrigatória."}, status_code=401)

    room_name = request.path_params["room_name"]
    password = request.query_params.get("password", "")
    effective_ht = hub.human_token if auth["is_human"] else ""

    try:
        if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
            p = auth.get("principal")
            room = hub.storage.v3.get_room(room_name)
            if not room:
                return JSONResponse({"error": f"Room '{room_name}' not found"}, status_code=404)
            if not hub.storage.v3.authorize(p, "read_room", {"room_id": room["id"]}):
                return JSONResponse({"error": "Access denied: incorrect password"}, status_code=403)
        elif not hub.verify_room_access(room_name, password, requester_token=effective_ht):
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
    auth = get_request_auth(request)
    if not auth:
        return JSONResponse({"error": "Acesso negado: Autenticação obrigatória."}, status_code=401)

    room_name = request.path_params["room_name"]
    password = request.query_params.get("password", "")
    effective_ht = hub.human_token if auth["is_human"] else ""

    try:
        if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
            p = auth.get("principal")
            room = hub.storage.v3.get_room(room_name)
            if not room:
                return JSONResponse({"error": f"Room '{room_name}' not found"}, status_code=404)
            if not hub.storage.v3.authorize(p, "read_room", {"room_id": room["id"]}):
                return JSONResponse({"error": "Access denied: incorrect password"}, status_code=403)
        elif not hub.verify_room_access(room_name, password, requester_token=effective_ht):
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
    auth = get_request_auth(request)
    if not auth:
        return JSONResponse({"error": "Acesso negado: Autenticação obrigatória."}, status_code=401)

    room_name = request.path_params["room_name"]
    password = request.query_params.get("password", "")
    effective_ht = hub.human_token if auth["is_human"] else ""

    try:
        if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
            p = auth.get("principal")
            room = hub.storage.v3.get_room(room_name)
            if not room:
                return JSONResponse({"error": "Room not found"}, status_code=404)
            if not hub.storage.v3.authorize(p, "read_room", {"room_id": room["id"]}):
                return JSONResponse({"error": "Access denied"}, status_code=403)
        elif not hub.verify_room_access(room_name, password, requester_token=effective_ht):
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


async def _handle_wake_up_request(request: Request, room_name: str) -> Response:
    """Core handler for tokenless wake-up activity ping for Sentinel / background watchers."""
    try:
        timeout_val = float(request.query_params.get("timeout", 30.0))
    except (ValueError, TypeError):
        timeout_val = 30.0
    safe_timeout = max(0.5, min(timeout_val, 300.0))

    raw_since = request.query_params.get("since_seq")
    if raw_since is not None:
        try:
            since_seq = int(raw_since)
        except (ValueError, TypeError):
            since_seq = None
    else:
        since_seq = None

    # Optional watcher name for presence tracking
    watcher_name = request.query_params.get("name") or request.query_params.get("watcher_name") or ""
    if not watcher_name:
        auth = get_request_auth(request)
        if auth and auth.get("name"):
            watcher_name = auth["name"]
        else:
            watcher_name = "Sentinel"

    res = await hub.wait_for_activity(
        room_name=room_name,
        since_seq=since_seq,
        timeout_seconds=safe_timeout,
        watcher_name=watcher_name,
    )
    return JSONResponse(res)


async def endpoint_wake_up(request: Request) -> Response:
    """
    Public wake-up ping endpoint for Sentinel / background watchers (global or specified room).
    GET /api/wake-up?room=all&timeout=30&since_seq=0
    """
    room_name = request.query_params.get("room") or request.query_params.get("room_name") or "all"
    return await _handle_wake_up_request(request, room_name)


async def endpoint_room_wake_up(request: Request) -> Response:
    """
    Public room-specific wake-up ping endpoint for Sentinel / background watchers.
    GET /api/rooms/{room_name}/wake-up?timeout=30&since_seq=0
    """
    room_name = request.path_params.get("room_name", "all")
    return await _handle_wake_up_request(request, room_name)


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
    auth = get_request_auth(request)
    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        if not auth:
            return JSONResponse({"error": "Autenticação necessária"}, status_code=401)
        p = auth.get("principal")
        if not p or p.get("kind") != "human":
            return JSONResponse({"error": "Acesso negado: Apenas utilizadores humanos podem tomar decisões."}, status_code=403)
        message_id = int(request.path_params["message_id"])
        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
        decision = data.get("decision", "").strip()
        if not decision:
            return JSONResponse({"error": "Decision is required"}, status_code=400)
        room_name = data.get("room_name", "").strip()
        room = hub.storage.v3.get_room(room_name) if room_name else None
        if not room:
            msg_obj = hub.storage.v3.get_message_by_id(message_id)
            if msg_obj:
                room = hub.storage.v3.get_room_by_id(msg_obj["room_id"])
        if not room:
            return JSONResponse({"error": "Sala não encontrada"}, status_code=404)
        if not hub.storage.v3.authorize(p, "write_room", {"room_id": room["id"]}):
            return JSONResponse({"error": "Acesso negado: Sem permissão de escrita nesta sala."}, status_code=403)
        try:
            res = await hub.resolve_human_decision(
                message_id=message_id,
                room_name=room["name"],
                decision=decision,
                decider=p,
                human_token=hub.human_token,
            )
            return JSONResponse(res)
        except ValueError as ve:
            return JSONResponse({"error": str(ve)}, status_code=400)
        except PermissionError as pe:
            return JSONResponse({"error": str(pe)}, status_code=403)
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # v2 fallback
    if not is_authenticated_human(request):
        return JSONResponse({"error": "Acesso negado: Apenas o utilizador humano autenticado pode tomar decisões."}, status_code=403)
    message_id = int(request.path_params["message_id"])
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    room_name = data.get("room_name", "").strip()
    decision = data.get("decision", "").strip()
    decider = data.get("decider", hub.human_name).strip()
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
    auth = get_request_auth(request)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    room_name = data.get("room_name", "").strip()
    question = data.get("question", "").strip()
    options = data.get("options", [])
    if not question or len(options) < 2:
        return JSONResponse({"error": "Question and at least 2 options are required"}, status_code=400)

    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        if not auth:
            return JSONResponse({"error": "Autenticação necessária"}, status_code=401)
        p = auth.get("principal")
        room = hub.storage.v3.get_room(room_name)
        if not room:
            return JSONResponse({"error": f"Room '{room_name}' does not exist."}, status_code=404)
        if room.get("is_archived"):
            return JSONResponse({"error": f"A sala '{room['name']}' está arquivada."}, status_code=400)
        if not hub.storage.v3.authorize(p, "write_room", {"room_id": room["id"]}):
            return JSONResponse({"error": "Acesso negado: Sem permissão de escrita nesta sala."}, status_code=403)
        role = p.get("kind", "human")
        creator_name = p.get("name") or p.get("display_name")
        try:
            poll = await hub.create_poll(
                room_name=room_name,
                creator=creator_name,
                question=question,
                options=options,
                member_token=auth.get("token", "") if role == "agent" else "",
                human_token=hub.human_token if role == "human" else "",
                role=role,
            )
            return JSONResponse(poll, status_code=201)
        except ValueError as ve:
            return JSONResponse({"error": str(ve)}, status_code=400)
        except PermissionError as pe:
            return JSONResponse({"error": str(pe)}, status_code=403)
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # v2 fallback
    creator = data.get("creator", "Human").strip()
    member_token = data.get("member_token", "").strip()
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
    auth = get_request_auth(request)
    poll_id = int(request.path_params["poll_id"])
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)
    option_index = int(data.get("option_index", 0))

    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        if not auth:
            return JSONResponse({"error": "Autenticação necessária"}, status_code=401)
        p = auth.get("principal")
        poll = hub.storage.v3.get_poll(poll_id)
        if not poll:
            return JSONResponse({"error": f"Poll #{poll_id} not found"}, status_code=404)
        if not hub.storage.v3.authorize(p, "write_room", {"room_id": poll["room_id"]}):
            return JSONResponse({"error": "Acesso negado: Sem permissão nesta sala."}, status_code=403)
        try:
            poll_res = await hub.cast_vote(poll_id, p["id"], option_index)
            return JSONResponse(poll_res)
        except ValueError as ve:
            return JSONResponse({"error": str(ve)}, status_code=400)
        except PermissionError as pe:
            return JSONResponse({"error": str(pe)}, status_code=403)
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # v2 fallback
    voter = data.get("voter", "Human").strip()
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
    auth = get_request_auth(request)
    poll_id = int(request.path_params["poll_id"])
    try:
        data = await request.json()
    except Exception:
        data = {}

    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        if not auth:
            return JSONResponse({"error": "Autenticação necessária"}, status_code=401)
        p = auth.get("principal")
        poll = hub.storage.v3.get_poll(poll_id)
        if not poll:
            return JSONResponse({"error": f"Poll #{poll_id} not found"}, status_code=404)
        if not hub.storage.v3.authorize(p, "manage_poll", {"creator_id": poll["creator_id"]}):
            return JSONResponse({"error": "Apenas o criador da votação ou um administrador pode encerrá-la."}, status_code=403)
        try:
            poll_res = await hub.close_poll(
                poll_id=poll_id,
                closer=str(p["id"]),
                is_human=(p.get("kind") == "human"),
            )
            return JSONResponse(poll_res)
        except ValueError as ve:
            return JSONResponse({"error": str(ve)}, status_code=400)
        except PermissionError as pe:
            return JSONResponse({"error": str(pe)}, status_code=403)
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)

    # v2 fallback
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
    """Archives a room. Restricted strictly to admin in v3, or authenticated human in v2."""
    auth = get_request_auth(request)
    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        if not auth:
            return JSONResponse({"error": "Autenticação necessária"}, status_code=401)
        p = auth.get("principal")
        if not hub.storage.v3.authorize(p, "admin"):
            return JSONResponse({"error": "Apenas administradores podem arquivar salas."}, status_code=403)
    else:
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
    """Unarchives a room. Restricted strictly to admin in v3, or authenticated human in v2."""
    auth = get_request_auth(request)
    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        if not auth:
            return JSONResponse({"error": "Autenticação necessária"}, status_code=401)
        p = auth.get("principal")
        if not hub.storage.v3.authorize(p, "admin"):
            return JSONResponse({"error": "Apenas administradores podem desarquivar salas."}, status_code=403)
    else:
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
    password = data.get("password", "")

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

    old_password = data.get("old_password", "")
    new_password = data.get("new_password", "")
    auth = get_request_auth(request)
    p = auth.get("principal") if auth else None
    default_actor = (p.get("name") if p else auth.get("name")) if auth else (hub.human_name if is_authenticated_human(request) else "")
    actor_name = data.get("actor_name", "") or default_actor
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

    auth = get_request_auth(request)
    p = auth.get("principal") if auth else None
    default_actor = (p.get("name") if p else auth.get("name")) if auth else (hub.human_name if is_authenticated_human(request) else "")
    actor_name = data.get("actor_name", "") or default_actor
    supervisor_token = hub.human_token if is_authenticated_human(request) else data.get("supervisor_token", "")
    room_password = data.get("room_password", "")

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
    password = _get_legacy_room_password(request)
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
    """Returns real-time active listeners in a room. Requires authenticated human supervisor or active agent."""
    auth = get_request_auth(request)
    if not auth:
        return JSONResponse({"error": "Acesso negado: Autenticação obrigatória."}, status_code=401)
    room_name = request.path_params["room_name"]
    password = request.query_params.get("password", "")
    effective_ht = hub.human_token if auth["is_human"] else ""
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
    """Lists tasks in a room with optional filters. Requires authenticated human supervisor or active agent."""
    auth = get_request_auth(request)
    if not auth:
        return JSONResponse({"error": "Acesso negado: Autenticação obrigatória."}, status_code=401)
    room_name = request.path_params["room_name"]
    password = request.query_params.get("password", "")
    status = request.query_params.get("status")
    assignee = request.query_params.get("assignee")
    hide_completed = request.query_params.get("hide_completed", "").lower() in ("true", "1", "yes")
    effective_ht = hub.human_token if auth["is_human"] else ""

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
    auth = get_request_auth(request)
    if not auth:
        return JSONResponse({"error": "Acesso negado: Autenticação obrigatória."}, status_code=401)

    p = auth.get("principal")
    is_human = auth["is_human"]

    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        room = hub.storage.v3.get_room(room_name)
        if not room:
            return JSONResponse({"error": f"Room '{room_name}' does not exist."}, status_code=404)
        if not hub.storage.v3.authorize(p, "write_room", {"room_id": room["id"]}):
            return JSONResponse({"error": f"Acesso negado: sem permissão de escrita na sala '{room_name}'."}, status_code=403)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    title = (data.get("title") or "").strip()
    if not title:
        return JSONResponse({"error": "O título da tarefa é obrigatório."}, status_code=400)

    human_tok = hub.human_token if is_human else ""
    member_tok = (auth["token"] if not is_human else "") or data.get("member_token", "")
    human_name = (p.get("display_name") or p.get("name") if p else auth.get("name")) if is_human else ""
    creator = human_name if is_human else (auth.get("name") or data.get("created_by") or data.get("creator") or "Agent")

    parent_task_id = data.get("parent_task_id")
    if parent_task_id is not None:
        try:
            parent_task_id = int(parent_task_id) if int(parent_task_id) > 0 else None
        except Exception:
            parent_task_id = None
    dependencies = data.get("dependencies")
    if isinstance(dependencies, list):
        dependencies = [int(x) for x in dependencies if str(x).isdigit()]
    else:
        dependencies = None
    progress_percent = safe_int(data.get("progress_percent"), default=0, min_val=0)

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
            start_at=data.get("start_at", ""),
            due_at=data.get("due_at", ""),
            resource=data.get("resource", ""),
            member_token=member_tok,
            human_token=human_tok,
            password=data.get("password", ""),
            created_by=creator,
            parent_task_id=parent_task_id,
            dependencies=dependencies,
            progress_percent=progress_percent,
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

    auth = get_request_auth(request)
    if not auth:
        return JSONResponse({"error": "Acesso negado: Autenticação obrigatória."}, status_code=401)
    is_human = auth["is_human"]
    p = auth.get("principal")
    human_tok = hub.human_token if is_human else ""
    member_tok = (auth["token"] if not is_human else "") or data.get("member_token", "")
    human_name = (p.get("display_name") or p.get("name") if p else auth.get("name")) if is_human else ""
    actor = human_name if is_human else (auth.get("name") or data.get("actor") or data.get("assignee") or "")

    allowed_fields = [
        "title", "description", "status", "assignee", "waiting_for_agent",
        "priority", "order_index", "message_id", "uses_gpu", "gpu_est_min",
        "start_at", "due_at", "resource", "parent_task_id", "dependencies", "progress_percent",
    ]
    kwargs = {k: v for k, v in data.items() if k in allowed_fields}
    if "progress_percent" in kwargs and kwargs["progress_percent"] is not None:
        kwargs["progress_percent"] = safe_int(kwargs["progress_percent"], default=0, min_val=0)
    if "dependencies" in kwargs and isinstance(kwargs["dependencies"], list):
        kwargs["dependencies"] = [int(x) for x in kwargs["dependencies"] if str(x).isdigit()]

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
        if "não encontrada" in str(ve).lower():
            return JSONResponse({"error": str(ve)}, status_code=404)
        return JSONResponse({"error": str(ve)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_add_task_dependency(request: Request) -> Response:
    """Adds a prerequisite dependency to a task with cycle detection."""
    task_id = int(request.path_params["task_id"])
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    dep_id = data.get("depends_on_task_id") or data.get("dep_id")
    if not dep_id:
        return JSONResponse({"error": "O campo 'depends_on_task_id' é obrigatório."}, status_code=400)
    try:
        dep_id = int(dep_id)
    except Exception:
        return JSONResponse({"error": "ID de dependência inválido."}, status_code=400)

    try:
        res = await hub.add_task_dependency(task_id, dep_id)
        return JSONResponse(res, status_code=201)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_remove_task_dependency(request: Request) -> Response:
    """Removes a prerequisite dependency from a task."""
    task_id = int(request.path_params["task_id"])
    dep_id = int(request.path_params["dep_id"])
    try:
        res = await hub.remove_task_dependency(task_id, dep_id)
        return JSONResponse(res)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_delete_task(request: Request) -> Response:
    """Deletes a task."""
    task_id = int(request.path_params["task_id"])
    auth = get_request_auth(request)
    if not auth:
        return JSONResponse({"error": "Acesso negado: Autenticação obrigatória."}, status_code=401)
    is_human = auth["is_human"]
    p = auth.get("principal")
    human_tok = hub.human_token if is_human else ""
    member_tok = (auth["token"] if not is_human else "") or request.headers.get("x-member-token", "")
    password = request.query_params.get("password", "")
    human_name = (p.get("display_name") or p.get("name") if p else auth.get("name")) if is_human else ""
    actor = human_name if is_human else (auth.get("name") or "")

    try:
        res = await hub.delete_task(
            task_id=task_id,
            member_token=member_tok,
            human_token=human_tok,
            password=password,
            actor=human_name if is_human else "",
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


# --- Calendar & Resource Reservation Endpoints (v2.8) ---

def generate_ical_feed(events: list[dict[str, Any]], cal_name: str = "ai-chat Calendar") -> str:
    """Generates standard RFC 5545 iCalendar (.ics) format."""
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//ai-chat//Calendar v2.8//PT",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        f"X-WR-CALNAME:{cal_name}",
        "X-WR-TIMEZONE:UTC",
    ]
    for ev in events:
        lines.append("BEGIN:VEVENT")
        lines.append(f"UID:aichat-event-{ev['id']}@aichat")
        created_str = (ev.get("created_at") or datetime.now().isoformat()).replace("-", "").replace(":", "")[:15] + "Z"
        lines.append(f"DTSTAMP:{created_str}")

        start_raw = ev.get("start_at", "")
        if start_raw:
            try:
                s_dt = datetime.fromisoformat(start_raw)
                s_formatted = s_dt.strftime("%Y%m%dT%H%M%SZ")
            except Exception:
                s_formatted = start_raw.replace("-", "").replace(":", "")[:15] + "Z"
            lines.append(f"DTSTART:{s_formatted}")

        end_raw = ev.get("end_at", "")
        if end_raw:
            try:
                e_dt = datetime.fromisoformat(end_raw)
                e_formatted = e_dt.strftime("%Y%m%dT%H%M%SZ")
            except Exception:
                e_formatted = end_raw.replace("-", "").replace(":", "")[:15] + "Z"
            lines.append(f"DTEND:{e_formatted}")

        summary = ev.get("title", "Evento")
        if ev.get("resource"):
            summary += f" [{ev['resource']}]"
        lines.append(f"SUMMARY:{summary}")

        desc_parts = []
        if ev.get("description"):
            desc_parts.append(ev["description"])
        if ev.get("resource"):
            desc_parts.append(f"Recurso: {ev['resource']}")
        if ev.get("target_agent"):
            desc_parts.append(f"Agente Alvo: @{ev['target_agent']}")
        if ev.get("created_by"):
            desc_parts.append(f"Criado por: @{ev['created_by']}")
        desc = "\\n".join(desc_parts).replace("\r", "")
        lines.append(f"DESCRIPTION:{desc}")
        loc = ev.get("resource") or f"#{ev.get('room_name', 'geral')}"
        lines.append(f"LOCATION:{loc}")
        lines.append(f"STATUS:{'CONFIRMED' if ev.get('status') != 'cancelled' else 'CANCELLED'}")

        if ev.get("wake_on_start"):
            lines.extend([
                "BEGIN:VALARM",
                "TRIGGER:-PT5M",
                "ACTION:DISPLAY",
                f"DESCRIPTION:Lembrete: {summary}",
                "END:VALARM",
            ])
        lines.append("END:VEVENT")

    lines.append("END:VCALENDAR")
    return "\r\n".join(lines) + "\r\n"


async def endpoint_get_calendar_events(request: Request) -> Response:
    """Lists calendar events for room or all rooms."""
    auth = get_request_auth(request)
    if not auth:
        return JSONResponse(
            {"error": "Acesso negado: Autenticação obrigatória. Inicie sessão como humano ou forneça um token de agente ativo."},
            status_code=401,
        )
    is_human = auth["is_human"]
    effective_tok = hub.human_token if is_human else auth["token"]
    p = auth.get("principal") if auth else None

    room_name = request.path_params.get("room_name") or request.query_params.get("room_name") or request.query_params.get("room") or "all"
    start_from = request.query_params.get("start_from", "")
    start_to = request.query_params.get("start_to", "")
    resource = request.query_params.get("resource", "")
    status = request.query_params.get("status", "")
    include_completed = request.query_params.get("include_completed", "true").lower() in ("true", "1")
    hide_completed = request.query_params.get("hide_completed", "").lower() in ("true", "1")
    if hide_completed:
        include_completed = False
    filter_type = request.query_params.get("filter_type") or request.query_params.get("scope") or ""
    password = _get_legacy_room_password(request)

    try:
        events = hub.list_calendar_events(
            room_name=room_name,
            start_from=start_from,
            start_to=start_to,
            resource=resource,
            status=status,
            include_completed=include_completed,
            password=password,
            requester_token=effective_tok,
            filter_type=filter_type,
            requester_principal=p,
        )
        return JSONResponse({"status": "success", "count": len(events), "events": events})
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_create_calendar_event(request: Request) -> Response:
    """Creates a new calendar event with resource collision detection."""
    auth = get_request_auth(request)
    if not auth:
        return JSONResponse(
            {"error": "Acesso negado: Autenticação obrigatória."},
            status_code=401,
        )
    room_name = request.path_params.get("room_name") or "general"
    p = auth.get("principal") if auth else None
    is_human = auth["is_human"]

    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        room = hub.storage.v3.get_room(room_name)
        if not room:
            return JSONResponse({"error": f"Room '{room_name}' does not exist."}, status_code=404)
        if not hub.storage.v3.authorize(p, "write_room", {"room_id": room["id"]}):
            return JSONResponse({"error": f"Acesso negado: sem permissão de escrita na sala '{room_name}'."}, status_code=403)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    force = bool(data.get("force", False))
    if force and not is_human:
        return JSONResponse(
            {"error": "Acesso negado: Apenas utilizadores humanos podem forçar sobreposição de reservas de recursos (force=True)."},
            status_code=403,
        )

    title = (data.get("title") or "").strip()
    if not title:
        return JSONResponse({"error": "O título do evento é obrigatório."}, status_code=400)
    start_at = (data.get("start_at") or "").strip()
    if not start_at:
        return JSONResponse({"error": "A data/hora de início ('start_at') é obrigatória."}, status_code=400)

    human_tok = hub.human_token if is_human else ""
    member_tok = (auth["token"] if not is_human else "") or data.get("member_token", "")
    human_name = (p.get("display_name") or p.get("name") if p else auth.get("name")) if is_human else ""
    creator = human_name if is_human else (auth.get("name") or data.get("created_by") or "Agent")
    password = data.get("password", "")
    is_personal = bool(data.get("is_personal", False))

    try:
        event = await hub.create_calendar_event(
            room_name=room_name,
            title=title,
            start_at=start_at,
            end_at=data.get("end_at", ""),
            description=data.get("description", ""),
            event_type=data.get("event_type", "event"),
            task_id=data.get("task_id"),
            resource=data.get("resource", ""),
            target_agent=data.get("target_agent", ""),
            status=data.get("status", "scheduled"),
            wake_on_start=bool(data.get("wake_on_start", True)),
            wake_on_end=bool(data.get("wake_on_end", False)),
            member_token=member_tok,
            human_token=human_tok,
            password=password,
            created_by=creator,
            force=force,
            is_personal=is_personal,
        )
        return JSONResponse({"status": "success", "event": event}, status_code=201)
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        err_msg = str(ve)
        status_code = 409 if ("Conflito" in err_msg or "já está reservado" in err_msg) else 400
        conflicts = hub.storage.check_resource_conflicts(
            resource=data.get("resource", ""),
            start_at=start_at,
            end_at=data.get("end_at", ""),
        )
        return JSONResponse({"error": err_msg, "conflicts": conflicts}, status_code=status_code)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_update_calendar_event(request: Request) -> Response:
    """Updates a calendar event."""
    auth = get_request_auth(request)
    if not auth:
        return JSONResponse(
            {"error": "Acesso negado: Autenticação obrigatória."},
            status_code=401,
        )
    event_id = int(request.path_params["event_id"])
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    is_human = auth["is_human"]
    human_tok = hub.human_token if is_human else ""
    member_tok = data.get("member_token", "") or (auth["token"] if not is_human else "")
    password = data.get("password", "")
    force = bool(data.get("force", False))

    allowed_fields = [
        "title", "description", "start_at", "end_at", "event_type",
        "task_id", "resource", "target_agent", "status", "wake_on_start", "wake_on_end"
    ]
    kwargs = {k: v for k, v in data.items() if k in allowed_fields}

    try:
        updated = await hub.update_calendar_event(
            event_id=event_id,
            member_token=member_tok,
            human_token=human_tok,
            password=password,
            force=force,
            **kwargs,
        )
        return JSONResponse({"status": "success", "event": updated})
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        err_msg = str(ve)
        status_code = 409 if ("Conflito" in err_msg or "já está reservado" in err_msg) else (404 if "não encontrado" in err_msg.lower() else 400)
        return JSONResponse({"error": err_msg}, status_code=status_code)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_delete_calendar_event(request: Request) -> Response:
    """Deletes a calendar event."""
    auth = get_request_auth(request)
    if not auth:
        return JSONResponse(
            {"error": "Acesso negado: Autenticação obrigatória."},
            status_code=401,
        )
    event_id = int(request.path_params["event_id"])
    is_human = auth["is_human"]
    human_tok = hub.human_token if is_human else ""
    is_v3 = hasattr(hub.storage, "is_v3") and hub.storage.is_v3()
    member_tok = ("" if is_v3 else request.query_params.get("member_token", "")) or (auth["token"] if not is_human else "")
    password = request.query_params.get("password", "")

    try:
        res = await hub.delete_calendar_event(
            event_id=event_id,
            member_token=member_tok,
            human_token=human_tok,
            password=password,
        )
        return JSONResponse(res)
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_get_calendar_resources(request: Request) -> Response:
    """Returns hardware resource availability."""
    auth = get_request_auth(request)
    if not auth:
        return JSONResponse(
            {"error": "Acesso negado: Autenticação obrigatória."},
            status_code=401,
        )
    raw_resources = request.query_params.get("resources", "")
    res_list = [r.strip() for r in raw_resources.split(",") if r.strip()] if raw_resources else None
    status = hub.get_resource_status(resources=res_list)
    return JSONResponse({"status": "success", "resources": status})


async def endpoint_get_calendar_ics(request: Request) -> Response:
    """Exports events as standard RFC 5545 iCalendar (.ics) format."""
    auth = get_request_auth(request)
    if not auth:
        return PlainTextResponse("Acesso negado: Autenticação obrigatória.", status_code=401)
    is_human = auth["is_human"]
    effective_tok = hub.human_token if is_human else auth["token"]
    password = request.query_params.get("password", "")

    room_name = request.path_params.get("room_name") or request.query_params.get("room_name") or request.query_params.get("room") or "all"
    try:
        events = hub.list_calendar_events(
            room_name=room_name,
            include_completed=True,
            password=password,
            requester_token=effective_tok,
        )
    except PermissionError as pe:
        return PlainTextResponse(str(pe), status_code=403)
    except ValueError as ve:
        return PlainTextResponse(str(ve), status_code=404)

    ics_body = generate_ical_feed(events, cal_name=f"ai-chat #{room_name}")
    return Response(
        content=ics_body,
        media_type="text/calendar; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="aichat_{room_name}_calendar.ics"'},
    )


# --- Agent Registry Management Endpoints (v2.7) ---

async def endpoint_list_agents(request: Request) -> Response:
    """Lists registered agents. Requires authenticated human supervisor or active agent."""
    auth = get_request_auth(request)
    if not auth:
        return JSONResponse({"error": "Acesso negado: Autenticação obrigatória."}, status_code=401)
    agents = hub.list_registered_agents(requester_token=hub.human_token if auth["is_human"] else "")
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
    client_ip = extract_client_ip(request=request)
    if not check_register_rate_limit(client_ip):
        return JSONResponse(
            {"status": "error", "error": "Demasiados pedidos de registo. Limite de 5 por hora atingido."},
            status_code=429,
        )

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    callsign = (data.get("callsign") or data.get("name") or "").strip()
    description = (data.get("description") or data.get("role") or "").strip()
    if not callsign:
        return JSONResponse({"error": "callsign is required"}, status_code=400)

    try:
        res = hub.self_register_agent(callsign=callsign, description=description)
        return JSONResponse({"status": "success", "agent": res, **res}, status_code=201)
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


async def endpoint_update_agent_status(request: Request) -> Response:
    """Allows authenticated supervisor Rui to activate or deactivate an agent."""
    if not is_authenticated_human(request):
        return JSONResponse({"error": "Acesso negado: Apenas o supervisor humano Rui pode alterar o estado de agentes."}, status_code=403)
    callsign = request.path_params["callsign"]
    try:
        data = await request.json()
    except Exception:
        data = {}
    status = data.get("status", "").strip().lower()
    if not status:
        return JSONResponse({"error": "Campo 'status' é obrigatório ('active' ou 'inactive')."}, status_code=400)
    try:
        hub.update_agent_status_admin(callsign=callsign, status=status, supervisor_token=hub.human_token)
        return JSONResponse({"status": "success", "callsign": callsign, "agent_status": status})
    except (ValueError, PermissionError) as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# --- Admin Console Endpoints (Phase 3) ---

def require_admin(request: Request) -> tuple[dict[str, Any] | None, Response | None]:
    """
    Validates that the request comes from an authenticated human admin.
    Returns (principal, None) on success, or (None, Response) on failure (401 or 403).
    """
    if not (hasattr(hub.storage, "is_v3") and hub.storage.is_v3()):
        if not is_authenticated_human(request):
            return None, JSONResponse({"error": "Acesso restrito ao supervisor"}, status_code=403)
        return {"id": 1, "name": hub.human_name, "kind": "human", "access_role": "admin"}, None

    auth = get_request_auth(request)
    if not auth:
        return None, JSONResponse({"error": "Autenticação necessária"}, status_code=401)

    principal = auth.get("principal") or auth
    if not hub.storage.v3.authorize(principal, "admin"):
        return None, JSONResponse({"error": "Acesso restrito a administradores"}, status_code=403)

    return principal, None


async def endpoint_admin_ui(request: Request) -> Response:
    """Serves the Admin Console SPA to authenticated human admins."""
    principal, err = require_admin(request)
    if err:
        if "text/html" in request.headers.get("accept", "") and err.status_code == 401:
            return RedirectResponse(url="/?login=1", status_code=303)
        return err
    if ADMIN_HTML.exists():
        return HTMLResponse(ADMIN_HTML.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Consola de Administração</h1><p>admin.html não encontrado</p>", status_code=404)


async def endpoint_admin_me(request: Request) -> Response:
    """Returns current admin profile information."""
    principal, err = require_admin(request)
    if err:
        return err
    return JSONResponse({
        "status": "success",
        "principal": {
            "id": principal.get("id"),
            "name": principal.get("name"),
            "display_name": principal.get("display_name"),
            "kind": principal.get("kind"),
            "role": principal.get("access_role", "admin"),
        }
    })


async def endpoint_admin_list_humans(request: Request) -> Response:
    """Lists all human principals."""
    principal, err = require_admin(request)
    if err:
        return err
    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        humans = hub.storage.v3.list_humans()
        return JSONResponse({"status": "success", "count": len(humans), "humans": humans, "users": humans})
    return JSONResponse({"status": "success", "count": 1, "humans": [{"id": 1, "name": hub.human_name, "access_role": "admin"}]})


async def endpoint_admin_create_human(request: Request) -> Response:
    """Creates a new human user."""
    principal, err = require_admin(request)
    if err:
        return err
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON inválido"}, status_code=400)
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    display_name = (data.get("display_name") or "").strip()
    access_role = (data.get("access_role") or "user").strip()
    must_change = int(data.get("must_change_password", 1))

    if not username:
        return JSONResponse({"error": "Nome de utilizador é obrigatório"}, status_code=400)
    if not password:
        return JSONResponse({"error": "Password é obrigatória"}, status_code=400)
    if access_role not in ("admin", "user"):
        return JSONResponse({"error": "Papel de acesso deve ser 'admin' ou 'user'"}, status_code=400)

    try:
        new_id = hub.storage.v3.create_human(
            username=username,
            password=password,
            display_name=display_name,
            access_role=access_role,
            must_change_password=must_change,
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
        )
        return JSONResponse({
            "status": "success",
            "id": new_id,
            "username": username,
            "display_name": display_name or username,
            "access_role": access_role,
        }, status_code=201)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


async def endpoint_admin_update_human(request: Request) -> Response:
    """Updates a human user's details, role, status, or resets password."""
    principal, err = require_admin(request)
    if err:
        return err
    principal_id = safe_int(request.path_params.get("principal_id"))
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON inválido"}, status_code=400)
    try:
        updated = hub.storage.v3.update_human(
            principal_id=principal_id,
            display_name=data.get("display_name"),
            access_role=data.get("access_role"),
            status=data.get("status"),
            reset_password=data.get("reset_password") or data.get("password"),
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
        )
        return JSONResponse({"status": "success", "user": updated, "human": updated})
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_admin_delete_human(request: Request) -> Response:
    """Deletes a human user, protecting the last active admin."""
    principal, err = require_admin(request)
    if err:
        return err
    principal_id = safe_int(request.path_params.get("principal_id"))
    try:
        hub.storage.v3.delete_principal(
            principal_id=principal_id,
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
        )
        return JSONResponse({"status": "success", "deleted_id": principal_id})
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_admin_list_agents(request: Request) -> Response:
    """Lists all agents with roles and credential hints."""
    principal, err = require_admin(request)
    if err:
        return err
    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        agents = hub.storage.v3.list_agents()
        return JSONResponse({"status": "success", "count": len(agents), "agents": agents})
    return JSONResponse({"status": "success", "count": 0, "agents": []})


async def endpoint_admin_create_agent(request: Request) -> Response:
    """Creates a new agent with credential. Plain token is returned once and never logged."""
    principal, err = require_admin(request)
    if err:
        return err
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON inválido"}, status_code=400)
    callsign = (data.get("callsign") or data.get("name") or "").strip()
    if not callsign:
        return JSONResponse({"error": "Callsign do agente é obrigatório"}, status_code=400)
    display_name = (data.get("display_name") or "").strip()
    role_key = (data.get("role_key") or "").strip() or None
    default_role_id = data.get("default_role_id")
    status = (data.get("status") or "active").strip()
    is_system = int(data.get("is_system", 0))

    try:
        pid, raw_token = hub.storage.v3.create_agent(
            callsign=callsign,
            display_name=display_name,
            role_key=role_key,
            is_system=is_system,
            status=status,
            default_role_id=default_role_id,
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
        )
        hint = raw_token[-4:]
        return JSONResponse({
            "status": "success",
            "id": pid,
            "callsign": callsign,
            "display_name": display_name or callsign,
            "token": raw_token,
            "token_hint": hint,
        }, status_code=201)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


async def endpoint_admin_update_agent(request: Request) -> Response:
    """Updates agent display name, status, or default role."""
    principal, err = require_admin(request)
    if err:
        return err
    principal_id = safe_int(request.path_params.get("principal_id"))
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON inválido"}, status_code=400)
    try:
        updated = hub.storage.v3.update_agent(
            principal_id=principal_id,
            display_name=data.get("display_name"),
            status=data.get("status"),
            default_role_id=data.get("default_role_id"),
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
        )
        return JSONResponse({"status": "success", "agent": updated})
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_admin_rotate_agent_token(request: Request) -> Response:
    """Rotates an agent's token. Plain token returned once, never logged."""
    principal, err = require_admin(request)
    if err:
        return err
    principal_id = safe_int(request.path_params.get("principal_id"))
    try:
        data = await request.json()
    except Exception:
        data = {}
    revoke_prev = bool(data.get("revoke_previous", True))
    try:
        token, hint = hub.storage.v3.rotate_agent_token(
            principal_id=principal_id,
            revoke_previous=revoke_prev,
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
        )
        return JSONResponse({
            "status": "success",
            "principal_id": principal_id,
            "token": token,
            "token_hint": hint,
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_admin_revoke_agent_token(request: Request) -> Response:
    """Revokes an agent's credential by token hint or ID."""
    principal, err = require_admin(request)
    if err:
        return err
    principal_id = safe_int(request.path_params.get("principal_id"))
    try:
        data = await request.json()
    except Exception:
        data = {}
    hint = data.get("token_hint")
    credential_id = data.get("credential_id")
    try:
        ok = hub.storage.v3.revoke_agent_credential(
            principal_id=principal_id,
            hint=hint,
            credential_id=credential_id,
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
        )
        if not ok:
            return JSONResponse({"error": "Credencial não encontrada ou já revogada"}, status_code=404)
        return JSONResponse({"status": "success", "revoked": True})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_admin_delete_agent(request: Request) -> Response:
    """Deletes an agent (including pending registrations) in admin console."""
    principal, err = require_admin(request)
    if err:
        return err
    principal_id = safe_int(request.path_params.get("principal_id"))
    try:
        hub.storage.v3.delete_principal(
            principal_id=principal_id,
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
        )
        return JSONResponse({"status": "success", "deleted_id": principal_id})
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_admin_list_rooms(request: Request) -> Response:
    """Lists all rooms including archived ones for admin."""
    principal, err = require_admin(request)
    if err:
        return err
    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        rooms = hub.storage.v3.list_rooms(include_archived=True)
        return JSONResponse({"status": "success", "count": len(rooms), "rooms": rooms})
    rooms = hub.storage.list_rooms(include_archived=True, include_passwords=True)
    return JSONResponse({"status": "success", "count": len(rooms), "rooms": rooms})

endpoint_list_admin_rooms = endpoint_admin_list_rooms


async def endpoint_admin_create_room(request: Request) -> Response:
    """Creates a new room."""
    principal, err = require_admin(request)
    if err:
        return err
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON inválido"}, status_code=400)
    name = (data.get("name") or "").strip()
    topic = (data.get("topic") or "").strip()
    if not name:
        return JSONResponse({"error": "Nome da sala é obrigatório"}, status_code=400)
    try:
        room = hub.storage.v3.create_room(
            name=name,
            topic=topic,
            created_by_id=principal.get("id"),
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
        )
        return JSONResponse({"status": "success", "room": room}, status_code=201)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


async def endpoint_admin_archive_room(request: Request) -> Response:
    """Archives a room."""
    principal, err = require_admin(request)
    if err:
        return err
    room_spec = request.path_params.get("room_id") or request.path_params.get("room_name")
    if str(room_spec).isdigit():
        room_spec = int(room_spec)
    try:
        ok = hub.storage.v3.archive_room(
            room_spec,
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
        )
        if not ok:
            return JSONResponse({"error": "Sala não encontrada"}, status_code=404)
        return JSONResponse({"status": "success", "archived": True})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_admin_unarchive_room(request: Request) -> Response:
    """Unarchives a room."""
    principal, err = require_admin(request)
    if err:
        return err
    room_spec = request.path_params.get("room_id") or request.path_params.get("room_name")
    if str(room_spec).isdigit():
        room_spec = int(room_spec)
    try:
        ok = hub.storage.v3.unarchive_room(
            room_spec,
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
        )
        if not ok:
            return JSONResponse({"error": "Sala não encontrada"}, status_code=404)
        return JSONResponse({"status": "success", "unarchived": True})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_admin_list_room_members(request: Request) -> Response:
    """Lists members and permissions of a room."""
    principal, err = require_admin(request)
    if err:
        return err
    room_spec = request.path_params.get("room_id") or request.path_params.get("room_name")
    if str(room_spec).isdigit():
        room_spec = int(room_spec)
    room = hub.storage.v3.get_room(room_spec)
    if not room:
        return JSONResponse({"error": "Sala não encontrada"}, status_code=404)
    try:
        members = hub.storage.v3.list_room_members(room["id"])
        return JSONResponse({"status": "success", "room_id": room["id"], "room_name": room["name"], "members": members})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_admin_grant_room_access(request: Request) -> Response:
    """Grants or updates room access for a principal (with role and can_write)."""
    principal, err = require_admin(request)
    if err:
        return err
    room_spec = request.path_params.get("room_id") or request.path_params.get("room_name")
    if str(room_spec).isdigit():
        room_spec = int(room_spec)
    room = hub.storage.v3.get_room(room_spec)
    if not room:
        return JSONResponse({"error": "Sala não encontrada"}, status_code=404)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON inválido"}, status_code=400)
    principal_id = safe_int(data.get("principal_id"))
    role_id = data.get("role_id")
    can_write = 1 if data.get("can_write", 1) else 0
    try:
        hub.storage.v3.grant_room_access(
            room_id=room["id"],
            principal_id=principal_id,
            role_id=role_id,
            can_write=can_write,
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
        )
        return JSONResponse({"status": "success", "room_id": room["id"], "principal_id": principal_id, "can_write": can_write})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


async def endpoint_admin_revoke_room_access(request: Request) -> Response:
    """Revokes room access for a principal."""
    principal, err = require_admin(request)
    if err:
        return err
    room_spec = request.path_params.get("room_id") or request.path_params.get("room_name")
    if str(room_spec).isdigit():
        room_spec = int(room_spec)
    principal_id = safe_int(request.path_params.get("principal_id"))
    try:
        ok = hub.storage.v3.revoke_room_access(
            room_id=room_spec,
            principal_id=principal_id,
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
        )
        return JSONResponse({"status": "success", "revoked": ok})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_admin_patch_room_access(request: Request) -> Response:
    """Updates role and/or write permission for an existing member of a room."""
    principal, err = require_admin(request)
    if err:
        return err
    room_spec = request.path_params.get("room_id") or request.path_params.get("room_name")
    if str(room_spec).isdigit():
        room_spec = int(room_spec)
    room = hub.storage.v3.get_room(room_spec)
    if not room:
        return JSONResponse({"error": "Sala não encontrada"}, status_code=404)
    principal_id = safe_int(request.path_params.get("principal_id"))

    try:
        data = await request.json()
        if not isinstance(data, dict):
            return JSONResponse({"error": "JSON deve ser um objeto"}, status_code=400)
    except Exception:
        return JSONResponse({"error": "JSON inválido"}, status_code=400)

    from aichat.storage_v3 import _UNSET
    role_id = data["role_id"] if "role_id" in data else _UNSET
    can_write = data["can_write"] if "can_write" in data else _UNSET

    try:
        res = hub.storage.v3.update_room_access(
            room_id=room["id"],
            principal_id=principal_id,
            role_id=role_id,
            can_write=can_write,
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
        )
        return JSONResponse({"status": "success", **res})
    except KeyError as e:
        return JSONResponse({"error": str(e)}, status_code=404)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_admin_bulk_grant_room_access(request: Request) -> Response:
    """Bulk updates room access matrix."""
    principal, err = require_admin(request)
    if err:
        return err
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON inválido"}, status_code=400)
    grants = data.get("grants") or []
    if not isinstance(grants, list):
        return JSONResponse({"error": "'grants' deve ser uma lista"}, status_code=400)
    try:
        count = hub.storage.v3.bulk_grant_room_access(
            grants=grants,
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
        )
        return JSONResponse({"status": "success", "count": count})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


async def endpoint_admin_rooms_matrix(request: Request) -> Response:
    """Returns rooms x principals access matrix for admins."""
    principal, err = require_admin(request)
    if err:
        return err

    include_archived = request.query_params.get("include_archived", "0").lower() in ("1", "true")
    include_humans = request.query_params.get("include_humans", "0").lower() in ("1", "true")

    if not (hasattr(hub.storage, "is_v3") and hub.storage.is_v3()):
        return JSONResponse({"status": "error", "error": "Apenas suportado na v3"}, status_code=400)

    matrix = hub.storage.v3.get_access_matrix(
        include_archived=include_archived,
        include_humans=include_humans,
    )
    return JSONResponse({"status": "success", **matrix})


async def endpoint_admin_list_roles(request: Request) -> Response:
    """Lists all agent roles."""
    principal, err = require_admin(request)
    if err:
        return err
    roles = hub.storage.v3.list_roles()
    return JSONResponse({"status": "success", "count": len(roles), "roles": roles})


async def endpoint_admin_create_role(request: Request) -> Response:
    """Creates a new agent role."""
    principal, err = require_admin(request)
    if err:
        return err
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON inválido"}, status_code=400)
    role_key = (data.get("role_key") or "").strip()
    display_name = (data.get("display_name") or "").strip()
    description = (data.get("description") or "").strip()
    reminder_text = (data.get("reminder_text") or "").strip()

    if not role_key or not display_name:
        return JSONResponse({"error": "role_key e display_name são obrigatórios"}, status_code=400)

    try:
        role = hub.storage.v3.create_role(
            role_key=role_key,
            display_name=display_name,
            description=description,
            reminder_text=reminder_text,
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
        )
        return JSONResponse({"status": "success", "role": role}, status_code=201)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


async def endpoint_admin_update_role(request: Request) -> Response:
    """Updates an agent role's display name, description, or reminder_text."""
    principal, err = require_admin(request)
    if err:
        return err
    role_id = safe_int(request.path_params.get("role_id"))
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "JSON inválido"}, status_code=400)
    try:
        role = hub.storage.v3.update_role(
            role_id=role_id,
            display_name=data.get("display_name"),
            description=data.get("description"),
            reminder_text=data.get("reminder_text"),
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
        )
        return JSONResponse({"status": "success", "role": role})
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_admin_delete_role(request: Request) -> Response:
    """Deletes an agent role."""
    principal, err = require_admin(request)
    if err:
        return err
    role_id = safe_int(request.path_params.get("role_id"))
    try:
        ok = hub.storage.v3.delete_role(
            role_id=role_id,
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
        )
        if not ok:
            return JSONResponse({"error": "Papel não encontrado"}, status_code=404)
        return JSONResponse({"status": "success", "deleted_id": role_id})
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_admin_list_audit_log(request: Request) -> Response:
    """Queries the audit log with filters and pagination."""
    principal, err = require_admin(request)
    if err:
        return err
    actor_id_param = request.query_params.get("actor_id")
    actor_id = safe_int(actor_id_param) if actor_id_param else None
    action = request.query_params.get("action")
    room_id_param = request.query_params.get("room_id")
    room_id = safe_int(room_id_param) if room_id_param else None
    target_type = request.query_params.get("target_type")
    limit = safe_int(request.query_params.get("limit", 50), default=50, min_val=1, max_val=200)
    offset = safe_int(request.query_params.get("offset", 0), default=0, min_val=0)

    try:
        res = hub.storage.v3.list_audit_log(
            limit=limit,
            offset=offset,
            actor_id=actor_id,
            action=action,
            room_id=room_id,
            target_type=target_type,
        )
        return JSONResponse({"status": "success", **res})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_admin_approve_agent(request: Request) -> Response:
    """Approves a pending agent and emits its initial token once."""
    principal, err = require_admin(request)
    if err:
        return err
    if not (hasattr(hub.storage, "is_v3") and hub.storage.is_v3()):
        return JSONResponse({"status": "error", "error": "Apenas suportado na v3"}, status_code=400)
    agent_id = request.path_params.get("id")
    try:
        pid = int(agent_id)
        res = hub.storage.v3.approve_agent(pid, actor_id=principal.get("id"), actor_name=principal.get("name", "admin"))
        return JSONResponse(res, status_code=200)
    except Exception as e:
        return JSONResponse({"status": "error", "error": str(e)}, status_code=400)


async def endpoint_admin_update_agent_wake_profile(request: Request) -> Response:
    """Updates an agent's harness and wake_mode profile."""
    principal, err = require_admin(request)
    if err:
        return err
    if not (hasattr(hub.storage, "is_v3") and hub.storage.is_v3()):
        return JSONResponse({"status": "error", "error": "Apenas suportado na v3"}, status_code=400)
    agent_id = request.path_params.get("id")
    try:
        data = await request.json()
        harness = data.get("harness")
        wake_mode = data.get("wake_mode")
        res = hub.storage.v3.update_agent_wake_profile(
            int(agent_id),
            harness=harness,
            wake_mode=wake_mode,
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
        )
        return JSONResponse({"status": "success", "agent": res}, status_code=200)
    except Exception as e:
        return JSONResponse({"status": "error", "error": str(e)}, status_code=400)


async def endpoint_admin_get_settings(request: Request) -> Response:
    """Returns configured system settings/thresholds."""
    principal, err = require_admin(request)
    if err:
        return err
    if not (hasattr(hub.storage, "is_v3") and hub.storage.is_v3()):
        return JSONResponse({"t_idle_seconds": 600, "t_unread_seconds": 600, "max_wake_timeout": 1500})
    settings = hub.storage.v3.get_system_thresholds()
    return JSONResponse({"status": "success", "settings": settings})


async def endpoint_admin_patch_settings(request: Request) -> Response:
    """Updates system thresholds (t_idle_seconds, t_unread_seconds, max_wake_timeout)."""
    principal, err = require_admin(request)
    if err:
        return err
    if not (hasattr(hub.storage, "is_v3") and hub.storage.is_v3()):
        return JSONResponse({"status": "error", "error": "Apenas suportado na v3"}, status_code=400)
    try:
        data = await request.json()
        if "t_idle_seconds" in data:
            hub.storage.v3.set_setting("t_idle_seconds", str(int(data["t_idle_seconds"])))
        if "t_unread_seconds" in data:
            hub.storage.v3.set_setting("t_unread_seconds", str(int(data["t_unread_seconds"])))
        if "max_wake_timeout" in data:
            hub.storage.v3.set_setting("max_wake_timeout", str(int(data["max_wake_timeout"])))
        hub.storage.v3.log_audit(
            actor_id=principal.get("id"),
            actor_name=principal.get("name", "admin"),
            action="update_settings",
            target_type="system_settings",
            details=f"Atualizou definições de wake: {data}",
        )
        return JSONResponse({"status": "success", "settings": hub.storage.v3.get_system_thresholds()})
    except Exception as e:
        return JSONResponse({"status": "error", "error": str(e)}, status_code=400)


async def endpoint_admin_system(request: Request) -> Response:
    """Returns system, database, uptime, and connected agents status for admins."""
    principal, err = require_admin(request)
    if err:
        return err

    from datetime import timezone
    from aichat.storage import check_schema_version, get_db_origin

    current_db = hub.storage.db_path.resolve()
    expected_db = (DATA_DIR / "chat_v3.db").resolve()
    schema_v = check_schema_version(current_db)
    uptime_sec = int(time.time() - SERVER_START_TIME)
    db_origin = get_db_origin(current_db)

    connected_agents = []
    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        agents = hub.storage.v3.list_agents()
        connected_agents = [
            {
                "id": a["id"],
                "name": a["name"],
                "display_name": a.get("display_name") or a["name"],
                "last_activity_at": a.get("last_activity_at"),
            }
            for a in agents
            if a.get("listening_now") == 1
        ]

    active_listeners_count = sum(len(l) for l in getattr(hub, "_room_listeners", {}).values())

    return JSONResponse({
        "status": "success",
        "version": "v3.1",
        "commit": get_git_commit(),
        "db_path": str(current_db),
        "db_origin": db_origin,
        "expected_db_path": str(expected_db),
        "is_unexpected_db": bool(current_db != expected_db and not os.environ.get("AICHAT_ALLOW_CUSTOM_DB")),
        "schema_version": schema_v,
        "uptime_seconds": uptime_sec,
        "started_at": datetime.fromtimestamp(SERVER_START_TIME, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
        "connected_agents": connected_agents,
        "connected_agents_count": len(connected_agents),
        "active_listeners_count": active_listeners_count,
        "trust_proxy": is_trust_proxy_enabled(),
    })


async def endpoint_admin_get_agent_rooms(request: Request) -> Response:
    """Lists all rooms accessible to a given agent, along with available rooms."""
    principal, err = require_admin(request)
    if err:
        return err

    principal_id = safe_int(request.path_params.get("principal_id"))
    agent = hub.storage.v3.get_principal_by_id(principal_id)
    if not agent or agent.get("kind") != "agent":
        return JSONResponse({"error": "Agente não encontrado"}, status_code=404)

    agent_info = None
    all_agents = hub.storage.v3.list_agents()
    for a in all_agents:
        if a["id"] == principal_id:
            agent_info = a
            break

    agent_rooms = hub.storage.v3.list_rooms_for_principal(agent, include_archived=True)
    member_room_ids = {r["id"] for r in agent_rooms}

    all_rooms = hub.storage.v3.list_rooms(include_archived=False)
    available_rooms = [r for r in all_rooms if r["id"] not in member_room_ids]
    roles = hub.storage.v3.list_roles()

    return JSONResponse({
        "status": "success",
        "agent": agent_info or agent,
        "rooms": agent_rooms,
        "available_rooms": available_rooms,
        "roles": roles,
    })


async def endpoint_wake(request: Request) -> Response:
    """
    Universal wake-up endpoint (GET /api/wake):
    Query params:
    - timeout_seconds (default 600, max 1500 or configured)
    - ack (optional message/batch ID to acknowledge)
    - format (json | text, default json)
    - room (optional room filter)
    """
    auth = get_request_auth(request)
    if not auth:
        auth_header = request.headers.get("Authorization", "").strip()
        bearer_tok = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
        header_tok = request.headers.get("x-agent-token", "") or request.headers.get("x-member-token", "")
        if bearer_tok or header_tok:
            return JSONResponse(
                {"status": "error", "error": "Acesso negado: Token inválido, revogado ou agente desativado."},
                status_code=403,
            )
        return JSONResponse(
            {"status": "error", "error": "Autenticação obrigatória. Forneça cabeçalho Authorization: Bearer <token>."},
            status_code=401,
        )

    try:
        timeout_seconds = float(request.query_params.get("timeout_seconds", 600))
    except (ValueError, TypeError):
        timeout_seconds = 600.0

    raw_ack = request.query_params.get("ack")
    ack = raw_ack.strip() if raw_ack is not None else None

    fmt = request.query_params.get("format", "json").strip().lower()
    room = request.query_params.get("room", "").strip()

    try:
        result = await hub.wait_for_work(
            principal_or_agent=auth.get("principal") or auth.get("name"),
            timeout_seconds=timeout_seconds,
            ack=ack,
            format=fmt,
            room=room,
        )
        if fmt == "text":
            return Response(content=str(result), media_type="text/plain; charset=utf-8")
        return JSONResponse(result)
    except Exception as e:
        return JSONResponse({"status": "error", "error": str(e)}, status_code=500)


async def endpoint_room_team_status(request: Request) -> Response:
    """Returns presence and liveliness state for members of a room."""
    auth = get_request_auth(request)
    if not auth:
        return JSONResponse({"status": "error", "error": "Autenticação obrigatória"}, status_code=401)
    room_name = request.path_params.get("room_name", "")
    try:
        team = hub.get_room_team_status(room_name, requester_principal=auth.get("principal"))
        return JSONResponse({"status": "success", "room": room_name, "team": team})
    except Exception as e:
        return JSONResponse({"status": "error", "error": str(e)}, status_code=400)


async def endpoint_serve_aichat_wait(request: Request) -> Response:
    """Serves the universal client script aichat-wait.py."""
    candidates = [
        Path(__file__).resolve().parent.parent / "tools" / "aichat-wait.py",
        Path(__file__).resolve().parent / "static" / "tools" / "aichat-wait.py",
    ]
    for p in candidates:
        if p.exists():
            return Response(content=p.read_text(encoding="utf-8"), media_type="text/x-python; charset=utf-8")
    return Response(content="# aichat-wait.py not found\n", media_type="text/plain", status_code=404)



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

    # Check if human is authenticated via valid session cookie, header, bearer, or query param
    cookie_token = websocket.cookies.get("human_session", "").strip()
    header_token = websocket.headers.get("x-human-token", "").strip()
    auth_header = websocket.headers.get("authorization", "").strip()
    bearer_tok = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
    query_token = (websocket.query_params.get("token") or websocket.query_params.get("human_token") or "").strip()

    if hasattr(hub.storage, "is_v3") and hub.storage.is_v3():
        principal = current_principal.get(None)
        if not principal:
            token_candidate = (
                bearer_tok or
                websocket.headers.get("x-agent-token", "") or
                websocket.headers.get("x-member-token", "")
            ).strip()

            if cookie_token:
                principal = hub.storage.v3.authenticate_human_session(cookie_token)
            if not principal and token_candidate:
                ag, _ = hub.storage.v3.authenticate_agent_token(token_candidate)
                if ag:
                    principal = ag
                else:
                    principal = hub.storage.v3.authenticate_human_session(token_candidate)

        if not principal:
            await websocket.close(code=4401, reason="Unauthorized: Authentication required")
            return

        if principal.get("kind") == "human" and principal.get("must_change_password") == 1:
            await websocket.close(code=4403, reason="Forbidden: Password change required")
            return

        room = hub.storage.v3.get_room_by_name(room_name)
        if not room:
            await websocket.close(code=4404, reason="Room not found")
            return

        if not hub.storage.v3.authorize(principal, "read_room", {"room_id": room["id"]}):
            await websocket.close(code=4403, reason="Forbidden: No access to this room")
            return

        caller_name = principal.get("display_name") or principal.get("username") or principal.get("name") or "Utilizador"
        is_human = (principal.get("kind") == "human")
    else:
        is_human = bool(
            (cookie_token and hub.verify_human_session(cookie_token)) or
            (header_token and secrets.compare_digest(header_token, hub.human_token)) or
            (bearer_tok and secrets.compare_digest(bearer_tok, hub.human_token)) or
            (query_token and secrets.compare_digest(query_token, hub.human_token))
        )

        caller_name = "Rui (Humano)"
        if not is_human:
            agent_tok = (
                websocket.headers.get("x-agent-token", "") or
                websocket.headers.get("x-member-token", "") or
                bearer_tok or
                websocket.query_params.get("agent_token", "") or
                websocket.query_params.get("member_token", "") or
                query_token
            ).strip()

            if not agent_tok:
                await websocket.close(code=4401, reason="Unauthorized: Authentication required")
                return

            try:
                ident = hub.authenticate_agent(agent_tok)
                caller_name = ident["callsign"]
                is_human = ident.get("is_human", False)
            except Exception:
                await websocket.close(code=4401, reason="Unauthorized: Invalid or inactive agent token")
                return

            try:
                if not hub.verify_room_access(room_name, password):
                    await websocket.close(code=4403, reason="Access denied: invalid or missing room password")
                    return
            except ValueError:
                await websocket.close(code=4404, reason="Room not found")
                return

    await websocket.accept()
    await hub.register_websocket(room_name, websocket, user_name=caller_name, is_human=is_human)

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
    cal_task = asyncio.create_task(hub.calendar_dispatcher_loop())
    live_task = asyncio.create_task(hub.liveness_monitor_loop())
    try:
        async with mcp.session_manager.run():
            yield
    finally:
        cal_task.cancel()
        live_task.cancel()
        try:
            await asyncio.gather(cal_task, live_task, return_exceptions=True)
        except Exception:
            pass


def create_app(allowed_hosts: list[str] | None = None) -> Any:
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
        Route("/tools/aichat-wait.py", endpoint=endpoint_serve_aichat_wait, methods=["GET"]),
        Route("/api/status", endpoint=endpoint_status, methods=["GET"]),
        Route("/api/wake", endpoint=endpoint_wake, methods=["GET"]),
        Route("/api/auth/status", endpoint=endpoint_auth_status, methods=["GET"]),
        Route("/api/auth/login", endpoint=endpoint_auth_login, methods=["POST"]),
        Route("/api/auth/logout", endpoint=endpoint_auth_logout, methods=["POST"]),
        Route("/api/auth/change-password", endpoint=endpoint_auth_change_password, methods=["POST"]),
        Route("/api/tts", endpoint=endpoint_tts, methods=["GET", "POST"]),
        Route("/api/tts/voices", endpoint=endpoint_tts_voices, methods=["GET"]),
        Route("/api/rooms", endpoint=endpoint_get_rooms, methods=["GET"]),
        Route("/api/rooms", endpoint=endpoint_create_room, methods=["POST"]),
        Route("/api/rooms/{room_name}/messages", endpoint=endpoint_get_messages, methods=["GET"]),
        Route("/api/rooms/{room_name}/messages", endpoint=endpoint_post_message, methods=["POST"]),
        Route("/api/rooms/{room_name}/team-status", endpoint=endpoint_room_team_status, methods=["GET"]),
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
        Route("/api/register", endpoint=endpoint_self_register_agent, methods=["POST"]),
        Route("/api/agents", endpoint=endpoint_register_agent, methods=["POST"]),
        Route("/api/agents/{callsign}", endpoint=endpoint_delete_agent, methods=["DELETE"]),
        Route("/api/agents/{callsign}/rotate", endpoint=endpoint_rotate_agent_token, methods=["POST"]),
        Route("/api/agents/{callsign}/status", endpoint=endpoint_update_agent_status, methods=["POST", "PATCH"]),
        Route("/admin", endpoint=endpoint_admin_ui, methods=["GET"]),
        Route("/api/admin/me", endpoint=endpoint_admin_me, methods=["GET"]),
        Route("/api/admin/settings", endpoint=endpoint_admin_get_settings, methods=["GET"]),
        Route("/api/admin/settings", endpoint=endpoint_admin_patch_settings, methods=["PATCH", "POST"]),
        Route("/api/admin/humans", endpoint=endpoint_admin_list_humans, methods=["GET"]),
        Route("/api/admin/humans", endpoint=endpoint_admin_create_human, methods=["POST"]),
        Route("/api/admin/humans/{principal_id:int}", endpoint=endpoint_admin_update_human, methods=["PATCH", "PUT"]),
        Route("/api/admin/humans/{principal_id:int}", endpoint=endpoint_admin_delete_human, methods=["DELETE"]),
        Route("/api/admin/users", endpoint=endpoint_admin_list_humans, methods=["GET"]),
        Route("/api/admin/users", endpoint=endpoint_admin_create_human, methods=["POST"]),
        Route("/api/admin/users/{principal_id:int}", endpoint=endpoint_admin_update_human, methods=["PATCH", "PUT"]),
        Route("/api/admin/users/{principal_id:int}", endpoint=endpoint_admin_delete_human, methods=["DELETE"]),
        Route("/api/admin/agents", endpoint=endpoint_admin_list_agents, methods=["GET"]),
        Route("/api/admin/agents", endpoint=endpoint_admin_create_agent, methods=["POST"]),
        Route("/api/admin/agents/{id:int}/approve", endpoint=endpoint_admin_approve_agent, methods=["POST"]),
        Route("/api/admin/agents/{id:int}/wake-profile", endpoint=endpoint_admin_update_agent_wake_profile, methods=["PATCH", "POST"]),
        Route("/api/admin/agents/{principal_id:int}", endpoint=endpoint_admin_update_agent, methods=["PATCH", "PUT"]),
        Route("/api/admin/agents/{principal_id:int}", endpoint=endpoint_admin_delete_agent, methods=["DELETE"]),
        Route("/api/admin/agents/{principal_id:int}/rotate-token", endpoint=endpoint_admin_rotate_agent_token, methods=["POST"]),
        Route("/api/admin/agents/{principal_id:int}/revoke-token", endpoint=endpoint_admin_revoke_agent_token, methods=["POST"]),
        Route("/api/admin/rooms", endpoint=endpoint_admin_list_rooms, methods=["GET"]),
        Route("/api/admin/rooms", endpoint=endpoint_admin_create_room, methods=["POST"]),
        Route("/api/admin/rooms/{room_id}/archive", endpoint=endpoint_admin_archive_room, methods=["POST"]),
        Route("/api/admin/rooms/{room_id}/unarchive", endpoint=endpoint_admin_unarchive_room, methods=["POST"]),
        Route("/api/admin/rooms/{room_id}/members", endpoint=endpoint_admin_list_room_members, methods=["GET"]),
        Route("/api/admin/rooms/{room_id}/access", endpoint=endpoint_admin_grant_room_access, methods=["POST"]),
        Route("/api/admin/rooms/{room_id}/access/{principal_id:int}", endpoint=endpoint_admin_revoke_room_access, methods=["DELETE"]),
        Route("/api/admin/rooms/{room_id}/access/{principal_id:int}", endpoint=endpoint_admin_patch_room_access, methods=["PATCH"]),
        Route("/api/admin/rooms/bulk-grant", endpoint=endpoint_admin_bulk_grant_room_access, methods=["POST"]),
        Route("/api/admin/rooms/matrix", endpoint=endpoint_admin_rooms_matrix, methods=["GET"]),
        Route("/api/admin/roles", endpoint=endpoint_admin_list_roles, methods=["GET"]),
        Route("/api/admin/roles", endpoint=endpoint_admin_create_role, methods=["POST"]),
        Route("/api/admin/roles/{role_id:int}", endpoint=endpoint_admin_update_role, methods=["PATCH", "PUT"]),
        Route("/api/admin/roles/{role_id:int}", endpoint=endpoint_admin_delete_role, methods=["DELETE"]),
        Route("/api/admin/audit", endpoint=endpoint_admin_list_audit_log, methods=["GET"]),
        Route("/api/admin/system", endpoint=endpoint_admin_system, methods=["GET"]),
        Route("/api/admin/agents/{principal_id:int}/rooms", endpoint=endpoint_admin_get_agent_rooms, methods=["GET"]),

        Route("/api/rooms/{room_name}/tasks", endpoint=endpoint_get_tasks, methods=["GET"]),
        Route("/api/rooms/{room_name}/tasks", endpoint=endpoint_create_task, methods=["POST"]),
        Route("/api/tasks/{task_id:int}", endpoint=endpoint_update_task, methods=["PATCH", "POST"]),
        Route("/api/tasks/{task_id:int}", endpoint=endpoint_delete_task, methods=["DELETE"]),
        Route("/api/tasks/{task_id:int}/dependencies", endpoint=endpoint_add_task_dependency, methods=["POST"]),
        Route("/api/tasks/{task_id:int}/dependencies/{dep_id:int}", endpoint=endpoint_remove_task_dependency, methods=["DELETE"]),
        Route("/api/rooms/{room_name}/tasks/reorder", endpoint=endpoint_reorder_tasks, methods=["POST"]),
        Route("/api/rooms/{room_name}/calendar", endpoint=endpoint_get_calendar_events, methods=["GET"]),
        Route("/api/rooms/{room_name}/calendar", endpoint=endpoint_create_calendar_event, methods=["POST"]),
        Route("/api/calendar/events", endpoint=endpoint_get_calendar_events, methods=["GET"]),
        Route("/api/calendar/events/{event_id:int}", endpoint=endpoint_update_calendar_event, methods=["PATCH", "POST"]),
        Route("/api/calendar/events/{event_id:int}", endpoint=endpoint_delete_calendar_event, methods=["DELETE"]),
        Route("/api/calendar/resources", endpoint=endpoint_get_calendar_resources, methods=["GET"]),
        Route("/api/rooms/{room_name}/calendar.ics", endpoint=endpoint_get_calendar_ics, methods=["GET"]),
        Route("/api/calendar.ics", endpoint=endpoint_get_calendar_ics, methods=["GET"]),
        Route("/api/rooms/{room_name}/log", endpoint=endpoint_download_log, methods=["GET"]),
        Route("/api/rooms/{room_name}/jsonl", endpoint=endpoint_download_jsonl, methods=["GET"]),
        Route("/api/rooms/{room_name}/stream", endpoint=endpoint_room_sse_stream, methods=["GET"]),
        Route("/api/rooms/{room_name}/wake-up", endpoint=endpoint_room_wake_up, methods=["GET"]),
        Route("/api/wake-up", endpoint=endpoint_wake_up, methods=["GET"]),
        WebSocketRoute("/ws/{room_name}", endpoint=websocket_room_endpoint),
        # If client sends POST /sse, handle via Streamable HTTP
        *([Route("/sse", endpoint=streamable_endpoint, methods=["POST"])] if streamable_endpoint else []),
        # Mount FastMCP SSE routes: GET /sse and /messages
        *mcp_sse.routes,
        # Mount FastMCP Streamable HTTP routes: /mcp
        *mcp_http.routes,
        Mount("/static", StaticFiles(directory=STATIC_DIR), name="static"),
    ]

    middleware = [
        Middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts),
        Middleware(SecurityHardeningMiddleware),
        Middleware(V3AuthenticationMiddleware),
    ]

    app = Starlette(debug=False, routes=routes, middleware=middleware, lifespan=app_lifespan)
    return CleanShutdownMiddleware(app)
