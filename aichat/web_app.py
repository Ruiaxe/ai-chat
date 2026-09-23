import asyncio
import json
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.endpoints import WebSocketEndpoint
from starlette.requests import Request
from starlette.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

import edge_tts

from aichat.config import STATIC_DIR
from aichat.mcp_server import hub, mcp

INDEX_HTML = STATIC_DIR / "index.html"


# --- HTTP Endpoints ---

async def endpoint_index(request: Request) -> Response:
    """Serves the Web UI HTML application."""
    if INDEX_HTML.exists():
        return HTMLResponse(INDEX_HTML.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>AI Chat Hub</h1><p>index.html not found</p>", status_code=404)


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
    password = request.query_params.get("password", "")
    since_id = int(request.query_params.get("since_id", 0))
    limit = min(int(request.query_params.get("limit", 500)), 1000)

    try:
        messages = hub.read_messages(
            room_name=room_name,
            password=password,
            since_id=since_id,
            limit=limit,
        )
        return JSONResponse(messages)
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_post_message(request: Request) -> Response:
    """Posts a message to a room."""
    room_name = request.path_params["room_name"]
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    sender = (data.get("sender") or data.get("sender_name") or data.get("agent_name") or "").strip()
    if not sender:
        return JSONResponse({"error": "Sender cannot be empty"}, status_code=400)

    content = data.get("content", "").strip()
    role = data.get("role", "agent" if sender.lower() not in ("human", "rui") else "human")
    password = data.get("password", "")
    member_token = data.get("member_token", "")

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
        )
        return JSONResponse(msg, status_code=201)
    except PermissionError as pe:
        return JSONResponse({"error": str(pe)}, status_code=403)
    except ValueError as ve:
        return JSONResponse({"error": str(ve)}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_download_log(request: Request) -> Response:
    """Downloads the text log of a room."""
    room_name = request.path_params["room_name"]
    password = request.query_params.get("password", "")

    try:
        if not hub.verify_room_access(room_name, password):
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

    try:
        if not hub.verify_room_access(room_name, password):
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

    try:
        if not hub.verify_room_access(room_name, password):
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
        res = await hub.resolve_human_decision(message_id, room_name, decision, decider)
        return JSONResponse(res)
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
    if not question or len(options) < 2:
        return JSONResponse({"error": "Question and at least 2 options are required"}, status_code=400)
    try:
        poll = await hub.create_poll(room_name, creator, question, options)
        return JSONResponse(poll, status_code=201)
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
    try:
        poll = await hub.close_poll(poll_id, closer, is_human=True)
        return JSONResponse(poll)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


async def endpoint_archive_room(request: Request) -> Response:
    """Archives a room. Restricted strictly to human users."""
    room_name = request.path_params["room_name"]
    try:
        res = hub.archive_room(room_name, requester_role="human")
        await hub._broadcast_to_websockets(room_name, {"type": "room_archived", "room_name": room_name})
        return JSONResponse(res)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=403)


async def endpoint_unarchive_room(request: Request) -> Response:
    """Unarchives a room. Restricted strictly to human users."""
    room_name = request.path_params["room_name"]
    try:
        res = hub.unarchive_room(room_name, requester_role="human")
        await hub._broadcast_to_websockets(room_name, {"type": "room_unarchived", "room_name": room_name})
        return JSONResponse(res)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=403)


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


# --- WebSocket Endpoint ---

async def websocket_room_endpoint(websocket: WebSocket) -> None:
    """Real-time WebSocket handler for chat rooms."""
    room_name = websocket.path_params["room_name"]
    await websocket.accept()
    await hub.register_websocket(room_name, websocket)
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


from contextlib import asynccontextmanager

@asynccontextmanager
async def app_lifespan(app: Starlette):
    """Manages background tasks and Streamable HTTP session manager."""
    async with mcp.session_manager.run():
        yield


def create_app() -> Starlette:
    """Builds and returns the combined Starlette ASGI application."""
    # FastMCP SSE app routes (/sse, /messages)
    mcp_sse = mcp.sse_app()
    # FastMCP Streamable HTTP app routes (/mcp)
    mcp_http = mcp.streamable_http_app()

    # Route POST /sse to the streamable HTTP endpoint in case client sends direct POST
    streamable_endpoint = mcp_http.routes[0].endpoint if mcp_http.routes else None

    routes = [
        Route("/", endpoint=endpoint_index, methods=["GET"]),
        Route("/api/status", endpoint=endpoint_status, methods=["GET"]),
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

    return Starlette(debug=False, routes=routes, lifespan=app_lifespan)
