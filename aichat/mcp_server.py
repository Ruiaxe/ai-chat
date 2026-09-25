import json
import os
from typing import Any

from mcp.server.fastmcp import FastMCP, Context

from aichat.hub import ChatHub

mcp = FastMCP("ai-chat-room")
# Allow local MCP connections without strict host-header rejections
mcp.settings.transport_security.enable_dns_rebinding_protection = False
hub = ChatHub()


def _authenticate(agent_token: str = "", member_token: str = "", expected_callsign: str = "") -> tuple[dict[str, Any] | None, str | None]:
    """
    Validates agent_token (or member_token alias, or AI_CHAT_AGENT_TOKEN env var) against closed registry.
    Returns (agent_info, error_json_str).
    """
    token = (agent_token or member_token or os.environ.get("AI_CHAT_AGENT_TOKEN", "")).strip()
    if not token:
        return None, json.dumps({
            "status": "error",
            "error": "Access denied: Missing agent_token. All MCP tools require a valid agent_token from the official registry. Contact human supervisor Rui if you need an authorized token."
        }, indent=2)
    try:
        ident = hub.authenticate_agent(token, expected_callsign=expected_callsign)
        return ident, None
    except Exception as e:
        return None, json.dumps({
            "status": "error",
            "error": f"Authentication failed: {str(e)}"
        }, indent=2)


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
    Lists all available chat rooms with metadata. Requires authorized agent_token.
    """
    ident, err = _authenticate(agent_token, member_token)
    if err:
        return err
    try:
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
def rotate_member_token(room_name: str, agent_name: str = "", current_token: str = "", password: str = "", member_token: str = "", agent_token: str = "") -> str:
    """
    Securely rotates and generates a new token for an agent in a room.
    The new token is returned directly and privately in this tool output. It is never broadcasted to the room.
    """
    token = (agent_token or member_token or current_token).strip()
    ident, err = _authenticate(token, expected_callsign=agent_name)
    if err:
        return err
    callsign = ident["callsign"]
    try:
        res = hub.rotate_member_token(room_name=room_name, member_name=callsign, current_token=token, password=password)
        return json.dumps({
            "status": "success",
            "message": f"Token for agent '{callsign}' in room '{room_name}' rotated successfully.",
            "details": res,
            "member_token": res.get("member_token", ""),
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def change_room_password(room_name: str, old_password: str, new_password: str, agent_name: str = "", agent_token: str = "", member_token: str = "") -> str:
    """
    Changes the password of a room.
    Requires authorized agent_token and current room password (or supervisor authorization).
    """
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(token, expected_callsign=agent_name)
    if err:
        return err
    callsign = ident["callsign"]
    try:
        res = hub.change_room_password(room_name=room_name, old_password=old_password, new_password=new_password, actor_name=callsign)
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
) -> str:
    """
    Sends a message to the specified chat room.
    Requires authorized agent_token (or member_token).
    Sender callsign is automatically bound and verified from your authenticated token.
    """
    token = (agent_token or member_token).strip()
    ident, err = _authenticate(token, expected_callsign=sender_name)
    if err:
        return err
    callsign = ident["callsign"]

    try:
        msg = await hub.send_message(
            room_name=room_name,
            sender=callsign,
            content=content,
            role="agent" if not ident.get("is_human") else "human",
            password=password,
            member_token=token,
            human_token=hub.human_token if ident.get("is_human") else "",
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
    try:
        msgs = hub.read_messages(
            room_name=room_name,
            password=password,
            since_id=since_id,
            before_id=before_id,
            limit=limit,
            message_id=message_id if message_id > 0 else None,
        )
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
) -> str:
    """
    Calls the human user for an important decision, impasse resolution, or architectural choice.
    Requires authorized agent_token (or member_token).
    Renders high-visibility alert cards, desktop notifications, and quick-action choice buttons in the human's Web UI.
    - options: Optional list of proposed choices (e.g. ['Option A: Vector DB', 'Option B: SQLite']).
    - password: Room password if calling in a password-protected room.
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

