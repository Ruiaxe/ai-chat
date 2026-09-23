import json
from typing import Any

from mcp.server.fastmcp import FastMCP, Context

from aichat.hub import ChatHub

mcp = FastMCP("ai-chat-room")
# Allow local MCP connections without strict host-header rejections
mcp.settings.transport_security.enable_dns_rebinding_protection = False
hub = ChatHub()


@mcp.tool()
def create_room(room_name: str, password: str = "", topic: str = "") -> str:
    """
    Creates a new collaborative chat room.
    Optionally set a password to protect the room from unauthorized access.
    """
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
def list_rooms() -> str:
    """
    Lists all available chat rooms with metadata:
    name, topic, whether it is password-protected, member count, and message count.
    """
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
def join_room(room_name: str, agent_name: str, password: str = "", member_token: str = "") -> str:
    """
    Joins an existing chat room as a participant.
    If the room is password-protected, the correct password must be supplied.
    Returns your unique member_token. Save this token and pass it to send_message to prove your identity!
    """
    try:
        res = hub.join_room(room_name=room_name, member_name=agent_name, role="agent", password=password, member_token=member_token)
        return json.dumps({
            "status": "success",
            "message": f"Agent '{agent_name}' joined room '{room_name}'.",
            "details": res,
            "member_token": res.get("member_token", ""),
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def leave_room(room_name: str, agent_name: str) -> str:
    """Leaves a chat room."""
    try:
        res = hub.leave_room(room_name=room_name, member_name=agent_name)
        return json.dumps({"status": "success", "details": res}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def list_my_rooms(agent_name: str) -> str:
    """
    Lists all chat rooms that this agent has joined.
    Useful for seeing which channels you are subscribed to when listening in 'subscribed' mode.
    """
    try:
        rooms = hub.list_my_rooms(agent_name=agent_name)
        return json.dumps({
            "status": "success",
            "agent_name": agent_name,
            "count": len(rooms),
            "rooms": rooms,
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def send_message(
    room_name: str,
    sender_name: str,
    content: str,
    password: str = "",
    member_token: str = "",
) -> str:
    """
    Sends a message to the specified chat room.
    All agents and the human user in the room will see this message in real-time.
    If the room is password-protected, the correct password must be provided.
    - member_token: Optional authentication token returned when calling `join_room`.
      If provided, verifies the sender identity and marks the message as verified (✓ Verificado).
      If a token was already issued for this sender, omitting or passing an invalid token will be rejected to prevent impersonation.
    """
    try:
        msg = await hub.send_message(
            room_name=room_name,
            sender=sender_name,
            content=content,
            role="agent",
            password=password,
            member_token=member_token,
        )
        return json.dumps({
            "status": "success",
            "message_id": msg["id"],
            "room": room_name,
            "sender": sender_name,
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
    limit: int = 50,
) -> str:
    """
    Reads recent messages from a room.
    Use 'since_id' to only fetch messages newer than a specific message ID you have already seen.
    """
    try:
        msgs = hub.read_messages(
            room_name=room_name,
            password=password,
            since_id=since_id,
            limit=limit,
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
    ctx: Context = None,
) -> str:
    """
    Long-polling notification tool for agents:
    Suspends and waits until another agent or the human sends a new message.
    - room_name: Specific room name, 'subscribed' (or empty) to watch all joined rooms, or comma-separated list.
    - agent_name: Your agent's name (e.g. 'Claude'). Your own messages are ignored.
    - since_id: ID of the last message you processed. If 0 (default), waits for new messages arriving from now on.
    - timeout_seconds: Maximum seconds to wait before timing out (1 to 3600, default 600 = 10 minutes).
      Sends regular MCP progress heartbeats (every 45s) to prevent client timeouts (e.g. Claude Code 300s limit).
    - password: Room password if protected.
    Returns immediately if new messages already exist or as soon as one arrives.
    If timeout expires without new messages, returns status 'timeout'.
    """
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
            agent_name=agent_name,
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
) -> str:
    """
    Fast non-blocking check: immediately returns whether there are new messages.
    Does not suspend or wait. Ideal for fast polling or checking status before acting.
    - room_name: Specific room name, 'subscribed' (or empty) to check all joined rooms, or comma-separated list.
    - since_id: Only return messages with ID > since_id.
    - agent_name: Filter out messages sent by this agent.
    """
    try:
        result = hub.check_new_messages(
            room_name=room_name,
            agent_name=agent_name,
            since_id=since_id,
            password=password,
        )
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def get_room_transcript(room_name: str, password: str = "") -> str:
    """
    Returns the complete human-readable transcript file of the room.
    Useful for reviewing the entire history of an agent team session.
    """
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
) -> str:
    """
    Adds or removes an emoji reaction on a message (e.g. '👍', '🚀', '❤️', '👀', '🎉', '👎').
    Calling again with the same emoji toggles (removes) it.
    """
    try:
        sender = (sender_name or agent_name or "Agent").strip()
        res = await hub.toggle_reaction(
            message_id=message_id,
            room_name=room_name,
            sender=sender,
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
) -> str:
    """
    Calls the human user for an important decision, impasse resolution, or architectural choice.
    Renders high-visibility alert cards, desktop notifications, and quick-action choice buttons in the human's Web UI.
    - options: Optional list of proposed choices (e.g. ['Option A: Vector DB', 'Option B: SQLite']).
    """
    try:
        sender = (sender_name or agent_name or "Agent").strip()
        msg = await hub.call_human(
            room_name=room_name,
            sender=sender,
            question=question,
            options=options,
            member_token=member_token,
        )
        return json.dumps({
            "status": "success",
            "message_id": msg["id"],
            "room": room_name,
            "sender": sender,
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
) -> str:
    """
    Creates a voting poll in the chat room for team decisions.
    - options: List of at least 2 choices to vote on.
    """
    try:
        creator = (creator_name or agent_name or "Agent").strip()
        poll = await hub.create_poll(
            room_name=room_name,
            creator=creator,
            question=question,
            options=options,
            member_token=member_token,
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
) -> str:
    """
    Casts a vote on an active poll.
    - option_index: 0-indexed choice position.
    """
    try:
        voter = (voter_name or agent_name or "Agent").strip()
        poll = await hub.cast_vote(
            poll_id=poll_id,
            voter=voter,
            option_index=option_index,
        )
        return json.dumps({"status": "success", "poll": poll}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def get_poll(poll_id: int) -> str:
    """
    Gets live poll status, vote counts per option, and percentages.
    """
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
    member_token: str = "",
) -> str:
    """
    Closes an active poll (can only be closed by its creator or the human user).
    """
    try:
        closer = (closer_name or agent_name or "Agent").strip()
        poll = await hub.close_poll(
            poll_id=poll_id,
            closer=closer,
            is_human=False,
            member_token=member_token,
        )
        return json.dumps({"status": "success", "poll": poll}, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
def archive_room(room_name: str, requester_name: str = "", requester_role: str = "agent") -> str:
    """
    Archives a chat room to read-only mode.
    WARNING: THIS TOOL IS STRICTLY RESTRICTED TO THE HUMAN USER. AGENTS CANNOT ARCHIVE ROOMS.
    """
    try:
        res = hub.archive_room(room_name=room_name, requester_role=requester_role)
        return json.dumps({"status": "success", "details": res}, indent=2)
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

