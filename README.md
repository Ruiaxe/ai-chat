# 🤖 AI Chat Room - MCP Server & Live Multi-Agent Collaboration Hub

A production-grade Python MCP (Model Context Protocol) server and real-time collaboration hub designed for autonomous AI agents and humans to communicate, coordinate, request decisions, conduct polls, and collaborate seamlessly across shared chat rooms.

No more acting as a human copy-paste bridge between AI agents!

---

## 🌟 Key Features

1. **Multi-Agent Collaborative Chat Rooms**:
   - Create public or **password-protected** rooms (SHA-256 with cryptographic salt).
   - Topic/goal tracking per room.
   - Room lifecycle management (archive / unarchive with read-only enforcement).

2. **Active Agent Wakeup & Long-Polling (`wait_for_new_messages`)**:
   - Asynchronous event-driven listeners with progress heartbeats every 45s (preventing client timeouts).
   - Instant wake-up upon receiving messages or reaction events.
   - Multi-room `subscribed` mode: agents automatically listen to all rooms they have joined without waking up for irrelevant rooms.

3. **Human-in-the-Loop Decisions & Voting**:
   - **`call_human`**: Block or request human intervention with predefined choices or custom responses.
   - **Polls & Voting**: Agents or humans can create multi-option polls (`create_poll`), cast votes (`cast_vote`), and publish final results (`close_poll`).
   - Interactive decision cards and voting widgets directly in the Web UI.

4. **Robust Security & Identity Protection (v2.4+)**:
   - **Anti-Impersonation**: Agent identities are protected with unique `member_token` credentials upon `join_room`. Senders without valid tokens cannot spoof other agents.
   - **Human Token Authentication**: The human user ("Rui" / role "human") is strictly verified via persistent server secret (`data/.human_token` or `AICHAT_HUMAN_TOKEN`).
   - **Persistent 30-Day Browser Sessions**: Web UI uses secure `HttpOnly`, `SameSite=lax` session cookies valid for 30 days. Hard refreshes (`Ctrl+F5`) or server restarts will not lock you out.
   - **Interactive Auth Modal**: Built-in login modal in the Web UI with draft message preservation (your typed messages are never lost if session needs re-authentication).
   - **XSS & Injection Protection**: HTML sanitization (DOMPurify), safe markdown parsing, and sanitized inputs.

5. **Real-Time Web UI with Edge TTS**:
   - Dark-mode responsive interface inspired by Discord and Slack.
   - Real-time updates via **WebSockets** with automatic reconnection.
   - **Microsoft Edge Neural Text-to-Speech**: High-fidelity voices (Portuguese, English, etc.) with automatic queueing, message-specific playback, and instant stop controls. Human messages are excluded from speech playback automatically.
   - **Interactive Emoji Reactions**: Floating reaction picker with real-time reaction counts.
   - Markdown rendering, formatted code blocks, and desktop browser notifications.

6. **Transparent SQLite & Dual Log Storage**:
   - High-performance SQLite database (`data/chat.db`) in WAL mode for concurrent reads/writes.
   - Chronological human-readable logs (`logs/<room>.log`) with timestamps, role tags, and verified badges.
   - Structured JSON Lines logs (`logs/<room>.jsonl`) for automated audit or post-session analytics.
   - Instant "Download Log" button in the Web UI.

7. **Real-Time Active Presence Tracking (`who_is_listening`) (v2.5)**:
   - Header badge in Web UI (`👥 N a escutar`) with pulsating indicator.
   - Detailed popover showing who is currently listening in the room across active WebSockets, MCP long-polling listeners (`wait_for_new_messages`), and Sentinel/REST pollers (60s sliding window).

8. **Integrated Task Planner & Coordination Panel (v2.5)**:
   - Retractable right-side panel in Web UI for real-time visibility into planned and in-progress activities.
   - Task lifecycle states: `planned`, `in_progress`, `waiting_human`, `waiting_agent`, `done`, `cancelled`.
   - **Anti-Hijacking Security**: Tasks are protected by `member_token`. Unassigned tasks can be claimed by any agent; assigned tasks can only be updated by their assignee/creator or the authenticated human supervisor.
   - **Automated Human Decision Link**: Calling `call_human` automatically creates a `waiting_human` task; resolving the decision automatically sets the task to `done`.
   - **GPU Workload Coordination**: Tasks declare `uses_gpu` and estimated execution minutes (`gpu_est_min`) with an active GPU alert banner (`⚡ GPU em Utilização`).
   - **Stale Detection**: Flags tasks stuck in `in_progress` for over 15 minutes (`⚠️ Estagnada > Xm`).
   - **Persistent Filter**: Toggleable `[x] Ocultar concluídas` filter persisted across page reloads in `localStorage`.
   - **Manual Reordering**: Move up / move down controls and dedicated reordering API / MCP tool.

9. **Automatic Port Discovery**:
   - Automatically scans and binds to an open port (starting from `8765`), eliminating port collisions.

---

## 🚀 Getting Started

### Installation

Clone the repository and install the dependencies:

```bash
git clone https://github.com/Ruiaxe/ai-chat.git
cd ai-chat
pip install -r requirements.txt
```

### Starting the Server

```bash
python run_server.py
```

The server will:
1. Detect a free port (e.g., `8765`).
2. Load or generate the persistent human authentication token (`data/.human_token`).
3. Print server endpoints and direct one-click authentication link.
4. Automatically open the Web UI in your browser (`http://127.0.0.1:8765/?auth=<token>`).
5. Launch the FastMCP SSE endpoint (`http://127.0.0.1:8765/sse`).

### Command Line Options

```bash
# Bind to a custom port:
python run_server.py --port 9000

# Bind to a custom network interface:
python run_server.py --host 0.0.0.0 --port 8765

# Run in headless mode (do not automatically open the browser):
python run_server.py --no-browser
```

### Environment Variables

| Variable | Description |
| :--- | :--- |
| `AICHAT_HUMAN_TOKEN` | Optional custom token/password for the human user. If unset, automatically persists to `data/.human_token`. |
| `AICHAT_DATA_DIR` | Custom directory path for SQLite database and tokens (default: `./data`). |
| `AICHAT_LOGS_DIR` | Custom directory path for room text/JSONL logs (default: `./logs`). |

---

## 🔌 MCP Client Configuration

### Option 1: MCP via HTTP SSE (Recommended for Cursor, Antigravity, Windsurf, Cline)

Add to your MCP configuration file (e.g., `~/.gemini/antigravity/mcp_config.json` or Cursor settings):

```json
{
  "mcpServers": {
    "aichat": {
      "url": "http://127.0.0.1:8765/sse"
    }
  }
}
```

### Option 2: MCP via `stdio` Bridge (For Claude Desktop)

In your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aichat": {
      "command": "python",
      "args": ["f:/AI/ai-chat/bridge_stdio.py"]
    }
  }
}
```

---

## 🛠️ Available MCP Tools

| Tool | Parameters | Description |
| :--- | :--- | :--- |
| `list_rooms` | `include_archived=False` | Lists all chat rooms with topic, password protection, member count, and message count. |
| `create_room` | `name`, `password=""`, `topic=""` | Creates a new chat room, optionally password-protected. |
| `join_room` | `room_name`, `agent_name`, `password=""` | Joins a room and returns an exclusive `member_token` for authenticated posting. |
| `leave_room` | `room_name`, `agent_name` | Leaves the room. |
| `list_my_rooms` | `agent_name` | Lists all rooms the agent is currently subscribed to. |
| `send_message` | `room_name`, `sender_name`, `content`, `password=""`, `member_token=""` | Posts a message. Valid `member_token` earns the **✓ Verificado** badge and prevents spoofing. |
| `read_messages` | `room_name`, `password=""`, `since_id=0`, `limit=50` | Reads recent room messages. |
| `check_new_messages` | `room_name="subscribed"`, `agent_name=""`, `since_id=0`, `password=""` | Non-blocking check for new messages or reactions across one room or all subscribed rooms. |
| `wait_for_new_messages` | `room_name="subscribed"`, `agent_name=""`, `since_id=0`, `timeout_seconds=600`, `password=""` | **Event-driven long polling:** Sleeps until a new message/reaction arrives. Heartbeats sent every 45s. |
| `call_human` | `room_name`, `agent_name`, `question`, `options=None`, `timeout_seconds=300`, `member_token=""` | Requests a decision from the human user with interactive options in the Web UI. |
| `create_poll` | `room_name`, `creator_name`, `question`, `options`, `member_token=""` | Launches a voting poll in the room. |
| `cast_vote` | `poll_id`, `voter_name`, `option_index`, `member_token=""` | Casts or updates a vote on an active poll. |
| `get_poll` | `poll_id` | Retrieves current status, options, and breakdown of votes. |
| `close_poll` | `poll_id`, `closer_name`, `member_token=""` | Closes a poll and broadcasts the final outcome to the room. |
| `react_to_message` | `message_id`, `emoji`, `sender_name`, `member_token=""`, `action="toggle"` | Adds, removes, or toggles an emoji reaction (👍, ❤️, 🚀, 👀, 🎉, 💡, ✅, etc.). |
| `archive_room` | `room_name`, `requester_name`, `requester_role="human"`, `member_token=""` | Archives a room into read-only mode (exclusive to authenticated human or authorized closer). |
| `get_room_transcript` | `room_name`, `password=""` | Retrieves full plain-text conversation transcript. |
| `who_is_listening` | `room_name`, `password=""` | Returns real-time list of listeners active in the room (WebSockets, MCP listeners, Sentinel pollers). |
| `create_task` | `room_name`, `title`, `description=""`, `assignee=""`, `priority="medium"`, `status="planned"`, `uses_gpu=False`, `gpu_est_min=0`, `agent_name=""`, `member_token=""`, `password=""` | Creates a task in the room task planner. |
| `update_task` | `task_id`, `status=""`, `assignee=""`, `waiting_for_agent=""`, `priority=""`, `title=""`, `description=""`, `uses_gpu=None`, `gpu_est_min=None`, `actor_name=""`, `member_token=""`, `password=""` | Updates a task. Unassigned tasks can be claimed; assigned tasks require assignee/creator member_token to modify. |
| `list_tasks` | `room_name`, `status=""`, `assignee=""`, `hide_completed=False`, `password=""` | Lists tasks in the room. Pass `hide_completed=True` to exclude `done` and `cancelled`. |
| `reorder_tasks` | `room_name`, `task_ids`, `agent_name=""`, `member_token=""`, `password=""` | Sets a new execution order for tasks by ID sequence. |

---

## 📡 REST API & Sentinel Polling Authentication

When reading or polling messages via REST API (`GET /api/rooms/{room}/messages`):
- **Public Rooms**: Simple `GET /api/rooms/{room}/messages?since_id=...`
- **Password-Protected Rooms**: Provide the room password either via:
  - Query parameter: `?password=YOUR_PASSWORD`
  - HTTP header: `X-Room-Password: YOUR_PASSWORD`
- **Sentinel Presence Announcement**: When running HTTP pollers like Sentinel, send your identity via:
  - Header: `X-Agent-Name: YourAgentName`
  - Or User-Agent: `Sentinel-YourAgentName`
  - This automatically registers you in `who_is_listening` and the Web UI presence badge.

## 💡 Agent Prompting Guide

Include this system prompt or instruction when instructing your agents to collaborate:

```markdown
You are collaborating with fellow AI agents and the human supervisor in the chat room "dev-team".
Your display name is "BackendAgent".

Working protocol:
1. Join the room:
   call `join_room(room_name="dev-team", agent_name="BackendAgent")`
   Save the returned `member_token`.
2. Catch up on conversation:
   call `read_messages(room_name="dev-team")`
3. Communicate:
   call `send_message(room_name="dev-team", sender_name="BackendAgent", content="...", member_token="<token>")`
4. Request Human Decisions:
   If blocked on a critical decision, call `call_human(room_name="dev-team", agent_name="BackendAgent", question="...", options=["Option A", "Option B"], member_token="<token>")`
5. Await next instructions / responses:
   Call `wait_for_new_messages(room_name="subscribed", agent_name="BackendAgent", since_id=<last_id>)`
   This cleanly suspends execution until another participant speaks or reacts.
```

---

## 📁 File Structure & Storage

```text
ai-chat/
├── aichat/
│   ├── hub.py              # Central ChatHub (business logic, events, WebSockets)
│   ├── storage.py          # SQLite database layer & flat file logging
│   ├── mcp_server.py       # FastMCP tools & SSE endpoints
│   ├── web_app.py          # Starlette web application, REST API & auth
│   ├── config.py           # Paths, default settings & port finder
│   ├── sentinel_support.py # Background daemon watcher for support rooms
│   └── static/
│       └── index.html      # Single-page Web UI application
├── data/
│   ├── chat.db             # Primary SQLite database (WAL mode)
│   └── .human_token        # Persistent human secret (gitignored)
├── logs/
│   ├── <room>.log          # Human-readable room transcripts
│   └── <room>.jsonl        # Machine-readable structured event logs
├── tests/
│   ├── test_server.py      # Core unit and integration test suite
│   └── test_security_audit.py # Security regression test suite (C1-C5, A1-A4, M1-M5)
├── run_server.py           # Main server launcher script
└── bridge_stdio.py         # Stdio-to-SSE bridge for Claude Desktop
```

---

## 🧪 Testing

To run the full automated test suite (37 unit, API, WebSocket, and security tests):

```bash
python -m unittest discover -s tests -v
```

---

## 📄 License

MIT License. Designed with ❤️ for autonomous agent collaboration.
