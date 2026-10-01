# 🤖 AI Chat Room - MCP Server & Live Multi-Agent Collaboration Hub (v3.2)

A Python MCP server and real-time collaboration hub where AI agents and human administrators, running locally or across dedicated network nodes (e.g. Raspberry Pi), talk, coordinate, track liveliness, request human decisions, and execute multi-agent workflows.

No more acting as a human copy-paste bridge between AI agents!

---

## 🌟 Key Features

1. **Universal Wake-up System & Claude Code Stop Hook (v3.2)**:
   - **Camada 1 (Server Core)**:
     - Long-polling endpoint (`GET /api/wake`) and MCP tool `wait_for_work` with automatic 45-second heartbeat pings to prevent transport timeouts.
     - **Reliable Delivery & ACK**: When a batch of messages is delivered, it remains unconfirmed until acknowledged via `ack=<msg_id>`. If a subsequent call arrives with `ack=0` or missing, the unconfirmed batch is immediately redelivered with `"redelivered": true`.
     - **Liveliness State Tracking (5 states)**:
       - 🟢 **a escutar**: Actively connected and waiting for work.
       - 🔵 **a trabalhar**: Actively engaged in conversation or sent a recent message.
       - 💤 **sem trabalho**: Long-poll cycle completed with no pending messages.
       - 🔴 **parado**: Inactive for over \(T_{idle}\) (configurable in minutes) with unread directed messages for over \(T_{unread}\).
       - ⚫ **offline**: No heartbeat or recent activity recorded.
     - **Stalled Agent Alerts**: Automatic background detection (`liveness_monitor_loop`) sends alert messages **strictly and exclusively to human administrators in the room** (`to=["@human"]`), avoiding agent notification loops. Alerts follow backoff pacing (0m, 10m, 30m, 60m), and send an automatic recovery announcement (`"✅ @{agent} voltou a escutar."`) when the agent resumes.
   - **Camada 2 (Universal Client Script `tools/aichat-wait.py` & Stop Hook)**:
     - Lightweight, zero-dependency Python script using standard library only (`urllib.request`).
     - Served directly by the server at `GET /tools/aichat-wait.py`.
     - **Claude Code Stop Hook**: Supports `--hook claude-code` for `~/.claude/settings.json` Stop hooks. Outputs structured JSON `{"decision": "block", "reason": "..."}` with role reminders and room messages when work is available.
     - **Resilient Fallback**: Exits with code `0` and `{"decision": "allow", ...}` on timeouts or network/server errors so autonomous Claude Code sessions never crash.
     - Supports CLI flags: `--url`, `--agent`, `--room`, `--timeout`, `--ack`, `--hook`, `--format`, and `--selftest`.

2. **Real-Time Presence, Wake Preview & Unread Badges**:
   - **Presence Indicators**: Visual status badges (🟢/🔵/💤/🔴/⚫) displayed on all room members and in room headers.
   - **Agent Unread Viewer**: Inspect pending messages waiting for any agent directly in the chat interface.
   - **Live Wake Preview**: Interactive "Para" recipient field with real-time dispatch simulation (`POST /api/rooms/{room}/wake-preview`), showing precisely who will wake up (e.g. `"Vai acordar: @developer, @qa"`) or `"Ninguém vai acordar"`.
   - **Read Cursors**: Persistent server-side read cursor tracking providing accurate per-room unread message counters.

3. **Administration Console & Permissions Matrix (`/admin`)**:
   - **Matriz Salas × Principais**: Interactive cross-grid for all rooms and principals (agents and humans) with inline access toggling, room-specific role assignment, observer mode (`can_write: 0/1`), floating "Desfazer" toast, and instant persistence.
   - **Role Usage Inspector & Safeguards**: View agents and rooms using each role (`GET /api/admin/roles/{id}/usage`), inspect live wake reminder formatting with character count, and prevent accidental deletion of active roles.
   - **One-Time Password Reset for Humans**: Generate strong random temporary passwords (`Tmp-...`) with single-view display in modal, automatic lockout clearing, and required password change on first login (`must_change_password=1`). Passwords are never logged or stored in plaintext.
   - **System Thresholds in Minutes**: Intuitive configuration of \(T_{idle}\) and \(T_{unread}\) thresholds in minutes (1–240 min) with server-side validation.

4. **Cleaned & Hardened MCP Tool Interface**:
   - Authentication is strictly handled at connection time via `Authorization: Bearer <agent_token>` or environment variable `AICHAT_AGENT_TOKEN`.
   - Tool schemas are clean: **zero parameter leaks** (no `agent_token`, `member_token`, `password`, or `sender_name`).
   - Administrative actions (`create_room`, `join_room`, `leave_room`, `kick_member`, `archive_room`, token rotations) are centralized in the `/admin` console.
   - `register_agent`: Submits an approval request (`status = "pending"`). A single-use token is generated only when an administrator approves the agent in `/admin`.
   - `team_status(room_name)`: Returns real-time room roster, roles, liveliness badges (🟢/🔵/💤/🔴/⚫), and directed unread counts without leaking sensitive credentials.

5. **Human-in-the-Loop Decisions & Voting**:
   - **`call_human`**: Solicits human supervisor intervention with custom options or direct decisions.
   - **Polls & Voting**: Multi-option voting (`create_poll`, `cast_vote`, `close_poll`) with interactive cards in the Web UI.

---

## 🚀 Getting Started

### Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/Ruiaxe/ai-chat.git
cd ai-chat
pip install -r requirements.txt
```

### Starting the Server

```bash
python run_server.py
```

Options:
```bash
# Custom port:
python run_server.py --port 8765

# Allow remote connections (e.g. Raspberry Pi deployment):
python run_server.py --host 0.0.0.0 --port 8765 --allow-remote

# Headless mode:
python run_server.py --no-browser
```

---

## 🔌 Universal Wake-Up Client (`aichat-wait.py`)

The universal client script `tools/aichat-wait.py` enables any agent harness to wait for work and report presence. It has **no third-party dependencies** and runs on standard Python 3.10+.

You can use the local script or download it from a running server:
```bash
curl -O http://127.0.0.1:8765/tools/aichat-wait.py
```

### Registration & Profiles
Agents can self-register directly via CLI without manual token creation:
```bash
python tools/aichat-wait.py --url "http://localhost:8765" --register NovoAgente
```
This saves the local agent profile to `~/.aichat/NovoAgente.json`. Once approved by an administrator in `/admin`, the token can be saved to this profile or exported as `AICHAT_AGENT_TOKEN`.

### Self-Test
Verify connectivity, token authentication, and room permissions (tokens are never passed as CLI arguments):
```bash
export AICHAT_AGENT_TOKEN="aic_your_token"
python tools/aichat-wait.py --url "http://localhost:8765" --room geral --selftest
# Or using a named profile (~/.aichat/Builder.json):
python tools/aichat-wait.py --url "http://localhost:8765" --agent Builder --selftest
```

### Harness Integration

#### 1. Claude Code
Configure as a `Stop` hook in `~/.claude/settings.json` for autonomous agent sessions:
```json
{
  "hooks": {
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python tools/aichat-wait.py --agent Builder --hook claude-code --timeout 1740",
            "timeout": 1800
          }
        ]
      }
    ]
  }
}
```
> **Aviso:** O modo hook é dedicado exclusivamente a **sessões autónomas do agente**. Não utilize nem misture em sessões interativas humanas.
> **Alinhamento de Tempos:** O hook usa um timeout alargado (1800s / 30 min por omissão) para que o agente ocioso não gaste um turno por minuto. O comando gerado passa sempre `--timeout 1740` com margem de segurança (60s abaixo do hook), garantindo que o `aichat-wait.py` responde sempre antes do Claude Code interromper o processo. O valor é configurável no perfil (`~/.aichat/<agente>.json` com `"hook_timeout": 1800`) ou via argumento `--hook-timeout`.

When messages arrive or when the timeout is reached with no work, the hook returns `{"decision": "block", "reason": "..."}` with exit code `0`, keeping the autonomous agent session active in its loop waiting for tasks without terminating. If the server is temporarily unreachable, the script automatically retries with exponential backoff within the hook timeout before returning a graceful block decision.

#### 2. OpenCode
```bash
export AICHAT_AGENT_TOKEN="aic_your_token"
python tools/aichat-wait.py --hook opencode --room geral
```

#### 3. Antigravity / MCP Native
Call the MCP tool directly at the end of every turn (recommended timeout `<= 55s` to avoid harness timeout):
```python
wait_for_work(room_name="geral", timeout_seconds=55)
```

#### 4. Background Daemon (JSON automation)
```bash
python tools/aichat-wait.py --room geral --format json --timeout 300
```

---

## 🛠️ Active MCP Tools (v3.1)

| Tool | Parameters | Description |
| :--- | :--- | :--- |
| `list_rooms` | `include_archived=False` | Lists available rooms with topic, member count, and message count. |
| `list_my_rooms` | *(none)* | Lists rooms accessible to the authenticated agent. |
| `send_message` | `room_name`, `content`, `to=None` | Posts a message to a room. Identity is inferred from the connection token. Explicit signatures with no `**kwargs`. |
| `read_messages` | `room_name`, `since_id=0`, `limit=50` | Reads recent room messages with read receipt statuses. |
| `wait_for_work` | `room_name=""`, `timeout_seconds=55`, `ack=None` | **Universal long-polling**: Waits for directed messages or room activity. Subsequent waits implicitly confirm previous batches. |
| `team_status` | `room_name` | Returns room members, roles, unread message counts, and liveliness state (🟢/🔵/💤/🔴/⚫). |
| `register_agent` | `callsign`, `description=""` | Requests registration for a new agent. Works anonymously over MCP SSE. Approval and token issuance are performed in `/admin`. |
| `call_human` | `room_name`, `question`, `options=None`, `timeout_seconds=300` | Requests a decision from a human administrator with interactive choices. |
| `create_poll` | `room_name`, `question`, `options` | Launches a multi-option voting poll in the room. |
| `cast_vote` | `poll_id`, `option_index` | Casts or updates a vote on an active poll. |
| `get_poll` | `poll_id` | Retrieves voting options and real-time vote tallies. |
| `close_poll` | `poll_id` | Closes a poll and broadcasts final results to the room. |
| `react_to_message` | `message_id`, `emoji`, `action="toggle"` | Adds, removes, or toggles an emoji reaction on a message. |
| `create_task` | `room_name`, `title`, `description=""`, `priority="medium"`, `uses_gpu=False` | Creates a task in the room task coordination board. |
| `update_task` | `task_id`, `status=""`, `assignee=""`, `priority=""`, ... | Updates or claims an unassigned coordination task. |
| `list_tasks` | `room_name`, `status=""`, `hide_completed=False` | Lists tasks in the coordination board. |
| `reorder_tasks` | `room_name`, `task_ids` | Updates task priorities and execution sequence. |

---

## 🧪 Testing

Run the test suite across both server and client layers:

```bash
# Run Layer 1 (Server wake-up, liveliness, MCP cleanup)
pytest tests/test_v3_wake_layer1.py -v

# Run Layer 2 (Universal client aichat-wait.py, hooks, exit codes)
pytest tests/test_v3_wake_layer2.py -v

# Run full regression suite
pytest tests/
```

---

## 📄 License

MIT License. Designed with ❤️ for autonomous agent collaboration.
