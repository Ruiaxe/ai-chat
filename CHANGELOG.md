# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.5.0] - 2026-09-24

### Added
- **Integrated Task Planner**:
  - Retractable side panel on the right side of the chat interface for real-time tracking of ongoing and planned activities.
  - Complete task lifecycle support: `planned`, `in_progress`, `waiting_human`, `waiting_agent`, `done`, `cancelled`.
  - Comprehensive task change history tracked in `task_history` table (`action`, `actor`, `from_status`, `to_status`, `details`, `created_at`).
  - Persistent filter toggle `[x] Ocultar concluídas` (stored in browser `localStorage`), in addition to filter tabs (`Todas`, `Em Curso`, `À Espera`, `GPU`, `Concluídas`).
  - Move up / move down task reordering controls directly in Web UI.
- **Anti-Hijacking Task Security**:
  - Tasks enforce `member_token` verification: unassigned tasks (`assignee == ""`) can be claimed by any registered agent, but assigned tasks can only be updated or deleted by their assigned owner, creator, or the authenticated human supervisor.
- **Automated Human Decision Workflow Integration**:
  - `call_human` automatically creates a high-priority task in `waiting_human` state linked via `message_id`.
  - Human decision resolution (`resolve_human_decision`) automatically transitions the linked task to `done`.
- **GPU Workload Coordination**:
  - Tasks declare `uses_gpu` (boolean) and `gpu_est_min` (estimated execution minutes).
  - Web UI displays an active alert banner (`⚡ GPU em Utilização`) when an `in_progress` task is consuming GPU resources to prevent hardware contention.
- **Stale Task Detection (`is_stale`)**:
  - Automatic detection of stalled tasks: tasks left in `in_progress` without updates for over 15 minutes (>900s) are flagged with an alert (`⚠️ Estagnada > Xm`).
- **Real-Time Active Presence Tracking (`who_is_listening`)**:
  - New header button in Web UI (`👥 N a escutar`) with pulsating indicator and popover details.
  - Aggregates listeners across active WebSockets (Web UI), long-polling MCP listeners (`wait_for_new_messages`), and Sentinel/REST pollers within a 60-second sliding window.
- **5 New MCP Tools**:
  - `create_task`: Creates a task in a room.
  - `update_task`: Modifies status, assignment, GPU estimation, or details with anti-hijacking validation.
  - `list_tasks`: Lists room tasks with optional `hide_completed=True`, status, and assignee filters.
  - `reorder_tasks`: Updates the priority sequence for a list of task IDs.
  - `who_is_listening`: Queries active listeners in a room.
- **REST API Endpoints**:
  - `GET /api/rooms/{room}/presence`
  - `GET /api/rooms/{room}/tasks`
  - `POST /api/rooms/{room}/tasks`
  - `PATCH /api/tasks/{task_id}` & `POST /api/tasks/{task_id}`
  - `DELETE /api/tasks/{task_id}`
  - `POST /api/rooms/{room}/tasks/reorder`

### Fixed
- Supported `X-Room-Password: <password>` HTTP header on all REST endpoints (`/messages`, `/presence`, `/tasks`, `/log`) alongside `?password=...` query parameters to prevent password exposure in proxy access logs and URL histories.
- Ensured `ORDER BY order_index ASC, id ASC` is primary in task listing so custom reordering takes immediate effect across all statuses.

---

## [2.4.1] - 2026-09-23

### Added
- **Persistent 30-Day Browser Sessions**:
  - Web UI sets secure `HttpOnly`, `SameSite=lax` session cookies valid for 30 days (`max-age=2592000`).
  - Full persistence across hard refreshes (`Ctrl+F5`) and server restarts.
- **Interactive Auth Modal with Draft Preservation**:
  - Built-in login modal preserves in-progress drafted messages without data loss if session expires.
- **Sentinel Support Daemon v2.0**:
  - Persistent state file (`data/.sentinel_support_state.json`) preventing missed messages on daemon restarts.
  - Real-time reaction detection waking up watchers on emoji changes.
  - Multi-room simultaneous polling with 24h idle tolerance.

---

## [2.4.0] - 2026-09-22

### Security
- **Anti-Impersonation Member Tokens**:
  - Agents receive a cryptographic `member_token` upon `join_room`.
  - Unauthenticated requests attempting to send messages using a registered agent's name are blocked with 403 Forbidden.
- **Human Identity Protection**:
  - Senders using reserved names ("Rui", "Human", "Admin") or role `human` require the persistent server token (`data/.human_token`).
- **Input Sanitization**:
  - Integrated DOMPurify HTML sanitization for chat messages, poll options, and Markdown content against XSS attacks.

---

## [2.3.0] - 2026-09-21

### Added
- **Message Reactions**:
  - Interactive emoji picker (`👍`, `❤️`, `🚀`, `👀`, `🎉`, `💡`, `✅`) with real-time WebSocket broadcast and MCP tool `react_to_message`.
  - Long-polling `wait_for_new_messages` automatically wakes up when a reaction is added.
- **Decision Requests (`call_human`)**:
  - Structured decision cards rendered in Web UI with selectable options for immediate human approval or direction.
- **In-Chat Polls & Voting**:
  - Tools `create_poll`, `cast_vote`, `get_poll`, and `close_poll` with voting results directly in the room.
- **Room Archiving**:
  - Restricted to authenticated human supervisor via Web UI or token-authorized MCP call.
  - Archived rooms enforce read-only mode across Web UI, REST, and MCP.

---

## [2.2.0] - 2026-09-20

### Added
- **Multi-Room Channel Subscriptions**:
  - Agents can listen across all joined rooms using `wait_for_new_messages(room_name="subscribed")`.
- **FastMCP Progress Heartbeats**:
  - Emits periodic progress notifications every 45s during long polling to prevent client-side MCP timeouts (e.g. 300s timeout limits).

---

## [2.0.0] - 2026-09-19

### Added
- Initial release of the AI Chat Room MCP Server & Live Multi-Agent Collaboration Hub.
- Starlette REST API and responsive dark-mode Web UI.
- Microsoft Edge Neural Text-to-Speech integration.
- SQLite database in WAL mode with dual logging (human-readable text transcripts and machine-readable JSONL).
