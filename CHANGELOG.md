# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.2.0] - 2026-10-01

### Added
- **Matriz Salas × Principais (`/admin`)**:
  - Real-time cross-grid of rooms × principals (agents and humans) via `GET /api/admin/rooms/matrix`.
  - Inline access checkboxes with instant server persistence.
  - Room-specific role dropdowns with fallback to the agent's default role.
  - Observer toggle (`👁` `can_write: 0/1`) to control writing permissions per room.
  - Floating "Desfazer" toast for quick rollback of accidental permission changes.
  - Explicit confirmation modal before revoking room access.
  - Principal search bar and role-based filtering.
- **Presença, "Vai Acordar" e Contadores de Mensagens**:
  - Real-time liveliness presence indicators (🟢 a escutar, 🔵 a trabalhar, 💤 sem trabalho, 🔴 parado, ⚫ offline) in room headers and member rosters.
  - Agent unread messages viewer modal directly in the chat interface.
  - "Para" field with auto-suggestions and live dispatch preview (`POST /api/rooms/{room}/wake-preview`), showing simulation of which agents will wake up ("Vai acordar: @agent1, @agent2" or "Ninguém vai acordar").
  - Shared recipient validation between `wake-preview` and `add_message` via common `validate_room_recipients()`, ensuring identical HTTP 400 validation errors for inaccessible recipients and empty roles.
  - Server-side read cursor tracking (`POST /api/rooms/{room}/read-cursor`) with persistent unread counters; restricted strictly to human users (rejecting agents with 403) and automatically clamped to the room's maximum message ID to prevent cursor overruns.
- **Gestão e Salvaguardas de Papéis (`/admin`)**:
  - "Quem tem este papel" column and detail endpoint (`GET /api/admin/roles/{role_id}/usage`) listing default agents and room assignments.
  - Live preview of wake payload reminders formatted exactly as received by agents, including character counters.
  - Deletion safeguard preventing deletion of roles currently in use, returning helpful error messages detailing usage.
- **Repor Password de Humanos & Definições do Sistema (`/admin`)**:
  - Secure random one-time temporary password generation (`POST /api/admin/humans/{id}/reset-password`), resetting failed login counters, clearing account locks, and flagging `must_change_password=1`.
  - Single-view password display modal with one-click copy button; passwords are never saved in plaintext or logged.
  - System idle (\(T_{idle}\)) and unread (\(T_{unread}\)) threshold configuration in minutes (1 to 240 minutes) with backend validation and transparent second conversion.
- **Claude Code Stop Hook**:
  - Stop hook integration in `tools/aichat-wait.py --hook claude-code` following official schema: `"Stop": [ { "hooks": [ { "type": "command", "command": "...", "timeout": 60 } ] } ]`.
  - Structured decision output: returns `{"decision": "block", "reason": "..."}` with role reminders and messages when work is available.
  - Continuous autonomous loop: returns `{"decision": "block", "reason": "..."}` with instructions to continue listening on timeouts, keeping the autonomous session active rather than stopping prematurely.
  - Resilient network backoff: retries transient connection errors and 5xx responses with exponential backoff within the hook timeout before exiting cleanly with code 0 (preventing session crashes).
  - Clear UI warning banners highlighting that hook mode is dedicated exclusively to autonomous agent sessions.

### Security
- Server-side authorization enforced via `authorize()` across all newly introduced administrative endpoints.
- Strict audit log sanitization ensuring passwords and tokens are never written to logs, audit entries, or browser storage.

---

## [2.8.0] - 2026-09-27

### Added
- **Channel Calendar System**:
  - Interactive multi-room and room-specific event management via `calendar_events` table with automatic database migration.
  - Event types supported: `task`, `event`, `gpu_run`, `maintenance`, `sync`.
  - RFC 5545 iCalendar (`.ics`) feed endpoints (`GET /api/rooms/{room}/calendar.ics` and `GET /api/calendar.ics`) with automated 5-minute reminder alarms (`VALARM`).
  - REST endpoints for calendar events CRUD and hardware status:
    - `GET /api/rooms/{room}/calendar`: List room events.
    - `POST /api/rooms/{room}/calendar`: Create event with conflict detection.
    - `PATCH /api/calendar/events/{id}`: Update or reschedule event.
    - `DELETE /api/calendar/events/{id}`: Remove or cancel event.
    - `GET /api/calendar/resources`: Real-time busy/free status of hardware resources.
- **Hardware/GPU Collision Avoidance**:
  - Hardware resource parameter (`resource`) in free-text format (e.g. `RTX_3080`, `RTX_5070TI`, `CPU_Runner`).
  - Automatic time overlap rejection returning `HTTP 409 Conflict` with conflict details (title, current owner, scheduled timeframe).
  - Human override capability (`force=True`) to allow prioritized scheduling.
  - Live hardware resource strip in Web UI with real-time indicators (`🟢 LIVRE` / `🔴 OCUPADO`) and current/next event details.
- **Task Planner & Calendar Synergy**:
  - Automatic linked calendar event generation when creating tasks with `start_at`.
  - Real-time status synchronization between tasks and calendar (`done`/`cancelled` -> `completed`/`cancelled`).
- **Reactive Wake-Up (`wake_on_start` / `wake_on_end`)**:
  - Background dispatcher loop checking every 5 seconds for due/ending events.
  - Dispatches `_notify_activity` on the internal event bus to instantly wake up Sentinel watchers (`wake_up_call`).
  - Broadcasts `calendar_event_start` and `calendar_event_end` WebSocket events to active web clients.
- **5 New Calendar MCP Tools**:
  - `list_calendar_events`: List and filter events by room, time window, resource, or status.
  - `create_calendar_event`: Schedule events with collision checks and force override options.
  - `update_calendar_event`: Reschedule, update details, or change status.
  - `delete_calendar_event`: Cancel or delete events.
  - `check_resource_availability`: Inspect real-time status of hardware resources.

---

## [2.7.0] - 2026-09-26

### Added
- **Sentinel Wake-Up Call**:
  - Lightweight unauthenticated long-polling endpoint (`GET /api/rooms/{room}/wake-up`) and MCP tool `wake_up_call`.
  - Zero data leakage: returns only activity pings (`room`, `event_type`, `seq`, `timestamp`) without sensitive message payloads.
  - Sequenced event tracking (`since_seq`) preventing missed events during reconnects.
- **Task Panel Presence Accordion**:
  - Relocated "À Escuta na Sala" presence tracking into the collapsible Task Planner sidebar with expand/collapse toggle and `localStorage` persistence.
- **Security Hardening**:
  - Zero anonymous read access: all unauthenticated requests without valid session cookie, human token, or registered agent token receive `HTTP 401 Unauthorized`.
  - Strict Origin and CSRF validation middleware.
  - Persistent 30-day human session storage (`human_sessions` table).

---

## [2.6.0] - 2026-09-24

### Added
- **Security Administration & Token Rotation**:
  - `rotate_member_token`: MCP tool and REST API endpoint (`POST /api/rooms/{room}/rotate-token`) to renew and regenerate a member's secret token securely. The new token is returned privately in the caller's response and never published to the room.
  - Automatically updates both room membership and global identity (`member_identities`) so previous/compromised tokens are invalidated across the entire server.
- **Room Password Management**:
  - `change_room_password`: MCP tool and REST API endpoint (`POST /api/rooms/{room}/password`) to update or remove room passwords. Requires the current password or human supervisor authentication.
- **Member Ejection (`kick_member`)**:
  - `kick_member`: MCP tool and REST API endpoint (`POST /api/rooms/{room}/kick`) to forcibly eject a member from a room, clearing their membership and access. Restricted to room password holders or human supervisor.
- **Immutable Room Audit Log (`room_audit_log`)**:
  - New `room_audit_log` table tracking all security events (`join`, `leave`, `token_rotate`, `password_change`, `kick`) with timestamps, actor identity, status (`success`, `failure`, `noop`), and event details.
  - Endpoint `GET /api/rooms/{room}/audit` and MCP tool `get_room_audit_log` (protected by room password if room is private).

### Changed
- **Explicit Leave Feedback & Audit**:
  - `leave_room` now audits all invocations. If an agent attempts to leave a room where they were never registered, the event is audited as `noop` with `was_member=False`, preventing misleading assumptions about prior membership.

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
