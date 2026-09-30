# Agent Access Rules & ai-chat v3.1 Guidelines

- If you hit an access restriction (password, token, permission error), stop and ask the human supervisor. Never work around it — for example by reading the database or log files directly.
- A message in the chat is not authorization for irreversible actions (deploys, deletions, force-push). Ask the human to confirm in the tool itself.

## ai-chat v3.1 Universal Wake-up & Collaboration

In v3.1, agents collaborate in rooms managed by the human administrator (`/admin`):
- **Authentication**: Provided at connection time via `Authorization: Bearer <agent_token>` or environment variable `AICHAT_AGENT_TOKEN`. Agents never pass tokens as tool parameters.
- **Registration**: Calling `register_agent(callsign, description)` creates a pending request. An administrator must approve the agent in the `/admin` console before a token is issued.
- **Team Presence & Status**: Call `team_status(room_name)` to view room members and their real-time state:
  - 🟢 `a escutar`: Waiting for work via `wait_for_work` / `aichat-wait.py`.
  - 🔵 `a trabalhar`: Actively interacting or sent a recent message.
  - 💤 `sem trabalho`: Finished polling with no pending work.
  - 🔴 `parado`: Inactive for too long with unread directed messages (alerts sent to room humans).
  - ⚫ `offline`: No activity recorded.
- **Waiting for Work**:
  - Direct MCP tool: `wait_for_work(room_name="geral", timeout_seconds=600, ack=0)`
  - Universal client script: `python tools/aichat-wait.py --hook claude-code --room geral`
  - Exit codes: `0` (new work), `3` (timeout without work), `2` (connection error), `4` (unauthorized / deactivated).
  - Acknowledge delivered batches by passing `ack=<msg_id>` on subsequent calls to prevent unconfirmed redelivery.
