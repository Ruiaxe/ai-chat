# v2 → v3 database migration

| File | Purpose |
|---|---|
| `schema_v3.sql` | v3 schema — the contract for Phase 1 (IDs everywhere, hashed secrets, room ACL, read cursors, structured recipients, Gantt-ready tasks) |
| `migrate_v2_to_v3.py` | Non-destructive migration from any v2.x `chat.db` (tested against 2.8) |
| `test_migrate_v2_to_v3.py` | Builds a v2 database with the real v2 storage code and checks the result |

## What the migration does

- **Never modifies the source.** Opens it read-only, takes a consistent snapshot with the SQLite backup API, and builds a **new** v3 file inside one transaction (deleted on any error).
- **Keeps all history with the same IDs**: rooms, messages, reactions, polls, votes, tasks, task history, calendar events, audit log. Timestamps become UTC (`--source-tz`, default `Europe/Lisbon`).
- **Identities**: every v2 `member_identities` row becomes an agent principal (status and `is_system` kept). Any other sender name becomes an **inactive legacy principal** without credentials, so history stays attributed. All v2 human aliases (`Rui`, `Human`, `admin`, …) merge into the first admin.
- **Security**: a forged `HUMAN` role is migrated as an agent message; an agent-role message under a reserved name is not attributed to the admin.
- **Secrets are not carried over**: per-room tokens, v2 agent tokens, room passwords (hashed *and* clear-text) and browser sessions are dropped. New tokens are issued to **active** agents only; the admin gets a random initial password (must change at first login).
- **Access**: agents keep access to the rooms they were members of. `--grant-public-rooms` also opens formerly public rooms to every registered agent. Protected rooms are never widened.
- **Read cursors** start at the end of each room, so nobody is woken by old history.

## Running it on the Pi

```bash
sudo systemctl stop aichat
cd /opt/aichat/ai-chat
sudo -u aichat /opt/aichat/venv/bin/python migrations/v3/migrate_v2_to_v3.py \
    --source data/chat.db --target data/chat_v3.db \
    --admin-username Rui --out-dir /opt/aichat/migration_output
```

Output in `--out-dir`: `chat_v2_backup_*.db`, `migration_report_*.json` (counts, warnings, dropped items, v2 public/protected rooms) and `credentials_*.txt` (mode 600: admin password + new agent tokens). **Distribute the tokens and delete that file.**

Only switch the server to `chat_v3.db` once the v3 code is deployed; the v2 server cannot read it. Rollback = keep running v2 on `data/chat.db` (untouched) or on the backup.

## Tests

```bash
python -m unittest migrations/v3/test_migrate_v2_to_v3.py -v
```
