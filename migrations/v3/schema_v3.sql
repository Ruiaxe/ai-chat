-- ai-chat v3 schema (SQLite)
--
-- Design rules:
--   * Every reference uses integer IDs (never names). Names are display data only.
--   * Humans and agents share one identity table (principals) and one name namespace.
--   * Secrets are stored only as hashes (agent tokens, session IDs, human passwords).
--   * Access is decided server-side through room_access; rooms have no passwords.
--   * Timestamps are ISO-8601 UTC strings ending in 'Z' (dates without time stay 'YYYY-MM-DD').
--
-- Enable per connection: PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;

CREATE TABLE schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL,
    notes       TEXT NOT NULL DEFAULT ''
);

-- ---------------------------------------------------------------- identity

CREATE TABLE principals (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kind          TEXT NOT NULL CHECK (kind IN ('human', 'agent')),
    name          TEXT NOT NULL UNIQUE COLLATE NOCASE,   -- login username / agent callsign
    display_name  TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'pending')),
    is_system     INTEGER NOT NULL DEFAULT 0,            -- infrastructure agents (e.g. sentinels)
    is_legacy     INTEGER NOT NULL DEFAULT 0,            -- created by migration from a bare sender name; never had credentials
    created_at    TEXT NOT NULL
);

CREATE TABLE humans (
    principal_id          INTEGER PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
    access_role           TEXT NOT NULL DEFAULT 'user' CHECK (access_role IN ('admin', 'user')),
    password_hash         TEXT NOT NULL DEFAULT '',      -- 'scrypt$<n>$<r>$<p>$<salt_hex>$<hash_hex>'; '' = cannot log in
    must_change_password  INTEGER NOT NULL DEFAULT 1,
    failed_logins         INTEGER NOT NULL DEFAULT 0,
    locked_until          TEXT,                          -- UTC; NULL = not locked
    last_login_at         TEXT
);

CREATE TABLE agent_roles (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    role_key       TEXT NOT NULL UNIQUE COLLATE NOCASE,  -- e.g. 'developer', 'qa'
    display_name   TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    reminder_text  TEXT NOT NULL DEFAULT '',             -- sent once per wake-up; admin-editable only
    is_builtin     INTEGER NOT NULL DEFAULT 0,
    updated_at     TEXT NOT NULL,
    updated_by     INTEGER REFERENCES principals(id) ON DELETE SET NULL
);

CREATE TABLE agents (
    principal_id              INTEGER PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
    default_role_id           INTEGER REFERENCES agent_roles(id) ON DELETE SET NULL,
    harness                   TEXT NOT NULL DEFAULT 'other' CHECK (harness IN ('claude-code', 'antigravity', 'opencode', 'other')),
    wake_mode                 TEXT NOT NULL DEFAULT 'tool' CHECK (wake_mode IN ('hook', 'background', 'tool')),
    listening_now             INTEGER NOT NULL DEFAULT 0,
    last_listen_at            TEXT,
    last_activity_at          TEXT,
    unconfirmed_batch_ids     TEXT NOT NULL DEFAULT '',
    unconfirmed_delivered_at  TEXT,
    stalled_alert_count       INTEGER NOT NULL DEFAULT 0,
    last_stalled_alert_at     TEXT
);

-- An agent may hold several tokens during a rotation window; each is revocable on its own.
CREATE TABLE credentials (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    principal_id  INTEGER NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    token_hash    TEXT NOT NULL UNIQUE,                  -- sha256 hex of a >=256-bit random token
    token_hint    TEXT NOT NULL DEFAULT '',              -- last 4 chars, for display only
    created_at    TEXT NOT NULL,
    last_used_at  TEXT,
    revoked_at    TEXT
);
CREATE INDEX idx_credentials_principal ON credentials(principal_id);

CREATE TABLE human_sessions (
    session_hash  TEXT PRIMARY KEY,                      -- sha256 hex of the cookie value
    principal_id  INTEGER NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    last_seen_at  TEXT
);
CREATE INDEX idx_sessions_expires ON human_sessions(expires_at);

-- ---------------------------------------------------------------- rooms & access

CREATE TABLE rooms (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    topic        TEXT NOT NULL DEFAULT '',
    is_archived  INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL,
    created_by   INTEGER REFERENCES principals(id) ON DELETE SET NULL
);

-- Admins see every room; everyone else sees only rooms listed here.
CREATE TABLE room_access (
    room_id       INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    principal_id  INTEGER NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    role_id       INTEGER REFERENCES agent_roles(id) ON DELETE SET NULL,  -- role in THIS room (agents)
    can_write     INTEGER NOT NULL DEFAULT 1,
    granted_by    INTEGER REFERENCES principals(id) ON DELETE SET NULL,
    granted_at    TEXT NOT NULL,
    PRIMARY KEY (room_id, principal_id)
);
CREATE INDEX idx_room_access_principal ON room_access(principal_id);

-- Server-side read position per principal and room (replaces client-managed since_id).
CREATE TABLE read_cursors (
    principal_id     INTEGER NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    room_id          INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    last_message_id  INTEGER NOT NULL DEFAULT 0,
    updated_at       TEXT NOT NULL,
    PRIMARY KEY (principal_id, room_id)
);

-- ---------------------------------------------------------------- messages

CREATE TABLE messages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,     -- v2 IDs are preserved by the migration
    room_id       INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    sender_id     INTEGER REFERENCES principals(id) ON DELETE SET NULL,  -- NULL for system messages
    sender_kind   TEXT NOT NULL CHECK (sender_kind IN ('human', 'agent', 'system')),
    sender_name   TEXT NOT NULL,                         -- display snapshot at send time
    content       TEXT NOT NULL,
    message_type  TEXT NOT NULL DEFAULT 'text',
    metadata      TEXT NOT NULL DEFAULT '{}',            -- JSON
    is_verified   INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);
CREATE INDEX idx_messages_room_id ON messages(room_id, id);

-- Structured addressing. No rows = legacy/unspecified (treated as 'all').
CREATE TABLE message_recipients (
    message_id   INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    target_kind  TEXT NOT NULL CHECK (target_kind IN ('all', 'role', 'principal')),
    target_id    INTEGER,                                -- agent_roles.id or principals.id; NULL for 'all'
    CHECK ((target_kind = 'all') = (target_id IS NULL))
);
CREATE INDEX idx_recipients_message ON message_recipients(message_id);
CREATE INDEX idx_recipients_target ON message_recipients(target_kind, target_id);

CREATE TABLE reactions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id    INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    principal_id  INTEGER NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    emoji         TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    UNIQUE (message_id, principal_id, emoji)
);
CREATE INDEX idx_reactions_msg ON reactions(message_id);

-- ---------------------------------------------------------------- polls

CREATE TABLE polls (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id     INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    creator_id  INTEGER REFERENCES principals(id) ON DELETE SET NULL,
    question    TEXT NOT NULL,
    options     TEXT NOT NULL,                           -- JSON array of strings
    is_closed   INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    closed_at   TEXT
);

CREATE TABLE poll_votes (
    poll_id       INTEGER NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
    voter_id      INTEGER NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    option_index  INTEGER NOT NULL,
    created_at    TEXT NOT NULL,
    PRIMARY KEY (poll_id, voter_id)
);

-- ---------------------------------------------------------------- tasks (Gantt-ready)

CREATE TABLE tasks (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id           INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    parent_task_id    INTEGER REFERENCES tasks(id) ON DELETE SET NULL,
    title             TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    status            TEXT NOT NULL DEFAULT 'planned'
                      CHECK (status IN ('planned', 'in_progress', 'waiting_human', 'waiting_agent', 'done', 'cancelled')),
    priority          TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
    assignee_id       INTEGER REFERENCES principals(id) ON DELETE SET NULL,
    waiting_for_id    INTEGER REFERENCES principals(id) ON DELETE SET NULL,
    order_index       INTEGER NOT NULL DEFAULT 0,
    message_id        INTEGER REFERENCES messages(id) ON DELETE SET NULL,
    uses_gpu          INTEGER NOT NULL DEFAULT 0,
    gpu_est_min       INTEGER NOT NULL DEFAULT 0,
    resource          TEXT,
    start_at          TEXT,
    due_at            TEXT,
    progress_percent  INTEGER NOT NULL DEFAULT 0 CHECK (progress_percent BETWEEN 0 AND 100),
    created_by        INTEGER REFERENCES principals(id) ON DELETE SET NULL,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);
CREATE INDEX idx_tasks_room_status ON tasks(room_id, status);
CREATE INDEX idx_tasks_room_order ON tasks(room_id, order_index);
CREATE INDEX idx_tasks_parent ON tasks(parent_task_id);

-- Cycle detection is enforced by the application before insert.
CREATE TABLE task_dependencies (
    task_id             INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    depends_on_task_id  INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    PRIMARY KEY (task_id, depends_on_task_id),
    CHECK (task_id <> depends_on_task_id)
);
CREATE INDEX idx_task_deps_reverse ON task_dependencies(depends_on_task_id);

CREATE TABLE task_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id      INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    action       TEXT NOT NULL,
    actor_id     INTEGER REFERENCES principals(id) ON DELETE SET NULL,
    actor_name   TEXT NOT NULL DEFAULT '',               -- display snapshot
    from_status  TEXT NOT NULL DEFAULT '',
    to_status    TEXT NOT NULL DEFAULT '',
    details      TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL
);
CREATE INDEX idx_task_history_task ON task_history(task_id);

-- ---------------------------------------------------------------- calendar & resources

-- room_id NULL + owner_id set  = personal event
-- room_id NULL + owner_id NULL = global resource booking (e.g. GPU)
CREATE TABLE calendar_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id         INTEGER REFERENCES rooms(id) ON DELETE CASCADE,
    owner_id        INTEGER REFERENCES principals(id) ON DELETE CASCADE,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    start_at        TEXT NOT NULL,
    end_at          TEXT,
    event_type      TEXT NOT NULL DEFAULT 'event',
    task_id         INTEGER REFERENCES tasks(id) ON DELETE SET NULL,
    resource        TEXT,
    target_id       INTEGER REFERENCES principals(id) ON DELETE SET NULL,
    status          TEXT NOT NULL DEFAULT 'scheduled',
    wake_on_start   INTEGER NOT NULL DEFAULT 1,
    wake_on_end     INTEGER NOT NULL DEFAULT 0,
    notified_start  INTEGER NOT NULL DEFAULT 0,
    notified_end    INTEGER NOT NULL DEFAULT 0,
    created_by      INTEGER REFERENCES principals(id) ON DELETE SET NULL,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);
CREATE INDEX idx_calendar_room_start ON calendar_events(room_id, start_at);
CREATE INDEX idx_calendar_owner_start ON calendar_events(owner_id, start_at);
CREATE INDEX idx_calendar_resource ON calendar_events(resource, start_at, end_at);
CREATE INDEX idx_calendar_status ON calendar_events(status, notified_start, start_at);

-- ---------------------------------------------------------------- audit

CREATE TABLE audit_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id     INTEGER REFERENCES principals(id) ON DELETE SET NULL,
    actor_name   TEXT NOT NULL DEFAULT '',
    action       TEXT NOT NULL,
    target_type  TEXT NOT NULL DEFAULT '',               -- 'room', 'principal', 'role', 'credential', ...
    target_id    INTEGER,
    room_id      INTEGER REFERENCES rooms(id) ON DELETE SET NULL,
    status       TEXT NOT NULL DEFAULT 'ok',
    details      TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL
);
CREATE INDEX idx_audit_room ON audit_log(room_id, created_at);
CREATE INDEX idx_audit_actor ON audit_log(actor_id, created_at);

-- ---------------------------------------------------------------- seed data

INSERT INTO agent_roles (role_key, display_name, description, reminder_text, is_builtin, updated_at) VALUES
 ('developer', 'Programador', 'Implementa e refatora código, corrige bugs e escreve testes unitários do que implementa.',
  'Tu és o Programador. Foca-te em implementar e corrigir código. Para desenho visual, testes de aceitação, deploys ou planeamento, pede à equipa responsável.', 1, strftime('%Y-%m-%dT%H:%M:%SZ','now')),
 ('project_manager', 'Gestor de Projeto', 'Planeia tarefas, prazos e dependências; coordena a equipa e escala decisões ao humano.',
  'Tu és o Gestor de Projeto. Planeia, atribui e acompanha tarefas; não implementes código. Escala ao humano as decisões que não são tuas.', 1, strftime('%Y-%m-%dT%H:%M:%SZ','now')),
 ('ui_designer', 'Designer de Interfaces', 'Desenha interfaces, componentes visuais e fluxos de utilização.',
  'Tu és o Designer de Interfaces. Trata do visual e da usabilidade. Para lógica de servidor ou testes, pede à equipa responsável.', 1, strftime('%Y-%m-%dT%H:%M:%SZ','now')),
 ('qa', 'Qualidade e Controlo', 'Revê entregas, procura falhas e valida critérios de aceitação.',
  'Tu és Qualidade e Controlo. Revê e valida; não corrijas tu próprio o código de outros — reporta com provas e pede a correção.', 1, strftime('%Y-%m-%dT%H:%M:%SZ','now')),
 ('tester', 'Testes', 'Escreve e corre testes de integração, regressão e desempenho.',
  'Tu és o responsável por Testes. Escreve e corre testes e reporta resultados. Correções de código são do Programador.', 1, strftime('%Y-%m-%dT%H:%M:%SZ','now')),
 ('devops', 'DevOps', 'Infraestrutura, deploys, serviços, backups e monitorização.',
  'Tu és DevOps. Trata de infraestrutura e deploys. Ações irreversíveis exigem confirmação humana na própria ferramenta, nunca só no chat.', 1, strftime('%Y-%m-%dT%H:%M:%SZ','now')),
 ('security', 'Auditor de Segurança', 'Revê permissões, autenticação e vulnerabilidades.',
  'Tu és o Auditor de Segurança. Analisa e reporta riscos com provas; não contornes restrições de acesso para o demonstrar.', 1, strftime('%Y-%m-%dT%H:%M:%SZ','now')),
 ('architect', 'Arquiteto', 'Decisões de arquitetura, contratos entre componentes e revisão de desenho técnico.',
  'Tu és o Arquiteto. Define e revê o desenho técnico; delega a implementação ao Programador.', 1, strftime('%Y-%m-%dT%H:%M:%SZ','now')),
 ('docs', 'Documentação', 'Escreve e mantém documentação técnica e de utilizador.',
  'Tu és o responsável pela Documentação. Mantém a documentação correta e atual; confirma factos com quem implementou.', 1, strftime('%Y-%m-%dT%H:%M:%SZ','now'));

-- ---------------------------------------------------------------- system settings

CREATE TABLE system_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

INSERT INTO system_settings (key, value, updated_at) VALUES
 ('t_idle_seconds', '1800', strftime('%Y-%m-%dT%H:%M:%SZ','now')),
 ('t_unread_seconds', '120', strftime('%Y-%m-%dT%H:%M:%SZ','now')),
 ('max_wake_timeout', '600', strftime('%Y-%m-%dT%H:%M:%SZ','now'));
