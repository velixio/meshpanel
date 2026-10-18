CREATE TABLE accounts (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name  TEXT NOT NULL DEFAULT '',
    email         TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL DEFAULT '',
    totp_secret   TEXT NOT NULL DEFAULT '',
    totp_enabled  INTEGER NOT NULL DEFAULT 0,
    role          TEXT NOT NULL,
    extra_caps    INTEGER NOT NULL DEFAULT 0,
    hs_user       TEXT NOT NULL DEFAULT '',
    theme         TEXT NOT NULL DEFAULT 'paper',
    quiet_start   TEXT NOT NULL DEFAULT '',
    quiet_end     TEXT NOT NULL DEFAULT '',
    timezone      TEXT NOT NULL DEFAULT 'UTC',
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE sessions (
    id           TEXT PRIMARY KEY,           -- sha256 of the cookie token
    account_id   INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    csrf         TEXT NOT NULL,
    mfa_ok       INTEGER NOT NULL DEFAULT 0, -- password ok, 2FA passed
    ip           TEXT NOT NULL DEFAULT '',
    user_agent   TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL
);
CREATE INDEX sessions_account ON sessions(account_id);

CREATE TABLE backup_codes (
    id         INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE invites (
    token_hash TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    role       TEXT NOT NULL,
    hs_user    TEXT NOT NULL DEFAULT '',
    created_by INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE pending_registrations (
    id           INTEGER PRIMARY KEY,
    kind         TEXT NOT NULL,              -- register | ssh
    auth_id      TEXT NOT NULL,
    requester_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    hs_user      TEXT NOT NULL DEFAULT '',
    ip           TEXT NOT NULL DEFAULT '',
    user_agent   TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'pending',
    decided_by   TEXT NOT NULL DEFAULT '',
    decided_via  TEXT NOT NULL DEFAULT '',
    decided_at   INTEGER NOT NULL DEFAULT 0,
    node_name    TEXT NOT NULL DEFAULT '',
    node_ip      TEXT NOT NULL DEFAULT '',
    error        TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
);
CREATE INDEX pending_status ON pending_registrations(status);
CREATE INDEX pending_auth ON pending_registrations(auth_id);

CREATE TABLE telegram_links (
    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    chat_id    INTEGER NOT NULL UNIQUE,
    tg_name    TEXT NOT NULL DEFAULT '',
    linked_at  INTEGER NOT NULL
);

CREATE TABLE telegram_link_tokens (
    token      TEXT PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE telegram_actions (
    id         TEXT PRIMARY KEY,
    kind       TEXT NOT NULL,                -- approve | deny | pick_user | as_user
    target_id  INTEGER NOT NULL,
    arg        TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL,
    used_at    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE telegram_messages (
    id         INTEGER PRIMARY KEY,
    ref_kind   TEXT NOT NULL,
    ref_id     INTEGER NOT NULL,
    chat_id    INTEGER NOT NULL,
    message_id INTEGER NOT NULL
);
CREATE INDEX telegram_messages_ref ON telegram_messages(ref_kind, ref_id);

CREATE TABLE watch_rules (
    id               INTEGER PRIMARY KEY,
    account_id       INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    subject_type     TEXT NOT NULL,          -- node | user | tag | all
    subject          TEXT NOT NULL DEFAULT '',
    events           TEXT NOT NULL,          -- comma separated event kinds
    offline_debounce INTEGER NOT NULL DEFAULT 120,
    not_seen_hours   INTEGER NOT NULL DEFAULT 0,
    expiry_days      INTEGER NOT NULL DEFAULT 7,
    created_at       INTEGER NOT NULL
);

CREATE TABLE notifications (
    id         INTEGER PRIMARY KEY,
    account_id INTEGER REFERENCES accounts(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL,
    text       TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX notifications_account ON notifications(account_id, created_at);

CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY,
    at         INTEGER NOT NULL,
    actor_id   INTEGER NOT NULL DEFAULT 0,
    actor      TEXT NOT NULL,
    channel    TEXT NOT NULL,                -- web | telegram | cli | system
    action     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    before     TEXT NOT NULL DEFAULT '',
    after      TEXT NOT NULL DEFAULT '',
    ip         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_at ON audit_log(at);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
