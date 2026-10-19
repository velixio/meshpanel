CREATE TABLE webhooks (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    url         TEXT NOT NULL,
    format      TEXT NOT NULL DEFAULT 'json', -- json | slack | discord
    events      TEXT NOT NULL DEFAULT '',     -- comma separated kinds; empty = all
    secret      TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    last_status INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT NOT NULL DEFAULT '',
    last_at     INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
);
