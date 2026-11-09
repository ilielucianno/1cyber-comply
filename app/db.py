"""Database: SQLite from the Python standard library, no extra dependencies."""
import sqlite3
from contextlib import contextmanager

from app.config import DATA_DIR, DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS frameworks (
    id          TEXT PRIMARY KEY,          -- e.g. nis2
    name        TEXT NOT NULL,
    version     TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS controls (
    id           TEXT PRIMARY KEY,         -- e.g. nis2-a-01
    framework_id TEXT NOT NULL REFERENCES frameworks(id),
    reference    TEXT NOT NULL,            -- e.g. Art. 21(2)(a)
    title        TEXT NOT NULL,
    description  TEXT,
    check_type   TEXT NOT NULL DEFAULT 'manual',  -- automated | manual
    category_id    TEXT,                   -- e.g. a
    category_title TEXT,
    automation     TEXT,                   -- e.g. wazuh:sca
    evidence_hint  TEXT,
    sort_order     INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS evidence (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    control_id   TEXT NOT NULL REFERENCES controls(id),
    source       TEXT NOT NULL,            -- wazuh | opnsense | manual
    status       TEXT NOT NULL,            -- pass | fail | unknown
    summary      TEXT,
    raw_json     TEXT,                     -- raw collected data
    collected_at TEXT NOT NULL DEFAULT (datetime('now')),
    reviewer     TEXT,                     -- manual evidence: who assessed it
    valid_until  TEXT,                     -- manual evidence: YYYY-MM-DD, expired = not compliant
    check_name   TEXT                      -- automated evidence: collector check, e.g. sca
);

CREATE INDEX IF NOT EXISTS idx_evidence_control ON evidence(control_id);

CREATE TABLE IF NOT EXISTS collection_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT NOT NULL,             -- wazuh | opnsense
    started_at  TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    ok          INTEGER NOT NULL DEFAULT 0,
    message     TEXT
);

CREATE TABLE IF NOT EXISTS score_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    framework_id TEXT NOT NULL REFERENCES frameworks(id),
    taken_at     TEXT NOT NULL DEFAULT (datetime('now')),
    score        REAL NOT NULL,            -- % of all controls with passing evidence
    automated_score REAL,                  -- % of automated controls passing
    passed       INTEGER NOT NULL,
    failed       INTEGER NOT NULL,
    unknown      INTEGER NOT NULL,
    missing      INTEGER NOT NULL,         -- controls without any evidence yet
    total        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS attachments (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id  INTEGER NOT NULL REFERENCES evidence(id),
    filename     TEXT NOT NULL,            -- sanitised original name
    stored_name  TEXT NOT NULL UNIQUE,     -- random name on disk
    content_type TEXT,
    size         INTEGER NOT NULL,
    sha256       TEXT NOT NULL,
    uploaded_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   TEXT NOT NULL,         -- scrypt$N$r$p$salt$hash
    role            TEXT NOT NULL,         -- admin | editor | viewer
    disabled        INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_login      TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,          -- sha256 of the cookie value; the raw token is never stored
    user_id     INTEGER NOT NULL REFERENCES users(id),
    csrf_token  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        TEXT NOT NULL DEFAULT (datetime('now')),
    username  TEXT,
    action    TEXT NOT NULL,
    detail    TEXT,
    ip        TEXT
);

CREATE INDEX IF NOT EXISTS idx_score_fw ON score_history(framework_id, taken_at);

-- Maturity model assessments (catalogues in controls/maturity/*.yaml, kept in memory)
CREATE TABLE IF NOT EXISTS maturity_answers (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    framework_id   TEXT NOT NULL,          -- e.g. dsa-cy-245-2024
    measure_id     TEXT NOT NULL,          -- e.g. IAM4
    requirement_id TEXT NOT NULL,          -- original numbering, e.g. 3.2
    answer         TEXT NOT NULL,          -- met | not_met | na
    note           TEXT,                   -- required for na
    answered_by    TEXT,
    evidence_id    INTEGER REFERENCES evidence(id) ON DELETE SET NULL,  -- automated evidence behind the answer
    answered_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_maturity_req ON maturity_answers(framework_id, measure_id, requirement_id);

CREATE TABLE IF NOT EXISTS maturity_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    framework_id TEXT NOT NULL,
    taken_at     TEXT NOT NULL DEFAULT (datetime('now')),
    mature       INTEGER NOT NULL,         -- 1 when every measure reaches the target level
    avg_level    REAL NOT NULL,
    min_level    INTEGER NOT NULL,
    at_target    INTEGER NOT NULL,         -- measures at or above the target level
    total        INTEGER NOT NULL,
    answered     INTEGER NOT NULL,         -- requirements with an answer
    requirements_total INTEGER NOT NULL
);
"""


# Columns added after v0.1.0. Existing databases receive them via ALTER TABLE.
MIGRATIONS = {
    "controls": {
        "category_id": "TEXT",
        "category_title": "TEXT",
        "automation": "TEXT",
        "evidence_hint": "TEXT",
        "sort_order": "INTEGER DEFAULT 0",
    },
    "evidence": {
        "reviewer": "TEXT",
        "valid_until": "TEXT",
        "check_name": "TEXT",
    },
}


def _migrate(conn: sqlite3.Connection) -> None:
    for table, columns in MIGRATIONS.items():
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, coltype in columns.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {coltype}")


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_check ON evidence(source, check_name)")


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
