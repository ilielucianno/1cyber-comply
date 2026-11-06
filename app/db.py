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
    valid_until  TEXT                      -- manual evidence: YYYY-MM-DD, expired = not compliant
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

CREATE INDEX IF NOT EXISTS idx_score_fw ON score_history(framework_id, taken_at);
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
