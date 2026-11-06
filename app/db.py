"""Baza de date: SQLite din biblioteca standard Python, fara dependinte extra."""
import sqlite3
from contextlib import contextmanager

from app.config import DATA_DIR, DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS frameworks (
    id          TEXT PRIMARY KEY,          -- ex: nis2
    name        TEXT NOT NULL,
    version     TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS controls (
    id           TEXT PRIMARY KEY,         -- ex: nis2-21.2.a-01
    framework_id TEXT NOT NULL REFERENCES frameworks(id),
    reference    TEXT NOT NULL,            -- ex: Art. 21(2)(a)
    title        TEXT NOT NULL,
    description  TEXT,
    check_type   TEXT NOT NULL DEFAULT 'manual'  -- automated | manual
);

CREATE TABLE IF NOT EXISTS evidence (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    control_id   TEXT NOT NULL REFERENCES controls(id),
    source       TEXT NOT NULL,            -- wazuh | opnsense | manual
    status       TEXT NOT NULL,            -- pass | fail | unknown
    summary      TEXT,
    raw_json     TEXT,                     -- datele brute colectate
    collected_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_evidence_control ON evidence(control_id);
"""


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA)


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
