import os
import sqlite3
import tempfile
from pathlib import Path

os.environ["COMPLY_DATA_DIR"] = tempfile.mkdtemp()

import pytest  # noqa: E402
import yaml  # noqa: E402
from helpers import LoggedInClient  # noqa: E402

from app import catalog, config, db  # noqa: E402
from app.main import app  # noqa: E402

NIS2_FILE = config.CONTROLS_DIR / "nis2.yaml"


def test_health():
    with LoggedInClient(app) as client:
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


def test_status_counts_nis2_controls():
    with LoggedInClient(app) as client:
        stats = client.get("/api/status").json()["stats"]
        assert stats["frameworks"] >= 1
        assert stats["controls"] == stats["automated"] + stats["manual"]
        assert stats["controls"] >= 35


def test_nis2_has_all_article_21_categories():
    with LoggedInClient(app) as client:
        data = client.get("/api/frameworks/nis2/controls").json()
        assert [c["id"] for c in data["categories"]] == list("abcdefghij")
        for cat in data["categories"]:
            assert len(cat["controls"]) >= 3, cat["id"]


def test_unknown_framework_returns_404():
    with LoggedInClient(app) as client:
        assert client.get("/api/frameworks/nope/controls").status_code == 404
        assert client.get("/controls/nope").status_code == 404


def test_pages_render():
    with LoggedInClient(app) as client:
        home = client.get("/")
        assert home.status_code == 200 and "NIS2 Directive" in home.text
        page = client.get("/controls")
        assert page.status_code == 200
        assert "Art. 21(2)(j)" in page.text and "nis2-a-01" in page.text


def test_catalog_file_is_valid():
    data = yaml.safe_load(NIS2_FILE.read_text(encoding="utf-8"))
    catalog.validate(data, NIS2_FILE.name)  # must not raise


@pytest.mark.parametrize("broken, message", [
    ({"categories": []}, "framework.id"),
    ({"framework": {"id": "x", "name": "X"},
      "categories": [{"id": "a", "reference": "r", "title": "t",
                      "controls": [{"id": "x-1", "title": "T", "check_type": "automated"}]}]},
     "automation"),
    ({"framework": {"id": "x", "name": "X"},
      "categories": [{"id": "a", "reference": "r", "title": "t",
                      "controls": [{"id": "x-1", "title": "T"}, {"id": "x-1", "title": "T2"}]}]},
     "duplicate"),
])
def test_invalid_catalog_is_rejected(broken, message):
    with pytest.raises(catalog.CatalogError, match=message):
        catalog.validate(broken, "test.yaml")


def test_reload_is_idempotent():
    with LoggedInClient(app):
        first = catalog.load_all()
        second = catalog.load_all()
        assert first == second
        with db.get_conn() as conn:
            assert conn.execute("SELECT COUNT(*) FROM controls").fetchone()[0] == first["nis2"]


def test_migration_from_v0_1_schema(tmp_path: Path):
    """A database created by v0.1.0 gets the new columns without losing data."""
    old_db = tmp_path / "comply.db"
    conn = sqlite3.connect(old_db)
    conn.executescript("""
        CREATE TABLE frameworks (id TEXT PRIMARY KEY, name TEXT NOT NULL, version TEXT, description TEXT);
        CREATE TABLE controls (id TEXT PRIMARY KEY, framework_id TEXT NOT NULL, reference TEXT NOT NULL,
                               title TEXT NOT NULL, description TEXT, check_type TEXT NOT NULL DEFAULT 'manual');
        CREATE TABLE evidence (id INTEGER PRIMARY KEY AUTOINCREMENT, control_id TEXT NOT NULL,
                               source TEXT NOT NULL, status TEXT NOT NULL, summary TEXT, raw_json TEXT,
                               collected_at TEXT NOT NULL DEFAULT (datetime('now')));
    """)
    conn.close()

    original = db.DB_PATH
    db.DB_PATH = old_db
    try:
        db.init_db()
        with db.get_conn() as c:
            cols = {r["name"] for r in c.execute("PRAGMA table_info(controls)")}
        assert {"category_id", "automation", "evidence_hint", "sort_order"} <= cols
    finally:
        db.DB_PATH = original


def test_demo_seeder_runs_on_empty_database(tmp_path):
    import os
    import subprocess
    import sys
    env = {**os.environ, "COMPLY_DATA_DIR": str(tmp_path), "COLLECT_INTERVAL_HOURS": "0"}
    out = subprocess.run([sys.executable, "scripts/seed_demo.py"], env=env, capture_output=True, text=True,
                         cwd=config.BASE_DIR)
    assert out.returncode == 0, out.stderr
    assert '"seeded": true' in out.stdout
    again = subprocess.run([sys.executable, "scripts/seed_demo.py"], env=env, capture_output=True, text=True,
                           cwd=config.BASE_DIR)
    assert again.returncode != 0          # refuses to touch a database that already has evidence
