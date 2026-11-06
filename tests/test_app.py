import os
import tempfile

os.environ["COMPLY_DATA_DIR"] = tempfile.mkdtemp()

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


def test_health():
    with TestClient(app) as client:
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


def test_status_and_db_created():
    with TestClient(app) as client:
        r = client.get("/api/status")
        assert r.status_code == 200
        assert r.json()["stats"] == {"frameworks": 0, "controls": 0, "evidence": 0}


def test_index_page():
    with TestClient(app) as client:
        r = client.get("/")
        assert r.status_code == 200
        assert "1cyber Comply" in r.text
