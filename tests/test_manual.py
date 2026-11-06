"""Manual evidence upload, expiry, safe download and the PDF report."""
from datetime import date, timedelta

import pytest
from fastapi.testclient import TestClient

from app import evidence, manual, scoring
from app.db import get_conn
from app.main import app

NEXT_YEAR = (date.today() + timedelta(days=365)).isoformat()


@pytest.fixture
def client():
    with TestClient(app) as c:
        with get_conn() as conn:
            conn.execute("DELETE FROM attachments")
            conn.execute("DELETE FROM evidence")
            conn.execute("DELETE FROM score_history")
        yield c


def form(**overrides):
    data = {"status": "pass", "note": "Signed policy v2.1", "reviewer": "Ilie Lucian", "valid_until": NEXT_YEAR}
    data.update(overrides)
    return data


def test_upload_with_file_counts_as_pass(client):
    r = client.post("/controls/nis2/nis2-a-01/evidence", data=form(),
                    files={"file": ("policy.pdf", b"%PDF-1.4 test", "application/pdf")}, follow_redirects=False)
    assert r.status_code == 303 and "ok=1" in r.headers["location"]
    e = evidence.latest_by_control("nis2")["nis2-a-01"]
    assert e["status"] == "pass" and e["reviewer"] == "Ilie Lucian" and e["attachment_count"] == 1
    assert scoring.compute("nis2")["manual_score"] > 0
    assert len(scoring.history("nis2")) == 1               # snapshot after saving


def test_detail_page_shows_history_and_download(client):
    client.post("/controls/nis2/nis2-a-01/evidence", data=form(),
                files={"file": ("../../etc/<bad>.pdf", b"%PDF-1.4 x", "application/pdf")})
    page = client.get("/controls/nis2/nis2-a-01")
    assert page.status_code == 200 and "Signed policy v2.1" in page.text and "sha256" in page.text
    att_id = evidence.history_for_control("nis2-a-01")[0]["attachments"][0]["id"]
    dl = client.get(f"/attachments/{att_id}")
    assert dl.status_code == 200 and dl.content == b"%PDF-1.4 x"
    assert dl.headers["content-type"] == "application/octet-stream"     # never rendered inline
    assert "attachment" in dl.headers["content-disposition"]
    assert "_bad_.pdf" in dl.headers["content-disposition"]             # path and markup stripped


def test_expired_evidence_counts_as_fail(client):
    manual.add_manual_evidence("nis2-a-01", "pass", "old policy", "Ilie", NEXT_YEAR)
    with get_conn() as conn:
        conn.execute("UPDATE evidence SET valid_until = '2020-01-01' WHERE control_id = 'nis2-a-01'")
    e = evidence.latest_by_control("nis2")["nis2-a-01"]
    assert e["status"] == "fail" and e["expired"] and e["summary"].startswith("EXPIRED on 2020-01-01")
    assert scoring.compute("nis2")["passed"] == 0


@pytest.mark.parametrize("overrides, files, message", [
    ({"note": ""}, None, "note"),
    ({"reviewer": " "}, None, "reviewer"),
    ({"status": "maybe"}, None, "pass or fail"),
    ({"valid_until": "2020-01-01"}, None, "past"),
    ({}, {"file": ("evil.html", b"<script>", "text/html")}, "not allowed"),
    ({}, {"file": ("big.pdf", b"0" * (manual.MAX_FILE_BYTES + 1), "application/pdf")}, "10 MB"),
])
def test_invalid_input_is_rejected(client, overrides, files, message):
    r = client.post("/controls/nis2/nis2-a-01/evidence", data=form(**overrides), files=files, follow_redirects=False)
    assert r.status_code == 303 and "ok=0" in r.headers["location"]
    assert message.replace(" ", "%20") in r.headers["location"]
    assert "nis2-a-01" not in evidence.latest_by_control("nis2")


def test_manual_evidence_refused_on_automated_control(client):
    with pytest.raises(manual.EvidenceError, match="automatically"):
        manual.add_manual_evidence("nis2-b-02", "pass", "x", "y", None)


def test_unknown_control_and_attachment_404(client):
    assert client.get("/controls/nis2/nis2-zz-99").status_code == 404
    assert client.get("/attachments/99999").status_code == 404


def test_pdf_report(client):
    manual.add_manual_evidence("nis2-a-01", "pass", "Politica aprobată – semnătură director", "Ilie Lucian",
                               NEXT_YEAR, manual.Upload("policy.pdf", b"%PDF-1.4"))
    scoring.snapshot_all()
    scoring.snapshot_all()
    r = client.get("/reports/nis2.pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    assert "nis2-compliance-report-" in r.headers["content-disposition"]
    assert len(r.content) > 5000
    assert client.get("/reports/nope.pdf").status_code == 404
