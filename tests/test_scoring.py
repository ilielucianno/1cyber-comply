"""Compliance score, history, the f-03 continuous-tracking check and the scheduler."""
import time

import pytest
from helpers import LoggedInClient

from app import config, evidence, scoring
from app.collectors.base import BaseCollector, CheckResult
from app.collectors.comply import ComplyCollector
from app.db import get_conn
from app.main import app
from app.scheduler import Scheduler, run_all


class StaticCollector(BaseCollector):
    """Returns fixed results, as if a real source had been queried."""
    name = "static"

    def __init__(self, results):
        self.results = results

    def is_configured(self):
        return True

    def test_connection(self):
        return True, "ok"

    def collect(self):
        return self.results


@pytest.fixture
def clean_db():
    with LoggedInClient(app):
        with get_conn() as conn:
            conn.execute("DELETE FROM attachments")
            conn.execute("DELETE FROM evidence")
            conn.execute("DELETE FROM score_history")
            conn.execute("DELETE FROM collection_runs")
        yield


def test_score_counts_unknown_and_missing_as_not_passing(clean_db):
    evidence.save_results("wazuh", [
        CheckResult("agents_active", "pass", "ok"),
        CheckResult("sca", "fail", "low"),
        CheckResult("fim", "unknown", "?"),
    ])
    s = scoring.compute("nis2")
    assert s["passed"] == 1 and s["failed"] == 1 and s["unknown"] == 1
    assert s["missing"] == s["total"] - 3
    assert s["score"] == round(100 / s["total"], 1)
    assert s["automated_score"] == round(100 / s["automated_total"], 1)
    assert s["manual_score"] == 0


def test_snapshot_after_manual_collection(clean_db):
    collector = StaticCollector([CheckResult("agents_active", "pass", "ok")])
    evidence.run_collection("wazuh", collector)
    evidence.run_collection("wazuh", collector)
    hist = scoring.history("nis2")
    assert len(hist) == 2 and hist[-1]["passed"] == 1


def test_comply_check_requires_scheduler(clean_db, monkeypatch):
    monkeypatch.setattr(config, "COLLECT_INTERVAL_HOURS", 0)
    assert ComplyCollector().collect()[0].status == "fail"


def test_comply_check_passes_with_recent_history(clean_db, monkeypatch):
    monkeypatch.setattr(config, "COLLECT_INTERVAL_HOURS", 24)
    assert ComplyCollector().collect()[0].status == "fail"     # no history yet
    scoring.snapshot("nis2")
    r = ComplyCollector().collect()[0]
    assert r.status == "pass" and "every 24h" in r.summary


def test_comply_check_detects_stopped_collection(clean_db, monkeypatch):
    monkeypatch.setattr(config, "COLLECT_INTERVAL_HOURS", 24)
    scoring.snapshot("nis2")
    with get_conn() as conn:
        conn.execute("UPDATE score_history SET taken_at = datetime('now', '-3 days')")
    r = ComplyCollector().collect()[0]
    assert r.status == "fail" and "stopped" in r.summary


def test_run_all_collects_configured_sources_and_snapshots_once(clean_db, monkeypatch):
    fake = {"wazuh": StaticCollector([CheckResult("agents_active", "pass", "ok")]),
            "comply": ComplyCollector()}
    monkeypatch.setattr(evidence, "get_collectors", lambda: fake)
    monkeypatch.setattr(config, "COLLECT_INTERVAL_HOURS", 24)
    results = run_all()
    assert list(results) == ["wazuh", "comply"]                # comply runs last
    assert len(scoring.history("nis2")) == 1                   # one snapshot per cycle
    assert evidence.latest_by_control("nis2")["nis2-f-03"]["status"] == "fail"   # first cycle
    run_all()
    assert evidence.latest_by_control("nis2")["nis2-f-03"]["status"] == "pass"


def test_scheduler_runs_and_stops(clean_db, monkeypatch):
    calls = []
    monkeypatch.setattr(config, "COLLECT_INTERVAL_HOURS", 0.0003)   # ~1 second
    monkeypatch.setattr(config, "COLLECT_START_DELAY_SECONDS", 0)
    monkeypatch.setattr("app.scheduler.run_all", lambda: calls.append(1) or {})
    s = Scheduler()
    s.start()
    deadline = time.time() + 5
    while len(calls) < 2 and time.time() < deadline:
        time.sleep(0.05)
    s.stop()
    assert len(calls) >= 2 and s.last_run is not None


def test_scheduler_disabled(monkeypatch):
    monkeypatch.setattr(config, "COLLECT_INTERVAL_HOURS", 0)
    s = Scheduler()
    s.start()
    assert not s.enabled and s.next_run is None


def test_chart_svg():
    assert scoring.chart_svg([]) == ""
    svg = scoring.chart_svg([{"taken_at": "2026-11-01 08:00:00", "score": 20.0, "automated_score": 40.0},
                             {"taken_at": "2026-11-06 08:00:00", "score": 45.5, "automated_score": 80.0}])
    assert svg.startswith("<svg") and "45.5%" in svg and "2026-11-06" in svg


def test_dashboard_and_api(clean_db):
    with LoggedInClient(app) as client:
        evidence.run_collection("wazuh", StaticCollector([CheckResult("agents_active", "pass", "ok")]))
        page = client.get("/")
        assert "compliance score" in page.text and "<svg" in page.text
        assert "Automatic collection disabled" in page.text
        score = client.get("/api/frameworks/nis2/score").json()
        assert score["passed"] == 1 and len(score["history"]) == 1
        assert client.get("/api/schedule").json()["enabled"] is False
        r = client.post("/collect-all", follow_redirects=False)
        assert r.status_code == 303
