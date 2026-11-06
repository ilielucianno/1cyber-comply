"""Tests the Wazuh collector against a simulated Wazuh server (no network)."""
import os
import tempfile
from datetime import datetime, timedelta, timezone

os.environ.setdefault("COMPLY_DATA_DIR", tempfile.mkdtemp())

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import config, evidence  # noqa: E402
from app.collectors.wazuh import WazuhCollector, _version_tuple  # noqa: E402
from app.main import app  # noqa: E402

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)
RECENT = (NOW - timedelta(hours=3)).isoformat()
OLD = (NOW - timedelta(days=5)).isoformat()


def items(lst, total=None):
    return {"data": {"affected_items": lst, "total_affected_items": len(lst) if total is None else total}}


class FakeWazuhAPI:
    """Simulates Wazuh Server API 4.x responses."""

    def __init__(self, expire_token_once=False):
        self.auth_calls = 0
        self.expire_token_once = expire_token_once

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/security/user/authenticate":
            if request.headers.get("authorization", "").startswith("Basic"):
                self.auth_calls += 1
                return httpx.Response(200, json={"data": {"token": f"tok{self.auth_calls}"}})
            return httpx.Response(401)
        if self.expire_token_once and request.headers.get("authorization") == "Bearer tok1":
            self.expire_token_once = False
            return httpx.Response(401)

        routes = {
            "/manager/info": items([{"version": "v4.14.8"}]),
            "/agents": items([
                {"id": "000", "name": "manager", "status": "active", "version": "Wazuh v4.14.8"},
                {"id": "001", "name": "web01", "status": "active", "version": "Wazuh v4.14.8"},
                {"id": "002", "name": "db01", "status": "active", "version": "Wazuh v4.13.1"},
                {"id": "003", "name": "laptop7", "status": "disconnected", "version": "Wazuh v4.14.8"},
            ]),
            "/sca/001": items([{"name": "CIS Ubuntu 24.04", "score": 82, "pass": 160, "fail": 35}]),
            "/sca/002": items([{"name": "CIS Ubuntu 24.04", "score": 55, "pass": 107, "fail": 88}]),
            "/syscheck/001/last_scan": items([{"start": RECENT, "end": RECENT}]),
            "/syscheck/002/last_scan": items([{"start": OLD, "end": OLD}]),
            "/syscollector/001/os": items([{"os": {"name": "Ubuntu"}}]),
            "/syscollector/002/os": items([{"os": {"name": "Ubuntu"}}]),
            "/syscollector/001/packages": items([{}], total=812),
            "/syscollector/002/packages": items([{}], total=640),
        }
        if path in routes:
            return httpx.Response(200, json=routes[path])
        return httpx.Response(404, json={"error": 1})


def fake_indexer(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if "wazuh-alerts" in path:
        return httpx.Response(200, json={
            "hits": {"total": {"value": 1234}},
            "aggregations": {"levels": {"buckets": [
                {"key": "low", "doc_count": 1100}, {"key": "medium", "doc_count": 130},
                {"key": "high", "doc_count": 4}]}}})
    if "vulnerabilities" in path:
        return httpx.Response(200, json={
            "hits": {"total": {"value": 57}},
            "aggregations": {"severity": {"buckets": [
                {"key": "High", "doc_count": 20}, {"key": "Medium", "doc_count": 33},
                {"key": "Critical", "doc_count": 4}]}}})
    return httpx.Response(200, json={"version": {"number": "2.19"}})


@pytest.fixture
def wazuh_env(monkeypatch):
    monkeypatch.setattr(config, "WAZUH_URL", "https://wazuh.test:55000")
    monkeypatch.setattr(config, "WAZUH_USER", "comply")
    monkeypatch.setattr(config, "WAZUH_PASSWORD", "secret")
    monkeypatch.setattr(config, "WAZUH_INDEXER_URL", "https://wazuh.test:9200")
    monkeypatch.setattr(config, "WAZUH_INDEXER_USER", "comply_ro")
    monkeypatch.setattr(config, "WAZUH_INDEXER_PASSWORD", "secret")


def make_collector(api=None, indexer=fake_indexer):
    return WazuhCollector(api_transport=httpx.MockTransport(api or FakeWazuhAPI()),
                          indexer_transport=httpx.MockTransport(indexer), now=NOW)


def by_check(results):
    return {r.check: r for r in results}


def test_version_parsing():
    assert _version_tuple("Wazuh v4.14.8") == (4, 14, 8)
    assert _version_tuple("v4.9.0-rc1") == (4, 9, 0)
    assert _version_tuple(None) == ()


def test_all_checks_produce_expected_status(wazuh_env):
    r = by_check(make_collector().collect())
    assert set(r) == {"agents_active", "agents_version", "sca", "fim", "syscollector",
                      "alerts_recent", "vulnerabilities"}
    assert r["agents_active"].status == "fail" and "laptop7" in r["agents_active"].summary
    assert r["agents_version"].status == "fail" and "db01" in r["agents_version"].summary
    assert r["sca"].status == "fail" and "db01 (55%)" in r["sca"].summary
    assert r["fim"].status == "fail" and "db01" in r["fim"].summary
    assert r["syscollector"].status == "pass" and "1452 packages" in r["syscollector"].summary
    assert r["alerts_recent"].status == "pass" and "1234" in r["alerts_recent"].summary
    assert r["vulnerabilities"].status == "fail" and "4 open critical vulnerabilities" in r["vulnerabilities"].summary


def test_manager_agent_is_excluded(wazuh_env):
    raw = by_check(make_collector().collect())["agents_active"].raw
    assert raw["total"] == 3


def test_token_expiry_reauthenticates(wazuh_env):
    api = FakeWazuhAPI(expire_token_once=True)
    r = by_check(make_collector(api=api).collect())
    assert api.auth_calls == 2
    assert r["agents_active"].status != "unknown"


def test_bad_credentials_give_unknown_not_crash(wazuh_env):
    def deny(_request):
        return httpx.Response(401)
    r = by_check(make_collector(api=deny).collect())
    assert r["agents_active"].status == "unknown"
    assert "Authentication failed" in r["agents_active"].summary
    assert r["alerts_recent"].status == "pass"   # the indexer works independently


def test_missing_vulnerability_index_is_unknown(wazuh_env):
    def no_vuln(request):
        if "vulnerabilities" in request.url.path:
            return httpx.Response(404)
        return fake_indexer(request)
    r = by_check(make_collector(indexer=no_vuln).collect())
    assert r["vulnerabilities"].status == "unknown"


def test_indexer_not_configured(wazuh_env, monkeypatch):
    monkeypatch.setattr(config, "WAZUH_INDEXER_URL", "")
    r = by_check(make_collector().collect())
    assert r["alerts_recent"].status == "unknown" and "not configured" in r["alerts_recent"].summary


def test_test_connection(wazuh_env):
    ok, msg = make_collector().test_connection()
    assert ok and "v4.14.8" in msg and "Indexer OK" in msg


def test_collection_saves_evidence_on_controls(wazuh_env):
    with TestClient(app) as client:
        result = evidence.run_collection("wazuh", make_collector())
        assert result["ok"] and result["saved"] == 7
        latest = evidence.latest_by_control("nis2")
        assert latest["nis2-b-02"]["status"] == "fail"     # agents_active
        assert latest["nis2-i-01"]["status"] == "pass"     # syscollector
        assert latest["nis2-e-01"]["status"] == "fail"     # vulnerabilities
        assert "nis2-a-01" not in latest                   # manual control, no evidence

        api = client.get("/api/frameworks/nis2/controls").json()
        assert api["status_counts"]["pass"] >= 2
        page = client.get("/controls")
        assert "laptop7" in page.text
        home = client.get("/")
        assert "Last collection" in home.text


def test_unconfigured_source_does_not_run(monkeypatch):
    monkeypatch.setattr(config, "WAZUH_URL", "")
    result = evidence.run_collection("wazuh", WazuhCollector())
    assert not result["ok"] and "not configured" in result["message"]


def test_ui_buttons_redirect_with_message(wazuh_env, monkeypatch):
    monkeypatch.setattr(evidence, "get_collectors", lambda: {"wazuh": make_collector()})
    with TestClient(app) as client:
        r = client.post("/sources/wazuh/test", follow_redirects=False)
        assert r.status_code == 303 and "ok=1" in r.headers["location"]
        r = client.post("/sources/wazuh/collect")
        assert r.status_code == 200 and "checks:" in r.text
        assert client.post("/api/sources/unknown/collect").status_code == 404
