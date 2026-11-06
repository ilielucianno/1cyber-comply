"""Tests the OPNsense collector against a simulated OPNsense 26.1 API (no network)."""
import os
import tempfile

os.environ.setdefault("COMPLY_DATA_DIR", tempfile.mkdtemp())

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import config, evidence  # noqa: E402
from app.collectors.opnsense import OPNsenseCollector, analyse_ruleset, parse_version  # noqa: E402
from app.main import app  # noqa: E402

GOOD_RULES = {
    "@0 scrub in all fragment reassemble": {},
    "@0 block drop in log on ! em0 inet from 192.168.1.0/24 to any": {},
    "@5 block drop in log inet all label \"02f4bab031b57d1e30553ce08e0ec131\"": {},
    "@6 pass in quick on lo0 all": {},
    "@9 pass in quick on em0 proto tcp from any to (em0) port = https flags S/SA keep state": {},
    "@12 pass in quick on em0 inet from (em0:network) to any flags S/SA keep state": {},
    "@14 pass in quick inet6 proto ipv6-icmp all icmp6-type routeradv keep state": {},
    "@20 pass out quick inet all flags S/SA keep state": {},
}


class FakeOPNsense:
    def __init__(self, rules=None, ids_enabled="1", ids_status="running", wg_enabled="1",
                 wg_servers=1, vlans=2, denied=()):
        self.rules = GOOD_RULES if rules is None else rules
        self.ids_enabled, self.ids_status = ids_enabled, ids_status
        self.wg_enabled, self.wg_servers, self.vlans = wg_enabled, wg_servers, vlans
        self.denied = set(denied)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.method != "GET":
            return httpx.Response(405)            # the collector must never write
        if request.headers.get("authorization", "") == "":
            return httpx.Response(401)
        path = request.url.path
        if path in self.denied:
            return httpx.Response(403)
        routes = {
            "/api/diagnostics/system/system_information": {
                "name": "OPNsense.internal",
                "versions": ["OPNsense 26.1.6_2-amd64", "FreeBSD 14.3-RELEASE-p10", "OpenSSL 3.0.20"],
                "updates": "Click to check for updates."},
            "/api/diagnostics/firewall/pf_statistics/rules": {
                "rules": {"filter rules": self.rules, "nat rules": {}}},
            "/api/ids/settings/get": {"ids": {"general": {"enabled": self.ids_enabled, "ips": "0"}}},
            "/api/ids/service/status": {"status": self.ids_status},
            "/api/wireguard/general/get": {"general": {"enabled": self.wg_enabled}},
            "/api/wireguard/server/search_server": {
                "rows": [{"name": f"wg{i}", "enabled": "1"} for i in range(self.wg_servers)]},
            "/api/interfaces/vlan_settings/search_item": {
                "rows": [{"tag": str(10 * (i + 1)), "if": "em0", "descr": f"zone{i}"} for i in range(self.vlans)]},
        }
        if path in routes:
            return httpx.Response(200, json=routes[path])
        return httpx.Response(404)


def github(latest="26.1.6"):
    def handler(_request):
        return httpx.Response(200, json=[{"name": "26.7.r1"}, {"name": latest},
                                         {"name": "26.1.5"}, {"name": "25.7.11"}])
    return handler


def http_redirect(_request):
    return httpx.Response(301, headers={"location": "https://192.168.1.1/"})


def http_plain_login(_request):
    return httpx.Response(200, text="<html>login</html>")


@pytest.fixture
def opn_env(monkeypatch):
    monkeypatch.setattr(config, "OPNSENSE_URL", "https://192.168.1.1")
    monkeypatch.setattr(config, "OPNSENSE_KEY", "key")
    monkeypatch.setattr(config, "OPNSENSE_SECRET", "secret")
    monkeypatch.setattr(config, "OPNSENSE_CHECK_LATEST", True)


def make(api=None, http=http_redirect, gh=None):
    return OPNsenseCollector(transport=httpx.MockTransport(api or FakeOPNsense()),
                             http_transport=httpx.MockTransport(http),
                             github_transport=httpx.MockTransport(gh or github()))


def by_check(results):
    return {r.check: r for r in results}


def test_parse_version():
    assert parse_version("OPNsense 26.1.6_2-amd64") == (26, 1, 6)
    assert parse_version("26.7") == (26, 7, 0)
    assert parse_version(None) == ()


def test_ruleset_analysis_good():
    a = analyse_ruleset(GOOD_RULES)
    assert a["default_deny"] and a["any_to_any"] == []


def test_ruleset_analysis_flags_any_to_any():
    rules = dict(GOOD_RULES)
    rules["@30 pass in log quick on em1 inet from any to any flags S/SA keep state"] = {}
    rules["@31 pass in quick on em1 all"] = {}
    a = analyse_ruleset(rules)
    assert len(a["any_to_any"]) == 2


def test_all_checks_pass_on_healthy_firewall(opn_env):
    r = by_check(make().collect())
    assert set(r) == {"firmware", "firewall_rules", "ids", "vpn", "webgui_https", "vlans"}
    assert all(x.status == "pass" for x in r.values()), {k: v.summary for k, v in r.items()}
    assert "26.1.6" in r["firmware"].summary
    assert "tags: 10, 20" in r["vlans"].summary


def test_lab_like_firewall(opn_env):
    """Mirrors the real lab: no IDS, no WireGuard, no VLANs, outdated firmware."""
    api = FakeOPNsense(ids_enabled="0", ids_status="stopped", wg_enabled="0", wg_servers=0, vlans=0)
    r = by_check(make(api=api, gh=github("26.1.8")).collect())
    assert r["firmware"].status == "fail" and "26.1.8" in r["firmware"].summary
    assert r["ids"].status == "fail" and "not enabled" in r["ids"].summary
    assert r["vpn"].status == "unknown"
    assert r["vlans"].status == "fail"
    assert r["firewall_rules"].status == "pass"


def test_any_to_any_rule_fails(opn_env):
    rules = dict(GOOD_RULES)
    rules["@30 pass in quick on em1 inet from any to any keep state"] = {}
    r = by_check(make(api=FakeOPNsense(rules=rules)).collect())
    assert r["firewall_rules"].status == "fail" and "any-to-any" in r["firewall_rules"].summary


def test_missing_default_deny_fails(opn_env):
    rules = {k: v for k, v in GOOD_RULES.items() if "label" not in k}
    r = by_check(make(api=FakeOPNsense(rules=rules)).collect())
    assert r["firewall_rules"].status == "fail" and "default-deny" in r["firewall_rules"].summary


def test_webgui_over_plain_http_fails(opn_env):
    r = by_check(make(http=http_plain_login).collect())
    assert r["webgui_https"].status == "fail"


def test_http_port_closed_passes(opn_env):
    def refused(request):
        raise httpx.ConnectError("refused", request=request)
    r = by_check(make(http=refused).collect())
    assert r["webgui_https"].status == "pass" and "not served" in r["webgui_https"].summary


def test_missing_privilege_gives_unknown(opn_env):
    api = FakeOPNsense(denied={"/api/ids/settings/get"})
    r = by_check(make(api=api).collect())
    assert r["ids"].status == "unknown" and "Missing privilege" in r["ids"].summary
    assert r["vlans"].status == "pass"


def test_github_unreachable_gives_unknown(opn_env):
    def offline(request):
        raise httpx.ConnectError("offline", request=request)
    r = by_check(make(gh=offline).collect())
    assert r["firmware"].status == "unknown" and "26.1.6_2" in r["firmware"].summary


def test_latest_check_disabled(opn_env, monkeypatch):
    monkeypatch.setattr(config, "OPNSENSE_CHECK_LATEST", False)
    r = by_check(make().collect())
    assert r["firmware"].status == "unknown" and "disabled" in r["firmware"].summary


def test_test_connection(opn_env):
    ok, msg = make().test_connection()
    assert ok and "OPNsense.internal" in msg and "26.1.6_2" in msg


def test_collection_saves_on_nis2_controls(opn_env):
    with TestClient(app):
        result = evidence.run_collection("opnsense", make())
        assert result["ok"] and result["saved"] == 6
        latest = evidence.latest_by_control("nis2")
        for cid in ("nis2-e-02", "nis2-g-03", "nis2-g-04", "nis2-h-02", "nis2-h-03", "nis2-i-05"):
            assert latest[cid]["source"] == "opnsense"
        assert "nis2-c-02" not in latest and "nis2-j-02" not in latest   # manual controls
