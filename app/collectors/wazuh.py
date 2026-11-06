"""Wazuh collector: Server API (port 55000) + Indexer (port 9200, optional).

Server API  -> agents, versions, SCA, FIM, inventory (syscollector)
Indexer     -> alerts and vulnerabilities (moved out of the Server API in Wazuh 4.8)

Read-only access is enough: an API user with the 'readonly' role and,
for the Indexer, a user with read-only access to the wazuh-* indices.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from app import config
from app.collectors.base import FAIL, PASS, UNKNOWN, BaseCollector, CheckResult

log = logging.getLogger("comply.wazuh")

MANAGER_ID = "000"
PAGE = 500


class WazuhError(RuntimeError):
    pass


# ---------------------------------------------------------------- clients

class WazuhAPI:
    """Minimal Wazuh Server API client with automatic re-authentication."""

    def __init__(self, url: str, user: str, password: str, verify: bool = False,
                 transport: httpx.BaseTransport | None = None):
        self._user, self._password = user, password
        self._token: str | None = None
        self._http = httpx.Client(base_url=url.rstrip("/"), verify=verify, timeout=20,
                                  transport=transport)

    def _authenticate(self) -> None:
        r = self._http.post("/security/user/authenticate", auth=(self._user, self._password))
        if r.status_code == 401:
            raise WazuhError("Authentication failed: check WAZUH_USER / WAZUH_PASSWORD")
        r.raise_for_status()
        self._token = r.json()["data"]["token"]

    def get(self, path: str, params: dict | None = None) -> dict:
        if not self._token:
            self._authenticate()
        for attempt in (1, 2):
            r = self._http.get(path, params=params, headers={"Authorization": f"Bearer {self._token}"})
            if r.status_code == 401 and attempt == 1:   # token expired (15 min by default)
                self._authenticate()
                continue
            if r.status_code == 403:
                raise WazuhError(f"Access denied to {path}: the user lacks read permissions")
            r.raise_for_status()
            return r.json()["data"]
        raise WazuhError(f"Could not access {path}")

    def items(self, path: str, params: dict | None = None) -> list[dict]:
        """All results of an endpoint, following pagination."""
        params = dict(params or {})
        out: list[dict] = []
        offset = 0
        while True:
            data = self.get(path, {**params, "limit": PAGE, "offset": offset})
            batch = data.get("affected_items", [])
            out.extend(batch)
            offset += len(batch)
            if not batch or offset >= data.get("total_affected_items", 0):
                return out

    def close(self) -> None:
        self._http.close()


class WazuhIndexer:
    """Minimal Wazuh Indexer (OpenSearch) client, search only."""

    def __init__(self, url: str, user: str, password: str, verify: bool = False,
                 transport: httpx.BaseTransport | None = None):
        self._http = httpx.Client(base_url=url.rstrip("/"), verify=verify, timeout=30,
                                  auth=(user, password), transport=transport)

    def search(self, index: str, body: dict) -> dict | None:
        """Return the response, or None if the index does not exist."""
        r = self._http.post(f"/{index}/_search", json=body)
        if r.status_code == 404:
            return None
        if r.status_code in (401, 403):
            raise WazuhError("Indexer: access denied, check WAZUH_INDEXER_USER / PASSWORD")
        r.raise_for_status()
        return r.json()

    def ping(self) -> None:
        r = self._http.get("/")
        if r.status_code in (401, 403):
            raise WazuhError("Indexer: authentication failed")
        r.raise_for_status()

    def close(self) -> None:
        self._http.close()


# ---------------------------------------------------------------- helpers

def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _version_tuple(value: str | None) -> tuple[int, ...]:
    """'Wazuh v4.14.8' or 'v4.14.8' -> (4, 14, 8)."""
    if not value:
        return ()
    v = value.split()[-1].lstrip("v")
    parts = []
    for p in v.split("."):
        num = ""
        for ch in p:              # leading digits only: "0-rc1" -> 0
            if not ch.isdigit():
                break
            num += ch
        if not num:
            break
        parts.append(int(num))
    return tuple(parts)


# ---------------------------------------------------------------- collector

class WazuhCollector(BaseCollector):
    name = "wazuh"

    def __init__(self, api_transport: httpx.BaseTransport | None = None,
                 indexer_transport: httpx.BaseTransport | None = None,
                 now: datetime | None = None):
        self._api_transport = api_transport
        self._indexer_transport = indexer_transport
        self._now = now

    # -- configuration

    def is_configured(self) -> bool:
        return bool(config.WAZUH_URL and config.WAZUH_USER and config.WAZUH_PASSWORD)

    def indexer_configured(self) -> bool:
        return bool(config.WAZUH_INDEXER_URL and config.WAZUH_INDEXER_USER
                    and config.WAZUH_INDEXER_PASSWORD)

    def _api(self) -> WazuhAPI:
        return WazuhAPI(config.WAZUH_URL, config.WAZUH_USER, config.WAZUH_PASSWORD,
                        config.WAZUH_VERIFY_TLS, self._api_transport)

    def _indexer(self) -> WazuhIndexer:
        return WazuhIndexer(config.WAZUH_INDEXER_URL, config.WAZUH_INDEXER_USER,
                            config.WAZUH_INDEXER_PASSWORD, config.WAZUH_VERIFY_TLS,
                            self._indexer_transport)

    def _utcnow(self) -> datetime:
        return self._now or datetime.now(timezone.utc)

    # -- connection test

    def test_connection(self) -> tuple[bool, str]:
        if not self.is_configured():
            return False, "Wazuh is not configured in .env"
        messages = []
        ok = True
        api = self._api()
        try:
            info = api.get("/manager/info")["affected_items"][0]
            messages.append(f"API OK, manager {info.get('version', '?')}")
        except Exception as exc:  # noqa: BLE001
            ok = False
            messages.append(f"API error: {exc}")
        finally:
            api.close()
        if self.indexer_configured():
            idx = self._indexer()
            try:
                idx.ping()
                messages.append("Indexer OK")
            except Exception as exc:  # noqa: BLE001
                ok = False
                messages.append(f"Indexer error: {exc}")
            finally:
                idx.close()
        else:
            messages.append("Indexer not configured (alerts and vulnerabilities will be 'unknown')")
        return ok, "; ".join(messages)

    # -- collection

    def collect(self) -> list[CheckResult]:
        results: list[CheckResult] = []
        api = self._api()
        try:
            try:
                manager_version = api.get("/manager/info")["affected_items"][0].get("version")
                agents = [a for a in api.items(
                    "/agents", {"select": "id,name,status,version,lastKeepAlive,os.name"})
                    if a.get("id") != MANAGER_ID]
            except Exception as exc:  # noqa: BLE001
                # Without the agent list no API check can run
                msg = f"Could not read agents from the Wazuh API: {exc}"
                log.warning(msg)
                for check in ("agents_active", "agents_version", "sca", "fim", "syscollector"):
                    results.append(CheckResult(check, UNKNOWN, msg))
                agents = None

            if agents is not None:
                active = [a for a in agents if a.get("status") == "active"]
                for fn in (self._check_agents_active, self._check_agents_version):
                    results.append(self._safe(fn.__name__, fn, agents, manager_version))
                for fn in (self._check_sca, self._check_fim, self._check_syscollector):
                    results.append(self._safe(fn.__name__, fn, api, active))
        finally:
            api.close()

        if self.indexer_configured():
            idx = self._indexer()
            try:
                results.append(self._safe("_check_alerts_recent", self._check_alerts_recent, idx))
                results.append(self._safe("_check_vulnerabilities", self._check_vulnerabilities, idx))
            finally:
                idx.close()
        else:
            note = "Wazuh Indexer not configured in .env (WAZUH_INDEXER_*)"
            results.append(CheckResult("alerts_recent", UNKNOWN, note))
            results.append(CheckResult("vulnerabilities", UNKNOWN, note))
        return results

    @staticmethod
    def _safe(fn_name: str, fn, *args) -> CheckResult:
        check = fn_name.removeprefix("_check_")
        try:
            return fn(*args)
        except Exception as exc:  # noqa: BLE001
            log.warning("Check %s failed: %s", check, exc)
            return CheckResult(check, UNKNOWN, f"Check could not run: {exc}")

    # -- individual checks

    def _check_agents_active(self, agents: list[dict], _mv) -> CheckResult:
        if not agents:
            return CheckResult("agents_active", FAIL, "No agents registered apart from the manager.")
        by_status: dict[str, list[str]] = {}
        for a in agents:
            by_status.setdefault(a.get("status", "unknown"), []).append(a.get("name", a.get("id")))
        active = len(by_status.get("active", []))
        problems = {s: n for s, n in by_status.items() if s != "active"}
        raw = {"total": len(agents), "by_status": by_status}
        if not problems:
            return CheckResult("agents_active", PASS, f"All {active} agents are active.", raw)
        detail = ", ".join(f"{s}: {', '.join(n)}" for s, n in problems.items())
        return CheckResult("agents_active", FAIL,
                           f"{active}/{len(agents)} agents active. Issues: {detail}", raw)

    def _check_agents_version(self, agents: list[dict], manager_version: str | None) -> CheckResult:
        mv = _version_tuple(manager_version)
        if not agents or not mv:
            return CheckResult("agents_version", UNKNOWN, "No agents, or the manager version is missing.")
        outdated = [f"{a.get('name')} ({a.get('version') or 'unknown'})" for a in agents
                    if _version_tuple(a.get("version"))[:2] != mv[:2]]
        raw = {"manager_version": manager_version,
               "agents": {a.get("name"): a.get("version") for a in agents}}
        if not outdated:
            return CheckResult("agents_version", PASS,
                               f"All agents run the manager version {manager_version} (major.minor).", raw)
        return CheckResult("agents_version", FAIL,
                           f"{len(outdated)} agents differ from manager version {manager_version}: "
                           + ", ".join(outdated), raw)

    def _check_sca(self, api: WazuhAPI, active: list[dict]) -> CheckResult:
        if not active:
            return CheckResult("sca", UNKNOWN, "No active agents to evaluate SCA.")
        per_agent: dict[str, list[dict]] = {}
        below, no_scan = [], []
        for a in active:
            policies = api.items(f"/sca/{a['id']}")
            per_agent[a["name"]] = [{"policy": p.get("name"), "score": p.get("score"),
                                     "pass": p.get("pass"), "fail": p.get("fail")} for p in policies]
            if not policies:
                no_scan.append(a["name"])
                continue
            worst = min(p.get("score", 0) for p in policies)
            if worst < config.SCA_MIN_SCORE:
                below.append(f"{a['name']} ({worst}%)")
        raw = {"min_score": config.SCA_MIN_SCORE, "agents": per_agent}
        scores = [p["score"] for ps in per_agent.values() for p in ps if p["score"] is not None]
        avg = round(sum(scores) / len(scores)) if scores else 0
        if not below and not no_scan:
            return CheckResult("sca", PASS,
                               f"All active agents have an SCA score >= {config.SCA_MIN_SCORE}% (average {avg}%).", raw)
        parts = []
        if below:
            parts.append(f"below {config.SCA_MIN_SCORE}%: {', '.join(below)}")
        if no_scan:
            parts.append(f"no SCA scan: {', '.join(no_scan)}")
        return CheckResult("sca", FAIL, f"Average SCA score {avg}%. " + "; ".join(parts), raw)

    def _check_fim(self, api: WazuhAPI, active: list[dict]) -> CheckResult:
        if not active:
            return CheckResult("fim", UNKNOWN, "No active agents to check FIM.")
        now = self._utcnow()
        stale, last = [], {}
        for a in active:
            items = api.get(f"/syscheck/{a['id']}/last_scan").get("affected_items") or [{}]
            end = _parse_time(items[0].get("end"))
            last[a["name"]] = items[0].get("end")
            if not end or (now - end).total_seconds() > config.FIM_MAX_AGE_HOURS * 3600:
                stale.append(a["name"])
        raw = {"max_age_hours": config.FIM_MAX_AGE_HOURS, "last_scan_end": last}
        if not stale:
            return CheckResult("fim", PASS,
                               f"FIM ran on all {len(active)} active agents in the last "
                               f"{config.FIM_MAX_AGE_HOURS} hours.", raw)
        return CheckResult("fim", FAIL,
                           f"No recent FIM scan (> {config.FIM_MAX_AGE_HOURS}h) on: {', '.join(stale)}", raw)

    def _check_syscollector(self, api: WazuhAPI, active: list[dict]) -> CheckResult:
        if not active:
            return CheckResult("syscollector", UNKNOWN, "No active agents for inventory.")
        inventory, missing = {}, []
        for a in active:
            os_items = api.get(f"/syscollector/{a['id']}/os").get("affected_items") or []
            pkg_total = api.get(f"/syscollector/{a['id']}/packages", {"limit": 1}).get("total_affected_items", 0)
            os_name = (os_items[0].get("os") or {}).get("name") if os_items else None
            inventory[a["name"]] = {"os": os_name, "packages": pkg_total}
            if not os_name or not pkg_total:
                missing.append(a["name"])
        raw = {"inventory": inventory}
        if not missing:
            total_pkgs = sum(v["packages"] for v in inventory.values())
            return CheckResult("syscollector", PASS,
                               f"Complete inventory for {len(active)} agents ({total_pkgs} packages).", raw)
        return CheckResult("syscollector", FAIL, f"Incomplete inventory for: {', '.join(missing)}", raw)

    def _check_alerts_recent(self, idx: WazuhIndexer) -> CheckResult:
        days = config.ALERTS_WINDOW_DAYS
        resp = idx.search("wazuh-alerts-*", {
            "size": 0, "track_total_hits": True,
            "query": {"range": {"timestamp": {"gte": f"now-{days}d"}}},
            "aggs": {"levels": {"range": {"field": "rule.level", "ranges": [
                {"key": "low", "to": 7}, {"key": "medium", "from": 7, "to": 12},
                {"key": "high", "from": 12}]}}},
        })
        if resp is None:
            return CheckResult("alerts_recent", FAIL, "The wazuh-alerts-* index does not exist.")
        total = resp["hits"]["total"]["value"]
        levels = {b["key"]: b["doc_count"] for b in resp["aggregations"]["levels"]["buckets"]}
        raw = {"window_days": days, "total": total, "by_level": levels}
        if total == 0:
            return CheckResult("alerts_recent", FAIL,
                               f"No alerts in the last {days} days: monitoring appears to be down.", raw)
        return CheckResult("alerts_recent", PASS,
                           f"{total} alerts in the last {days} days (level 12+: {levels.get('high', 0)}, "
                           f"7-11: {levels.get('medium', 0)}). Alert review is documented manually.", raw)

    def _check_vulnerabilities(self, idx: WazuhIndexer) -> CheckResult:
        resp = idx.search("wazuh-states-vulnerabilities-*", {
            "size": 0, "track_total_hits": True,
            "aggs": {"severity": {"terms": {"field": "vulnerability.severity", "size": 10}}},
        })
        if resp is None:
            return CheckResult("vulnerabilities", UNKNOWN,
                               "The vulnerability index does not exist: is Vulnerability Detection enabled?")
        sev = {b["key"]: b["doc_count"] for b in resp["aggregations"]["severity"]["buckets"]}
        total = resp["hits"]["total"]["value"]
        raw = {"total": total, "by_severity": sev}
        summary = ", ".join(f"{k}: {v}" for k, v in sorted(sev.items())) or "none"
        if sev.get("Critical", 0) > 0:
            return CheckResult("vulnerabilities", FAIL,
                               f"{sev['Critical']} open critical vulnerabilities. Total {total} ({summary}).", raw)
        return CheckResult("vulnerabilities", PASS,
                           f"No critical vulnerabilities. Total {total} ({summary}).", raw)
