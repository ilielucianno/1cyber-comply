"""OPNsense collector.

OPNsense has no read-only API role: privileges are granted per page and many of
them also allow changes. This collector therefore only ever sends GET requests,
and the recommended API user gets the smallest set of privileges below:

    Lobby: Dashboard                      -> version (firmware check)
    Diagnostics: Firewall Statistics      -> active pf ruleset (firewall check)
    Services: Intrusion Detection         -> IDS/IPS settings and status
    VPN: WireGuard (configuration/status) -> remote access VPN
    Interfaces: VLAN                      -> network segmentation

Deliberately NOT required (they allow updates, config download or restore):
System: Firmware, Diagnostics: Backup & Restore, Diagnostics: Configuration History.
"""
from __future__ import annotations

import logging
import re
from urllib.parse import urlsplit

import httpx

from app import config
from app.collectors.base import FAIL, PASS, UNKNOWN, BaseCollector, CheckResult

log = logging.getLogger("comply.opnsense")

GITHUB_TAGS = "https://api.github.com/repos/opnsense/core/tags?per_page=100"

_RULE_PREFIX = re.compile(r"^@\d+\s+")
_DEFAULT_DENY = re.compile(r"^block (drop |return )?in\b.*\b(all|from any to any)\b")
_RESTRICTED = re.compile(r"\b(proto|port|icmp-type|icmp6-type)\b")


class OPNsenseError(RuntimeError):
    pass


def parse_version(text: str | None) -> tuple[int, ...]:
    """'OPNsense 26.1.6_2-amd64' or '26.1.6' -> (26, 1, 6)."""
    if not text:
        return ()
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", text)
    if not m:
        return ()
    return tuple(int(g) for g in m.groups(default="0"))


def analyse_ruleset(filter_rules: dict) -> dict:
    """Classify active pf filter rules (engine-independent: legacy and new rules)."""
    rules = [_RULE_PREFIX.sub("", r).strip() for r in filter_rules]
    default_deny = [r for r in rules if _DEFAULT_DENY.search(r)]
    permissive = []
    for r in rules:
        if not r.startswith("pass in"):
            continue
        if " on lo" in r or _RESTRICTED.search(r):
            continue
        if re.search(r"\bfrom any to any\b", r) or re.search(r"\bpass in( log)?( quick)?( on \S+)?( inet6?)? all\b", r):
            permissive.append(r)
    return {
        "total": len(rules),
        "pass_in": sum(1 for r in rules if r.startswith("pass in")),
        "block_in": sum(1 for r in rules if r.startswith("block") and " in " in f" {r} "),
        "default_deny": bool(default_deny),
        "any_to_any": permissive,
    }


class OPNsenseClient:
    def __init__(self, url: str, key: str, secret: str, verify: bool = False,
                 transport: httpx.BaseTransport | None = None):
        self._http = httpx.Client(base_url=url.rstrip("/"), auth=(key, secret), verify=verify,
                                  timeout=20, transport=transport)

    def get(self, path: str, params: dict | None = None) -> dict:
        r = self._http.get(path, params=params)
        if r.status_code == 401:
            raise OPNsenseError("Authentication failed: check OPNSENSE_KEY / OPNSENSE_SECRET")
        if r.status_code == 403:
            raise OPNsenseError(f"Missing privilege for {path} (see README for the required privileges)")
        r.raise_for_status()
        return r.json()

    def close(self) -> None:
        self._http.close()


class OPNsenseCollector(BaseCollector):
    name = "opnsense"

    def __init__(self, transport: httpx.BaseTransport | None = None,
                 http_transport: httpx.BaseTransport | None = None,
                 github_transport: httpx.BaseTransport | None = None):
        self._transport = transport                # OPNsense API
        self._http_transport = http_transport      # plain-HTTP probe of the web GUI
        self._github_transport = github_transport  # latest release lookup

    def is_configured(self) -> bool:
        return bool(config.OPNSENSE_URL and config.OPNSENSE_KEY and config.OPNSENSE_SECRET)

    def _client(self) -> OPNsenseClient:
        return OPNsenseClient(config.OPNSENSE_URL, config.OPNSENSE_KEY, config.OPNSENSE_SECRET,
                              config.OPNSENSE_VERIFY_TLS, self._transport)

    def test_connection(self) -> tuple[bool, str]:
        if not self.is_configured():
            return False, "OPNsense is not configured in .env"
        client = self._client()
        try:
            info = client.get("/api/diagnostics/system/system_information")
            version = (info.get("versions") or ["?"])[0]
            return True, f"API OK, {info.get('name', 'firewall')} running {version}"
        except Exception as exc:  # noqa: BLE001
            return False, f"API error: {exc}"
        finally:
            client.close()

    def collect(self) -> list[CheckResult]:
        client = self._client()
        try:
            checks = [
                ("firmware", self._check_firmware),
                ("firewall_rules", self._check_firewall_rules),
                ("ids", self._check_ids),
                ("vpn", self._check_vpn),
                ("webgui_https", self._check_webgui_https),
                ("vlans", self._check_vlans),
            ]
            results = []
            for name, fn in checks:
                try:
                    results.append(fn(client))
                except Exception as exc:  # noqa: BLE001
                    log.warning("Check %s failed: %s", name, exc)
                    results.append(CheckResult(name, UNKNOWN, f"Check could not run: {exc}"))
            return results
        finally:
            client.close()

    # -- individual checks

    def _latest_release(self) -> tuple[int, ...]:
        with httpx.Client(timeout=15, transport=self._github_transport,
                          headers={"Accept": "application/vnd.github+json",
                                   "User-Agent": "1cyber-comply"}) as gh:
            r = gh.get(GITHUB_TAGS)
            r.raise_for_status()
            versions = [parse_version(t["name"]) for t in r.json()
                        if re.fullmatch(r"\d+\.\d+(\.\d+)?", t.get("name", ""))]
        if not versions:
            raise OPNsenseError("no release tags found on GitHub")
        return max(versions)

    def _check_firmware(self, client: OPNsenseClient) -> CheckResult:
        info = client.get("/api/diagnostics/system/system_information")
        installed_text = (info.get("versions") or [""])[0]
        installed = parse_version(installed_text)
        raw = {"installed": installed_text}
        if not installed:
            return CheckResult("firmware", UNKNOWN, "Could not read the installed OPNsense version.", raw)
        if not config.OPNSENSE_CHECK_LATEST:
            return CheckResult("firmware", UNKNOWN,
                               f"Installed {installed_text}. Latest-release lookup is disabled "
                               "(OPNSENSE_CHECK_LATEST=false).", raw)
        try:
            latest = self._latest_release()
        except Exception as exc:  # noqa: BLE001
            return CheckResult("firmware", UNKNOWN,
                               f"Installed {installed_text}. Could not look up the latest release: {exc}", raw)
        latest_text = ".".join(map(str, latest))
        raw["latest_release"] = latest_text
        if installed >= latest:
            return CheckResult("firmware", PASS,
                               f"Installed {installed_text}, latest public release is {latest_text}.", raw)
        return CheckResult("firmware", FAIL,
                           f"Installed {installed_text} is behind the latest release {latest_text}.", raw)

    def _check_firewall_rules(self, client: OPNsenseClient) -> CheckResult:
        data = client.get("/api/diagnostics/firewall/pf_statistics/rules")
        filter_rules = (data.get("rules") or {}).get("filter rules") or {}
        if not filter_rules:
            return CheckResult("firewall_rules", UNKNOWN, "No active filter rules returned by pf.")
        a = analyse_ruleset(filter_rules)
        raw = {k: a[k] for k in ("total", "pass_in", "block_in", "default_deny")}
        raw["any_to_any_rules"] = a["any_to_any"]
        base = f"{a['total']} active rules ({a['pass_in']} inbound pass, {a['block_in']} inbound block)."
        problems = []
        if not a["default_deny"]:
            problems.append("no default-deny inbound rule found")
        if a["any_to_any"]:
            problems.append(f"{len(a['any_to_any'])} unrestricted any-to-any inbound pass rule(s)")
        if problems:
            return CheckResult("firewall_rules", FAIL, base + " Issues: " + "; ".join(problems) + ".", raw)
        return CheckResult("firewall_rules", PASS,
                           base + " Default deny is active and no unrestricted any-to-any inbound rules.", raw)

    def _check_ids(self, client: OPNsenseClient) -> CheckResult:
        general = (client.get("/api/ids/settings/get").get("ids") or {}).get("general") or {}
        status = client.get("/api/ids/service/status").get("status", "unknown")
        enabled = str(general.get("enabled", "0")) == "1"
        ips = str(general.get("ips", "0")) == "1"
        raw = {"enabled": enabled, "ips_mode": ips, "service_status": status}
        mode = "IPS (blocking)" if ips else "IDS (detect only)"
        if enabled and status == "running":
            return CheckResult("ids", PASS, f"Intrusion detection is enabled and running in {mode} mode.", raw)
        if enabled:
            return CheckResult("ids", FAIL, f"Intrusion detection is enabled but the service is '{status}'.", raw)
        return CheckResult("ids", FAIL, "Intrusion detection (Suricata) is not enabled.", raw)

    def _check_vpn(self, client: OPNsenseClient) -> CheckResult:
        enabled = str((client.get("/api/wireguard/general/get").get("general") or {}).get("enabled", "0")) == "1"
        servers = client.get("/api/wireguard/server/search_server").get("rows") or []
        active = [s for s in servers if str(s.get("enabled", "1")) == "1"]
        raw = {"wireguard_enabled": enabled, "instances": len(servers), "enabled_instances": len(active)}
        if enabled and active:
            return CheckResult("vpn", PASS, f"WireGuard is enabled with {len(active)} active instance(s).", raw)
        return CheckResult("vpn", UNKNOWN,
                           "No active WireGuard instance. If remote access uses OpenVPN/IPsec, or there is "
                           "no remote access, document it as manual evidence.", raw)

    def _check_webgui_https(self, _client: OPNsenseClient) -> CheckResult:
        parts = urlsplit(config.OPNSENSE_URL)
        raw = {"api_scheme": parts.scheme}
        if parts.scheme != "https":
            return CheckResult("webgui_https", FAIL, "The OPNsense API/web GUI is configured over plain HTTP.", raw)
        try:
            with httpx.Client(timeout=5, transport=self._http_transport, follow_redirects=False) as h:
                r = h.get(f"http://{parts.hostname}/")
        except httpx.TransportError:
            raw["http_port"] = "closed"
            return CheckResult("webgui_https", PASS, "Web GUI uses HTTPS; plain HTTP is not served.", raw)
        raw["http_status"] = r.status_code
        location = r.headers.get("location", "")
        if 300 <= r.status_code < 400 and location.startswith("https://"):
            return CheckResult("webgui_https", PASS, "Web GUI uses HTTPS; plain HTTP redirects to HTTPS.", raw)
        if r.status_code == 200:
            return CheckResult("webgui_https", FAIL, "The web GUI login page is also served over plain HTTP.", raw)
        return CheckResult("webgui_https", PASS,
                           f"Web GUI uses HTTPS; plain HTTP answers with status {r.status_code}.", raw)

    def _check_vlans(self, client: OPNsenseClient) -> CheckResult:
        rows = client.get("/api/interfaces/vlan_settings/search_item", {"rowCount": -1}).get("rows") or []
        raw = {"vlans": [{"tag": v.get("tag"), "parent": v.get("if"), "description": v.get("descr")} for v in rows]}
        if rows:
            tags = ", ".join(str(v.get("tag")) for v in rows)
            return CheckResult("vlans", PASS, f"{len(rows)} VLAN(s) configured (tags: {tags}).", raw)
        return CheckResult("vlans", FAIL,
                           "No VLANs configured: the network looks flat. If zones are separated with "
                           "physical interfaces instead, document it as manual evidence.", raw)
