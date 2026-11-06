"""Microsoft 365 / Entra ID collector (Microsoft Graph, read-only).

Uses an app registration in the customer's tenant with application permissions that
only read. Recommended set (admin consent required once):

    Policy.Read.All                  security defaults, Conditional Access policies
    RoleManagement.Read.Directory    who holds admin roles
    User.Read.All                    users, guests, account state
    AuditLog.Read.All                MFA registration report, last sign-in (Entra ID P1/P2)
    UserAuthenticationMethod.Read.All  only for tenants without Entra ID P1: per-user MFA methods

Checks:
    mfa                  MFA is enforced (security defaults or a Conditional Access policy for
                         all users) and every enabled member account has MFA registered
    privileged_accounts  2-4 Global Administrators and every admin has MFA registered
    stale_accounts       no enabled account unused for STALE_DAYS (needs Entra ID P1)
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import httpx

from app import config
from app.collectors.base import FAIL, PASS, UNKNOWN, BaseCollector, CheckResult

log = logging.getLogger("comply.microsoft365")

GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"
GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"
MFA_METHOD_TYPES = {
    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
    "#microsoft.graph.phoneAuthenticationMethod",
    "#microsoft.graph.fido2AuthenticationMethod",
    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod",
    "#microsoft.graph.softwareOathAuthenticationMethod",
    "#microsoft.graph.platformCredentialAuthenticationMethod",
}


class GraphError(RuntimeError):
    pass


class NotAvailable(GraphError):
    """The tenant's licence or the app's permissions do not allow this query."""


class GraphClient:
    def __init__(self, tenant: str, client_id: str, secret: str, transport: httpx.BaseTransport | None = None):
        self._tenant, self._client_id, self._secret = tenant, client_id, secret
        self._http = httpx.Client(timeout=30, transport=transport)
        self._token: str | None = None

    def _authenticate(self) -> None:
        r = self._http.post(f"{LOGIN}/{self._tenant}/oauth2/v2.0/token", data={
            "grant_type": "client_credentials", "client_id": self._client_id,
            "client_secret": self._secret, "scope": "https://graph.microsoft.com/.default"})
        if r.status_code in (400, 401):
            detail = (r.json().get("error_description") or "").split("\r\n")[0] if r.content else ""
            raise GraphError(f"Sign-in to Entra ID failed: check tenant, client ID and secret. {detail}".strip())
        r.raise_for_status()
        self._token = r.json()["access_token"]

    def get(self, url: str, params: dict | None = None) -> dict:
        if not self._token:
            self._authenticate()
        full = url if url.startswith("https://") else GRAPH + url
        for attempt in (1, 2):
            r = self._http.get(full, params=params, headers={"Authorization": f"Bearer {self._token}",
                                                            "ConsistencyLevel": "eventual"})
            if r.status_code == 401 and attempt == 1:
                self._authenticate()
                continue
            if r.status_code == 403:
                err = (r.json().get("error") or {}) if r.content else {}
                raise NotAvailable(err.get("message") or "Access denied")
            if r.status_code == 429:
                raise GraphError("Microsoft Graph is throttling requests; try again later")
            r.raise_for_status()
            return r.json()
        raise GraphError(f"Could not read {url}")

    def items(self, url: str, params: dict | None = None) -> list[dict]:
        out: list[dict] = []
        data = self.get(url, params)
        while True:
            out.extend(data.get("value", []))
            nxt = data.get("@odata.nextLink")
            if not nxt:
                return out
            data = self.get(nxt)

    def close(self) -> None:
        self._http.close()


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


class Microsoft365Collector(BaseCollector):
    name = "microsoft365"

    def __init__(self, transport: httpx.BaseTransport | None = None, now: datetime | None = None):
        self._transport = transport
        self._now = now

    def is_configured(self) -> bool:
        return bool(config.M365_TENANT_ID and config.M365_CLIENT_ID and config.M365_CLIENT_SECRET)

    def _client(self) -> GraphClient:
        return GraphClient(config.M365_TENANT_ID, config.M365_CLIENT_ID, config.M365_CLIENT_SECRET, self._transport)

    def _utcnow(self) -> datetime:
        return self._now or datetime.now(timezone.utc)

    def test_connection(self) -> tuple[bool, str]:
        if not self.is_configured():
            return False, "Microsoft 365 is not configured in .env"
        g = self._client()
        try:
            org = g.get("/organization", {"$select": "displayName,verifiedDomains"})["value"][0]
            domain = next((d["name"] for d in org.get("verifiedDomains", []) if d.get("isDefault")), "")
            return True, f"Graph OK, tenant {org.get('displayName', '?')} {domain}".strip()
        except Exception as exc:  # noqa: BLE001
            return False, f"Graph error: {exc}"
        finally:
            g.close()

    # -- data shared by several checks

    def _members(self, g: GraphClient) -> list[dict]:
        users = g.items("/users", {"$select": "id,userPrincipalName,accountEnabled,userType,createdDateTime",
                                   "$top": "999"})
        return [u for u in users if u.get("accountEnabled") and u.get("userType", "Member") == "Member"]

    def _mfa_registered(self, g: GraphClient, members: list[dict]) -> tuple[dict[str, bool], str]:
        """userPrincipalName -> has MFA. Uses the registration report (P1), else per-user methods."""
        try:
            rows = g.items("/reports/authenticationMethods/userRegistrationDetails", {"$top": "999"})
            return {r["userPrincipalName"].lower(): bool(r.get("isMfaRegistered")) for r in rows}, "report"
        except NotAvailable:
            pass
        result = {}
        for u in members:
            methods = g.items(f"/users/{u['id']}/authentication/methods")
            result[u["userPrincipalName"].lower()] = any(m.get("@odata.type") in MFA_METHOD_TYPES for m in methods)
        return result, "methods"

    def collect(self) -> list[CheckResult]:
        g = self._client()
        try:
            try:
                members = self._members(g)
            except Exception as exc:  # noqa: BLE001
                msg = f"Could not read users from Microsoft Graph: {exc}"
                return [CheckResult(c, UNKNOWN, msg) for c in ("mfa", "privileged_accounts", "stale_accounts")]
            try:
                registered, mfa_source = self._mfa_registered(g, members)
            except Exception as exc:  # noqa: BLE001
                registered, mfa_source = None, f"unavailable ({exc})"
            results = []
            for name, fn in (("mfa", self._check_mfa), ("privileged_accounts", self._check_admins),
                             ("stale_accounts", self._check_stale)):
                try:
                    results.append(fn(g, members, registered, mfa_source))
                except Exception as exc:  # noqa: BLE001
                    log.warning("Check %s failed: %s", name, exc)
                    results.append(CheckResult(name, UNKNOWN, f"Check could not run: {exc}"))
            return results
        finally:
            g.close()

    # -- checks

    def _enforcement(self, g: GraphClient) -> tuple[bool | None, str]:
        sd = g.get("/policies/identitySecurityDefaultsEnforcementPolicy")
        if sd.get("isEnabled"):
            return True, "security defaults are enabled"
        try:
            policies = g.items("/identity/conditionalAccess/policies")
        except NotAvailable:
            return None, ("security defaults are off and Conditional Access cannot be read "
                          "(needs Entra ID P1 and Policy.Read.All)")
        for p in policies:
            users = ((p.get("conditions") or {}).get("users") or {})
            grant = p.get("grantControls") or {}
            requires_mfa = "mfa" in (grant.get("builtInControls") or []) or bool(grant.get("authenticationStrength"))
            if p.get("state") == "enabled" and "All" in (users.get("includeUsers") or []) and requires_mfa:
                return True, f"Conditional Access policy '{p.get('displayName')}' requires MFA for all users"
        return False, "security defaults are off and no enabled Conditional Access policy requires MFA for all users"

    def _check_mfa(self, g, members, registered, mfa_source) -> CheckResult:
        enforced, how = self._enforcement(g)
        if registered is None:
            raw = {"enforced": enforced, "enforcement": how, "registration_source": mfa_source}
            if enforced is False:
                return CheckResult("mfa", FAIL, f"MFA is not enforced: {how}.", raw)
            return CheckResult("mfa", UNKNOWN, f"MFA enforcement: {how}. MFA registration could not be read "
                               "(grant AuditLog.Read.All with Entra ID P1, or UserAuthenticationMethod.Read.All).", raw)
        missing = [u["userPrincipalName"] for u in members if not registered.get(u["userPrincipalName"].lower())]
        raw = {"enforced": enforced, "enforcement": how, "members": len(members),
               "without_mfa": missing, "registration_source": mfa_source}
        coverage = f"{len(members) - len(missing)}/{len(members)} enabled accounts have MFA registered"
        if enforced is False:
            return CheckResult("mfa", FAIL, f"MFA is not enforced: {how}. {coverage}.", raw)
        if missing:
            shown = ", ".join(missing[:5]) + (f" and {len(missing) - 5} more" if len(missing) > 5 else "")
            return CheckResult("mfa", FAIL, f"{coverage}. Without MFA: {shown}.", raw)
        if enforced is None:
            return CheckResult("mfa", UNKNOWN, f"{coverage}, but enforcement could not be verified: {how}.", raw)
        return CheckResult("mfa", PASS, f"MFA enforced ({how}); {coverage}.", raw)

    def _check_admins(self, g, members, registered, _src) -> CheckResult:
        defs = {d["id"]: d.get("displayName") for d in
                g.items("/roleManagement/directory/roleDefinitions", {"$select": "id,displayName,templateId"})}
        assignments = g.items("/roleManagement/directory/roleAssignments", {"$expand": "principal"})
        admins: dict[str, set] = {}
        global_admins = set()
        for a in assignments:
            principal = a.get("principal") or {}
            if principal.get("@odata.type") != "#microsoft.graph.user":
                continue
            upn = principal.get("userPrincipalName", principal.get("id"))
            admins.setdefault(upn, set()).add(defs.get(a.get("roleDefinitionId"), a.get("roleDefinitionId")))
            if a.get("roleDefinitionId") == GLOBAL_ADMIN_TEMPLATE:
                global_admins.add(upn)
        no_mfa = [] if registered is None else sorted(u for u in admins if not registered.get(str(u).lower()))
        raw = {"global_admins": sorted(global_admins), "admins": {u: sorted(r) for u, r in admins.items()},
               "admins_without_mfa": no_mfa}
        issues = []
        if len(global_admins) > 4:
            issues.append(f"{len(global_admins)} Global Administrators (recommended: 2-4)")
        if len(global_admins) < 2:
            issues.append(f"only {len(global_admins)} Global Administrator (keep 2 for emergency access)")
        if no_mfa:
            issues.append("admins without MFA: " + ", ".join(no_mfa))
        base = f"{len(admins)} accounts hold admin roles, {len(global_admins)} of them Global Administrator."
        if issues:
            return CheckResult("privileged_accounts", FAIL, base + " Issues: " + "; ".join(issues) + ".", raw)
        if registered is None:
            return CheckResult("privileged_accounts", UNKNOWN,
                               base + " Admin MFA registration could not be read.", raw)
        return CheckResult("privileged_accounts", PASS, base + " All admins have MFA registered.", raw)

    def _check_stale(self, g, _members, _registered, _src) -> CheckResult:
        days = config.M365_STALE_DAYS
        try:
            users = g.items("/users", {"$select": "userPrincipalName,accountEnabled,userType,createdDateTime,"
                                                  "signInActivity", "$top": "999"})
        except NotAvailable:
            return CheckResult("stale_accounts", UNKNOWN,
                               "Last sign-in dates need Entra ID P1 and AuditLog.Read.All. "
                               "Document the leaver process manually.")
        cutoff = self._utcnow() - timedelta(days=days)
        stale = []
        for u in users:
            if not u.get("accountEnabled"):
                continue
            created = _parse(u.get("createdDateTime"))
            if created and created > cutoff:
                continue                                   # new account, give it time
            act = u.get("signInActivity") or {}
            last = max(filter(None, (_parse(act.get("lastSuccessfulSignInDateTime")),
                                     _parse(act.get("lastSignInDateTime")),
                                     _parse(act.get("lastNonInteractiveSignInDateTime")))), default=None)
            if not last or last < cutoff:
                stale.append(f"{u['userPrincipalName']} ({'guest' if u.get('userType') == 'Guest' else 'member'})")
        raw = {"days": days, "stale": stale, "enabled": sum(1 for u in users if u.get("accountEnabled"))}
        if stale:
            shown = ", ".join(stale[:5]) + (f" and {len(stale) - 5} more" if len(stale) > 5 else "")
            return CheckResult("stale_accounts", FAIL,
                               f"{len(stale)} enabled accounts unused for {days}+ days: {shown}.", raw)
        return CheckResult("stale_accounts", PASS, f"No enabled account has been unused for {days}+ days.", raw)
