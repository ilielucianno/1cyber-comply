"""Microsoft 365 / Entra ID collector against a simulated Microsoft Graph (no network)."""
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from helpers import LoggedInClient

from app import config, evidence
from app.collectors.microsoft365 import GLOBAL_ADMIN_TEMPLATE, Microsoft365Collector
from app.main import app

NOW = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)


def iso(days_ago: int) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


USERS = [
    {"id": "1", "userPrincipalName": "ana@example.com", "accountEnabled": True, "userType": "Member",
     "createdDateTime": iso(800), "signInActivity": {"lastSignInDateTime": iso(1)}},
    {"id": "2", "userPrincipalName": "bogdan@example.com", "accountEnabled": True, "userType": "Member",
     "createdDateTime": iso(800), "signInActivity": {"lastSignInDateTime": iso(200)}},
    {"id": "3", "userPrincipalName": "admin@example.com", "accountEnabled": True, "userType": "Member",
     "createdDateTime": iso(900), "signInActivity": {"lastSuccessfulSignInDateTime": iso(3)}},
    {"id": "4", "userPrincipalName": "new@example.com", "accountEnabled": True, "userType": "Member",
     "createdDateTime": iso(10), "signInActivity": {}},
    {"id": "5", "userPrincipalName": "old@example.com", "accountEnabled": False, "userType": "Member",
     "createdDateTime": iso(900), "signInActivity": {}},
    {"id": "6", "userPrincipalName": "partner_ext#EXT#@example.com", "accountEnabled": True, "userType": "Guest",
     "createdDateTime": iso(400), "signInActivity": {"lastSignInDateTime": iso(150)}},
]


class FakeGraph:
    def __init__(self, premium=True, security_defaults=False, ca_mfa_all=True, mfa_missing=("bogdan@example.com",),
                 global_admins=("admin@example.com", "ana@example.com"), token_ok=True, page_users=False):
        self.premium, self.security_defaults, self.ca_mfa_all = premium, security_defaults, ca_mfa_all
        self.mfa_missing, self.global_admins, self.token_ok = set(mfa_missing), global_admins, token_ok
        self.page_users = page_users
        self.calls = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if request.method == "POST" and url.path.endswith("/oauth2/v2.0/token"):
            if not self.token_ok:
                return httpx.Response(401, json={"error": "invalid_client", "error_description": "AADSTS7000215: bad secret"})
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3599})
        assert request.method == "GET", "the collector must only read"
        assert request.headers["authorization"] == "Bearer tok"
        path = url.path.removeprefix("/v1.0")
        self.calls.append(path)
        no_p1 = httpx.Response(403, json={"error": {"code": "Authentication_RequestFromNonPremiumTenantOrB2CTenant",
                                                    "message": "Tenant does not have a SKU required"}})
        if path == "/organization":
            return httpx.Response(200, json={"value": [{"displayName": "Example Ltd", "verifiedDomains": [
                {"name": "example.com", "isDefault": True}]}]})
        if path == "/users":
            wants_signin = "signInActivity" in url.params.get("$select", "")
            if wants_signin and not self.premium:
                return no_p1
            users = [{k: v for k, v in u.items() if wants_signin or k != "signInActivity"} for u in USERS]
            if self.page_users and "skiptoken" not in str(url):
                return httpx.Response(200, json={"value": users[:3],
                                                 "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?skiptoken=2"})
            if self.page_users:
                return httpx.Response(200, json={"value": users[3:]})
            return httpx.Response(200, json={"value": users})
        if path == "/reports/authenticationMethods/userRegistrationDetails":
            if not self.premium:
                return no_p1
            return httpx.Response(200, json={"value": [
                {"userPrincipalName": u["userPrincipalName"], "isMfaRegistered": u["userPrincipalName"] not in self.mfa_missing}
                for u in USERS]})
        if path.startswith("/users/") and path.endswith("/authentication/methods"):
            uid = path.split("/")[2]
            upn = next(u["userPrincipalName"] for u in USERS if u["id"] == uid)
            methods = [{"@odata.type": "#microsoft.graph.passwordAuthenticationMethod"}]
            if upn not in self.mfa_missing:
                methods.append({"@odata.type": "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"})
            return httpx.Response(200, json={"value": methods})
        if path == "/policies/identitySecurityDefaultsEnforcementPolicy":
            return httpx.Response(200, json={"isEnabled": self.security_defaults})
        if path == "/identity/conditionalAccess/policies":
            if not self.premium:
                return no_p1
            include = ["All"] if self.ca_mfa_all else ["some-group"]
            return httpx.Response(200, json={"value": [{"displayName": "Require MFA for all users", "state": "enabled",
                                                        "conditions": {"users": {"includeUsers": include}},
                                                        "grantControls": {"builtInControls": ["mfa"]}}]})
        if path == "/roleManagement/directory/roleDefinitions":
            return httpx.Response(200, json={"value": [{"id": GLOBAL_ADMIN_TEMPLATE, "displayName": "Global Administrator"},
                                                       {"id": "r2", "displayName": "User Administrator"}]})
        if path == "/roleManagement/directory/roleAssignments":
            value = [{"roleDefinitionId": GLOBAL_ADMIN_TEMPLATE,
                      "principal": {"@odata.type": "#microsoft.graph.user", "userPrincipalName": upn}}
                     for upn in self.global_admins]
            value.append({"roleDefinitionId": "r2", "principal": {"@odata.type": "#microsoft.graph.user",
                                                                   "userPrincipalName": "bogdan@example.com"}})
            value.append({"roleDefinitionId": GLOBAL_ADMIN_TEMPLATE,
                          "principal": {"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp"}})
            return httpx.Response(200, json={"value": value})
        return httpx.Response(404, json={"error": {"message": "not found"}})


@pytest.fixture
def m365_env(monkeypatch):
    monkeypatch.setattr(config, "M365_TENANT_ID", "contoso.onmicrosoft.com")
    monkeypatch.setattr(config, "M365_CLIENT_ID", "app-id")
    monkeypatch.setattr(config, "M365_CLIENT_SECRET", "secret")
    monkeypatch.setattr(config, "M365_STALE_DAYS", 90)


def run(graph):
    return {r.check: r for r in Microsoft365Collector(transport=httpx.MockTransport(graph), now=NOW).collect()}


def test_premium_tenant_with_gaps(m365_env):
    r = run(FakeGraph())
    assert r["mfa"].status == "fail" and "bogdan@example.com" in r["mfa"].summary
    assert "3/4 enabled accounts" in r["mfa"].summary                  # disabled + guest excluded
    assert r["privileged_accounts"].status == "fail" and "admins without MFA: bogdan@example.com" in r["privileged_accounts"].summary
    assert r["stale_accounts"].status == "fail"
    assert "bogdan@example.com (member)" in r["stale_accounts"].summary
    assert "partner_ext#EXT#@example.com (guest)" in r["stale_accounts"].summary
    assert "new@example.com" not in r["stale_accounts"].summary       # created 10 days ago


def test_premium_tenant_all_good(m365_env, monkeypatch):
    clean = [dict(u, signInActivity={"lastSignInDateTime": iso(2)}) for u in USERS]
    monkeypatch.setattr(__import__(__name__), "USERS", clean)
    r = run(FakeGraph(mfa_missing=()))
    assert r["mfa"].status == "pass" and "Conditional Access" in r["mfa"].summary
    assert r["privileged_accounts"].status == "pass"
    assert r["stale_accounts"].status == "pass"


def test_free_tenant_uses_security_defaults_and_methods(m365_env):
    g = FakeGraph(premium=False, security_defaults=True, mfa_missing=())
    r = run(g)
    assert r["mfa"].status == "pass" and "security defaults" in r["mfa"].summary
    assert any(c.endswith("/authentication/methods") for c in g.calls)   # fallback without P1
    assert r["stale_accounts"].status == "unknown" and "Entra ID P1" in r["stale_accounts"].summary


def test_free_tenant_without_security_defaults_fails(m365_env):
    r = run(FakeGraph(premium=False, security_defaults=False, mfa_missing=()))
    assert r["mfa"].status == "unknown"                 # CA unreadable without P1; registration fine
    r = run(FakeGraph(premium=True, security_defaults=False, ca_mfa_all=False, mfa_missing=()))
    assert r["mfa"].status == "fail" and "not enforced" in r["mfa"].summary


def test_too_many_or_too_few_global_admins(m365_env):
    many = ("a@example.com", "b@example.com", "c@example.com", "d@example.com", "e@example.com")
    r = run(FakeGraph(global_admins=many, mfa_missing=()))
    assert "5 Global Administrators" in r["privileged_accounts"].summary
    r = run(FakeGraph(global_admins=("admin@example.com",), mfa_missing=()))
    assert "only 1 Global Administrator" in r["privileged_accounts"].summary


def test_pagination_is_followed(m365_env):
    g = FakeGraph(page_users=True)
    r = run(g)
    assert "3/4 enabled accounts" in r["mfa"].summary
    assert g.calls.count("/users") >= 2


def test_bad_secret_gives_unknown(m365_env):
    r = run(FakeGraph(token_ok=False))
    assert all(x.status == "unknown" for x in r.values())
    assert "Sign-in to Entra ID failed" in r["mfa"].summary


def test_test_connection(m365_env):
    ok, msg = Microsoft365Collector(transport=httpx.MockTransport(FakeGraph()), now=NOW).test_connection()
    assert ok and "Example Ltd" in msg and "example.com" in msg


def test_results_reach_nis2_controls(m365_env):
    with LoggedInClient(app):
        result = evidence.run_collection("microsoft365", Microsoft365Collector(
            transport=httpx.MockTransport(FakeGraph()), now=NOW))
        assert result["ok"] and result["saved"] == 3
        latest = evidence.latest_by_control("nis2")
        for cid in ("nis2-j-01", "nis2-i-02", "nis2-i-03"):
            assert "microsoft365" in [p["source"] for p in latest[cid]["parts"]]
