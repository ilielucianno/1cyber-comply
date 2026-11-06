"""Authentication, roles, CSRF, lockout, sessions, user management, audit log and CLI."""
import re

import pytest
from fastapi.testclient import TestClient
from helpers import PASSWORD, LoggedInClient, ensure_user

from app import auth, cli, config, db
from app.db import get_conn
from app.guard import SESSION_COOKIE
from app.main import app


def test_password_hashing():
    h = auth.hash_password("Correct-Horse-9")
    assert h.startswith("scrypt$") and "Correct-Horse-9" not in h
    assert auth.verify_password("Correct-Horse-9", h)
    assert not auth.verify_password("wrong", h)
    assert auth.hash_password("Correct-Horse-9") != h            # random salt
    assert not auth.verify_password("x", "garbage")


@pytest.mark.parametrize("pw", ["short1A", "alllowercaseletters", "contains-admin-123"])
def test_password_policy(pw):
    with pytest.raises(auth.AuthError):
        auth.check_password_policy(pw, "admin")


def test_first_run_setup_on_empty_database(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "fresh.db")
    with TestClient(app) as c:
        assert c.get("/", follow_redirects=False).headers["location"] == "/setup"
        assert c.get("/login", follow_redirects=False).headers["location"] == "/setup"
        r = c.post("/setup", data={"username": "boss", "password": "Very-Secret-Pass-1",
                                   "confirm": "Very-Secret-Pass-1"}, follow_redirects=False)
        assert r.status_code == 303 and SESSION_COOKIE in r.cookies
        assert c.get("/").status_code == 200
        # setup is closed once an account exists
        assert c.post("/setup", data={"username": "x", "password": "Another-Pass-12",
                                      "confirm": "Another-Pass-12"}).status_code == 403
        assert auth.list_users()[0]["role"] == "admin"


def test_anonymous_access_is_blocked():
    with LoggedInClient(app):                     # ensures at least one user exists
        pass
    with TestClient(app) as c:
        r = c.get("/controls", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/login?next=")
        assert c.get("/api/status").status_code == 401
        assert c.get("/reports/nis2.pdf", follow_redirects=False).status_code == 303
        assert c.post("/collect-all").status_code == 401
        assert c.get("/health").status_code == 200          # stays public for Docker
        assert c.get("/docs").status_code in (303, 404)     # API docs not exposed


def test_session_cookie_flags():
    ensure_user("cookie-user", "viewer")
    with TestClient(app) as c:
        r = c.post("/login", data={"username": "cookie-user", "password": PASSWORD}, follow_redirects=False)
        cookie = r.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=strict" in cookie


def test_wrong_password_and_lockout(monkeypatch):
    monkeypatch.setattr(config, "LOGIN_MAX_ATTEMPTS", 3)
    ensure_user("victim", "viewer")
    with TestClient(app) as c:
        for _ in range(3):
            r = c.post("/login", data={"username": "victim", "password": "nope"}, follow_redirects=False)
            assert "Invalid%20username%20or%20password" in r.headers["location"]
        r = c.post("/login", data={"username": "victim", "password": PASSWORD}, follow_redirects=False)
        assert "locked" in r.headers["location"]                # even the right password is refused
    ensure_user("victim", "viewer")                             # admin reset unlocks


def test_unknown_user_gets_same_message():
    with TestClient(app) as c:
        r = c.post("/login", data={"username": "nobody-here", "password": "x"}, follow_redirects=False)
        assert "Invalid%20username%20or%20password" in r.headers["location"]


def test_open_redirect_is_prevented():
    ensure_user("redir", "viewer")
    with TestClient(app) as c:
        r = c.post("/login", data={"username": "redir", "password": PASSWORD, "next": "//evil.example"},
                   follow_redirects=False)
        assert r.headers["location"] == "/"


def test_csrf_required_for_state_changes():
    with LoggedInClient(app) as c:
        token = c.csrf
        c.csrf = None                                           # stop auto-sending the token
        assert c.post("/collect-all").status_code == 403
        assert c.post("/collect-all", headers={"X-CSRF-Token": "forged"}).status_code == 403
        assert c.post("/collect-all", data={"csrf_token": token}, follow_redirects=False).status_code == 303


def test_viewer_is_read_only():
    with LoggedInClient(app, role="viewer") as c:
        assert c.get("/").status_code == 200
        assert c.get("/controls/nis2/nis2-a-01").status_code == 200
        assert c.get("/reports/nis2.pdf").status_code == 200
        assert c.post("/collect-all").status_code == 403
        assert c.post("/controls/nis2/nis2-a-01/evidence", data={"status": "pass", "note": "x"}).status_code == 403
        assert c.get("/users").status_code == 403
        assert "Save evidence" not in c.get("/controls/nis2/nis2-a-01").text


def test_editor_can_add_evidence_but_not_manage_users():
    with LoggedInClient(app, role="editor") as c:
        r = c.post("/controls/nis2/nis2-a-01/evidence", data={"status": "pass", "note": "policy"},
                   follow_redirects=False)
        assert "ok=1" in r.headers["location"]
        assert c.get("/users").status_code == 403
        assert c.get("/audit").status_code == 403
        assert c.post("/api/sources/wazuh/test").status_code == 403


def test_admin_user_management_and_temp_password():
    with LoggedInClient(app) as c:
        r = c.post("/users", data={"username": "newbie", "role": "editor"})
        assert r.status_code == 200 and "Temporary password" in r.text
        temp = re.search(r"newbie: ([A-Za-z0-9_-]+)", r.text).group(1)
        uid = next(u["id"] for u in auth.list_users() if u["username"] == "newbie")
        assert c.post(f"/users/{uid}", data={"action": "role", "role": "viewer"}).status_code == 200
        audit_page = c.get("/audit").text
        assert "user.created" in audit_page and "user.role" in audit_page
    # the new user must change the temporary password first
    with TestClient(app) as n:
        n.post("/login", data={"username": "newbie", "password": temp})
        r = n.get("/controls", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/account")


def test_disabling_user_ends_sessions():
    with LoggedInClient(app, role="viewer") as viewer:
        assert viewer.get("/").status_code == 200
        uid = next(u["id"] for u in auth.list_users() if u["username"] == "test-viewer")
        auth.update_user(uid, disabled=True)
        assert viewer.get("/", follow_redirects=False).status_code == 303
    auth.update_user(uid, disabled=False)


def test_last_admin_cannot_be_removed():
    with LoggedInClient(app):
        pass
    with get_conn() as conn:
        admins = [r["id"] for r in conn.execute("SELECT id FROM users WHERE role='admin' AND disabled=0")]
    for extra in admins[1:]:
        auth.update_user(extra, role="viewer")
    with pytest.raises(auth.AuthError, match="admin"):
        auth.update_user(admins[0], disabled=True)
    for extra in admins[1:]:
        auth.update_user(extra, role="admin")


def test_logout_revokes_session():
    with LoggedInClient(app) as c:
        cookie = c.cookies.get(SESSION_COOKIE)
        assert c.post("/logout", follow_redirects=False).status_code == 303
        assert auth.session_user(cookie) is None


def test_change_own_password():
    with LoggedInClient(app, role="editor") as c:
        r = c.post("/account/password", data={"current": PASSWORD, "password": "Brand-New-Pass-77",
                                              "confirm": "Brand-New-Pass-77"}, follow_redirects=False)
        assert r.status_code == 303 and "Password%20changed" in r.headers["location"]
        assert auth.authenticate("test-editor", "Brand-New-Pass-77")


def test_security_headers():
    with LoggedInClient(app) as c:
        h = c.get("/").headers
        assert h["x-frame-options"] == "DENY" and "frame-ancestors 'none'" in h["content-security-policy"]


def test_cli_reset_password(capsys):
    ensure_user("forgetful", "admin")
    assert cli.main(["reset-password", "forgetful"]) == 0
    temp = capsys.readouterr().out.split(": ")[1].split()[0]
    assert auth.authenticate("forgetful", temp)["must_change_password"] == 1
    assert cli.main(["reset-password", "does-not-exist"]) == 1
