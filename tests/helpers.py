"""Test client that is logged in and sends the CSRF token on every state-changing request."""
from fastapi.testclient import TestClient

from app import auth
from app.db import get_conn
from app.guard import SESSION_COOKIE

PASSWORD = "Test-Password-123"


def ensure_user(username: str, role: str) -> None:
    with get_conn() as conn:
        row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if row:
        auth.set_password(row["id"], PASSWORD)
        auth.update_user(row["id"], role=role, disabled=False)
    else:
        auth.create_user(username, PASSWORD, role)


class LoggedInClient(TestClient):
    def __init__(self, app, role: str = "admin", **kwargs):
        super().__init__(app, **kwargs)
        self.role = role
        self.csrf = None

    def __enter__(self):
        super().__enter__()
        username = f"test-{self.role}"
        ensure_user(username, self.role)
        r = self.post("/login", data={"username": username, "password": PASSWORD}, follow_redirects=False)
        assert r.status_code == 303, r.text
        self.csrf = auth.session_user(self.cookies.get(SESSION_COOKIE))["csrf_token"]
        return self

    def request(self, method, url, **kwargs):
        if self.csrf and method.upper() not in ("GET", "HEAD", "OPTIONS"):
            headers = dict(kwargs.pop("headers", None) or {})
            headers.setdefault("X-CSRF-Token", self.csrf)
            kwargs["headers"] = headers
        return super().request(method, url, **kwargs)
