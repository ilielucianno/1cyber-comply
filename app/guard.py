"""Access control applied to every request: login, roles and CSRF.

Roles:
  viewer -> read everything, download reports and files
  editor -> viewer + add evidence, run collections
  admin  -> editor + test connections, manage users, read the audit log

CSRF: every state-changing request must carry the session's token, either in the
form field `csrf_token` or the `X-CSRF-Token` header. Cookies are also SameSite=Strict.
"""
import hmac
import re
from urllib.parse import quote

from fastapi import HTTPException, Request

from app import auth

SESSION_COOKIE = "comply_session"
PUBLIC_PATHS = {"/health", "/login", "/setup"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
ADMIN_PATTERNS = [re.compile(p) for p in (r"^/users", r"^/audit", r"^(/api)?/sources/[^/]+/test$")]


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _deny(request: Request, status: int, detail: str):
    if request.url.path.startswith("/api/") or request.method not in SAFE_METHODS:
        raise HTTPException(status_code=status, detail=detail)
    if status == 401:
        target = "/setup" if auth.user_count() == 0 else f"/login?next={quote(request.url.path)}"
        raise HTTPException(status_code=303, headers={"Location": target})
    raise HTTPException(status_code=status, detail=detail)


async def guard(request: Request) -> None:
    request.state.user = None
    request.state.csrf = ""
    path = request.url.path
    if path in PUBLIC_PATHS:
        return

    user = auth.session_user(request.cookies.get(SESSION_COOKIE))
    if not user:
        _deny(request, 401, "Login required")
    request.state.user = user
    request.state.csrf = user["csrf_token"]

    if user["must_change_password"] and path not in ("/account", "/account/password", "/logout"):
        if path.startswith("/api/") or request.method not in SAFE_METHODS:
            raise HTTPException(status_code=403, detail="Password change required")
        raise HTTPException(status_code=303, headers={
            "Location": "/account?ok=0&msg=" + quote("Please set a new password first.")})

    if request.method not in SAFE_METHODS:
        sent = request.headers.get("x-csrf-token", "")
        if not sent:
            ctype = request.headers.get("content-type", "")
            if ctype.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
                sent = str((await request.form()).get("csrf_token", ""))
        if not sent or not hmac.compare_digest(sent, user["csrf_token"]):
            raise HTTPException(status_code=403, detail="Invalid or missing CSRF token")

    needed = "viewer"
    if any(p.search(path) for p in ADMIN_PATTERNS):
        needed = "admin"
    elif request.method not in SAFE_METHODS:
        needed = "editor"
    if not auth.has_role(user, needed):
        raise HTTPException(status_code=403, detail=f"This action requires the {needed} role")
