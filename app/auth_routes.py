"""Login, first-run setup, logout, own account, user management and audit log pages."""
import secrets
from urllib.parse import quote

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import auth, config
from app.guard import SESSION_COOKIE, client_ip

router = APIRouter()
templates = None   # set by app.main


def _ctx(request: Request, page: str, **extra) -> dict:
    return {"app_name": config.APP_NAME, "version": config.APP_VERSION, "page": page, **extra}


def _safe_next(target: str | None) -> str:
    return target if target and target.startswith("/") and not target.startswith("//") else "/"


def _redirect(url: str, ok: bool = True, msg: str = "") -> RedirectResponse:
    sep = "&" if "?" in url else "?"
    return RedirectResponse(f"{url}{sep}ok={int(ok)}&msg={quote(msg)}" if msg else url, status_code=303)


def _start_session(request: Request, user: dict, target: str) -> RedirectResponse:
    resp = RedirectResponse(target, status_code=303)
    resp.set_cookie(SESSION_COOKIE, auth.create_session(user["id"]), max_age=config.SESSION_HOURS * 3600,
                    httponly=True, samesite="strict", secure=request.url.scheme == "https", path="/")
    return resp


# ---------------------------------------------------------------- first run

@router.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request, msg: str | None = None):
    if auth.user_count() > 0:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "setup.html", _ctx(request, "setup", flash=msg, flash_ok=False))


@router.post("/setup")
def setup(request: Request, username: str = Form(...), password: str = Form(...), confirm: str = Form(...)):
    if auth.user_count() > 0:
        raise HTTPException(status_code=403, detail="Setup has already been completed")
    if password != confirm:
        return _redirect("/setup", False, "Passwords do not match.")
    try:
        uid = auth.create_user(username, password, "admin")
    except auth.AuthError as exc:
        return _redirect("/setup", False, str(exc))
    auth.audit("setup.admin_created", username, ip=client_ip(request))
    return _start_session(request, auth.get_user(uid), "/")


# ---------------------------------------------------------------- login / logout

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/", msg: str | None = None):
    if auth.user_count() == 0:
        return RedirectResponse("/setup", status_code=303)
    return templates.TemplateResponse(request, "login.html",
                                      _ctx(request, "login", next=_safe_next(next), flash=msg, flash_ok=False))


@router.post("/login")
def login(request: Request, username: str = Form(""), password: str = Form(""), next: str = Form("/")):
    try:
        user = auth.authenticate(username, password)
    except auth.AuthError as exc:
        auth.audit("login.failed", username[:64], str(exc), client_ip(request))
        return _redirect(f"/login?next={quote(_safe_next(next))}", False, str(exc))
    auth.audit("login.success", user["username"], ip=client_ip(request))
    return _start_session(request, user, _safe_next(next))


@router.post("/logout")
def logout(request: Request):
    auth.end_session(request.cookies.get(SESSION_COOKIE))
    auth.audit("logout", request.state.user["username"], ip=client_ip(request))
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


# ---------------------------------------------------------------- own account

@router.get("/account", response_class=HTMLResponse)
def account_page(request: Request, msg: str | None = None, ok: int = 1):
    return templates.TemplateResponse(request, "account.html",
                                      _ctx(request, "account", flash=msg, flash_ok=bool(ok)))


@router.post("/account/password")
def change_password(request: Request, current: str = Form(...), password: str = Form(...), confirm: str = Form(...)):
    me = request.state.user
    try:
        auth.authenticate(me["username"], current)
    except auth.AuthError:
        return _redirect("/account", False, "Current password is wrong.")
    if password != confirm:
        return _redirect("/account", False, "New passwords do not match.")
    if password == current:
        return _redirect("/account", False, "Choose a password different from the current one.")
    try:
        auth.set_password(me["id"], password)       # also ends all sessions of this user
    except auth.AuthError as exc:
        return _redirect("/account", False, str(exc))
    auth.audit("account.password_changed", me["username"], ip=client_ip(request))
    return _start_session(request, auth.get_user(me["id"]), "/?ok=1&msg=" + quote("Password changed."))


# ---------------------------------------------------------------- admin: users and audit

def _users_view(request: Request, msg: str | None = None, ok: bool = True, temp: str | None = None):
    # A temporary password is rendered directly in this response, never put in a URL,
    # so it does not end up in browser history or access logs.
    return templates.TemplateResponse(request, "users.html", _ctx(
        request, "users", users=auth.list_users(), roles=auth.ROLES, flash=msg, flash_ok=ok, temp=temp))


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request, msg: str | None = None, ok: int = 1):
    return _users_view(request, msg, bool(ok))


def _temp_password() -> str:
    return secrets.token_urlsafe(12)


@router.post("/users")
def create_user(request: Request, username: str = Form(...), role: str = Form(...)):
    temp = _temp_password()
    try:
        auth.create_user(username, temp, role, must_change=True)
    except auth.AuthError as exc:
        return _redirect("/users", False, str(exc))
    auth.audit("user.created", request.state.user["username"], f"{username} as {role}", client_ip(request))
    return _users_view(request, f"User {username} created. Give them the temporary password below; "
                                "it is shown only once.", True, f"{username}: {temp}")


@router.post("/users/{user_id}")
def update_user(request: Request, user_id: int, action: str = Form(...), role: str = Form("")):
    target = auth.get_user(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    me = request.state.user
    try:
        if action == "role":
            auth.update_user(user_id, role=role)
            detail = f"{target['username']} -> {role}"
        elif action in ("disable", "enable"):
            if action == "disable" and user_id == me["id"]:
                raise auth.AuthError("You cannot disable your own account.")
            auth.update_user(user_id, disabled=action == "disable")
            detail = target["username"]
        elif action == "reset":
            temp = _temp_password()
            auth.set_password(user_id, temp, must_change=True)
            auth.audit("user.password_reset", me["username"], target["username"], client_ip(request))
            return _users_view(request, "Password reset. The temporary password below is shown only once.",
                               True, f"{target['username']}: {temp}")
        else:
            raise auth.AuthError("Unknown action.")
    except auth.AuthError as exc:
        return _redirect("/users", False, str(exc))
    auth.audit(f"user.{action}", me["username"], detail, client_ip(request))
    return _redirect("/users", True, "Saved.")


@router.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request):
    return templates.TemplateResponse(request, "audit.html", _ctx(request, "audit", entries=auth.audit_entries()))
