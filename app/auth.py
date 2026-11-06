"""Users, password hashing, server-side sessions, login lockout and the audit log.

Standard library only:
- passwords: scrypt (memory-hard), random salt per user, constant-time comparison
- sessions: a random token in an HttpOnly cookie; only its SHA-256 is stored, so a
  copy of the database cannot be used to hijack sessions. Logout and disabling a
  user revoke sessions immediately.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from app import config
from app.db import get_conn

ROLES = ("admin", "editor", "viewer")
ROLE_RANK = {"viewer": 1, "editor": 2, "admin": 3}
MIN_PASSWORD_LENGTH = 12
_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}


class AuthError(ValueError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------- passwords

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, dklen=32, **_SCRYPT)
    return f"scrypt${_SCRYPT['n']}${_SCRYPT['r']}${_SCRYPT['p']}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, digest = stored.split("$")
        if algo != "scrypt":
            return False
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p),
                              dklen=len(bytes.fromhex(digest)))
        return hmac.compare_digest(calc.hex(), digest)
    except (ValueError, TypeError):
        return False


_DUMMY_HASH = hash_password(secrets.token_hex(16))


def check_password_policy(password: str, username: str = "") -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AuthError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    if username and username.lower() in password.lower():
        raise AuthError("Password must not contain the username.")
    classes = sum(any(f(c) for c in password) for f in (str.islower, str.isupper, str.isdigit))
    if classes < 2 and not any(not c.isalnum() for c in password):
        raise AuthError("Use a mix of letters, digits or symbols.")


# ---------------------------------------------------------------- audit

def audit(action: str, username: str | None = None, detail: str = "", ip: str | None = None) -> None:
    with get_conn() as conn:
        conn.execute("INSERT INTO audit_log (username, action, detail, ip) VALUES (?, ?, ?, ?)",
                     (username, action, detail[:500], ip))


def audit_entries(limit: int = 200) -> list[dict]:
    with get_conn() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]


# ---------------------------------------------------------------- users

def user_count() -> int:
    with get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


def list_users() -> list[dict]:
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT id, username, role, disabled, locked_until, created_at, last_login, must_change_password "
            "FROM users ORDER BY username")]


def get_user(user_id: int) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def create_user(username: str, password: str, role: str, must_change: bool = False) -> int:
    username = (username or "").strip()
    if not username or len(username) > 64 or not all(c.isalnum() or c in "._-@" for c in username):
        raise AuthError("Username may contain letters, digits and . _ - @ (max 64).")
    if role not in ROLES:
        raise AuthError("Unknown role.")
    check_password_policy(password, username)
    with get_conn() as conn:
        if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            raise AuthError("A user with this name already exists.")
        return conn.execute(
            "INSERT INTO users (username, password_hash, role, must_change_password) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), role, int(must_change))).lastrowid


def _admins_left(conn, excluding: int) -> int:
    return conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0 AND id != ?",
                        (excluding,)).fetchone()[0]


def update_user(user_id: int, role: str | None = None, disabled: bool | None = None) -> None:
    with get_conn() as conn:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            raise AuthError("User not found.")
        demoting = (role is not None and role != "admin") or disabled
        if user["role"] == "admin" and demoting and _admins_left(conn, user_id) == 0:
            raise AuthError("At least one active admin must remain.")
        if role is not None:
            if role not in ROLES:
                raise AuthError("Unknown role.")
            conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        if disabled is not None:
            conn.execute("UPDATE users SET disabled = ? WHERE id = ?", (int(disabled), user_id))
            if disabled:
                conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


def set_password(user_id: int, password: str, must_change: bool = False) -> None:
    user = get_user(user_id)
    if not user:
        raise AuthError("User not found.")
    check_password_policy(password, user["username"])
    with get_conn() as conn:
        conn.execute("""UPDATE users SET password_hash = ?, must_change_password = ?, failed_attempts = 0,
                        locked_until = NULL WHERE id = ?""", (hash_password(password), int(must_change), user_id))
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


# ---------------------------------------------------------------- login / sessions

def authenticate(username: str, password: str) -> dict:
    """Return the user or raise AuthError. Same message for unknown user and wrong password."""
    with get_conn() as conn:
        user = conn.execute("SELECT * FROM users WHERE username = ?", ((username or "").strip(),)).fetchone()
    if not user:
        verify_password(password, _DUMMY_HASH)          # keep timing similar for unknown users
        raise AuthError("Invalid username or password.")
    if user["locked_until"] and user["locked_until"] > _ts(_now()):
        raise AuthError("Account temporarily locked after too many failed attempts. Try again later.")
    if not verify_password(password, user["password_hash"]):
        attempts = user["failed_attempts"] + 1
        locked = (_ts(_now() + timedelta(minutes=config.LOGIN_LOCK_MINUTES))
                  if attempts >= config.LOGIN_MAX_ATTEMPTS else None)
        with get_conn() as conn:
            conn.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                         (0 if locked else attempts, locked, user["id"]))
        raise AuthError("Invalid username or password.")
    if user["disabled"]:
        raise AuthError("Invalid username or password.")
    with get_conn() as conn:
        conn.execute("""UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = datetime('now')
                        WHERE id = ?""", (user["id"],))
    return dict(user)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    expires = _ts(_now() + timedelta(hours=config.SESSION_HOURS))
    with get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < datetime('now')")
        conn.execute("INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)",
                      (_token_hash(token), user_id, secrets.token_urlsafe(32), expires))
    return token


def session_user(token: str | None) -> dict | None:
    """The logged-in user plus the session's CSRF token, or None."""
    if not token:
        return None
    with get_conn() as conn:
        row = conn.execute(
            """SELECT u.id, u.username, u.role, u.must_change_password, s.csrf_token
               FROM sessions s JOIN users u ON u.id = s.user_id
               WHERE s.token_hash = ? AND s.expires_at > datetime('now') AND u.disabled = 0""",
            (_token_hash(token),)).fetchone()
    return dict(row) if row else None


def end_session(token: str | None) -> None:
    if token:
        with get_conn() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))


def has_role(user: dict | None, required: str) -> bool:
    return bool(user) and ROLE_RANK.get(user["role"], 0) >= ROLE_RANK[required]
