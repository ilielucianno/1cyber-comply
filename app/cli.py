"""Command line administration, for when nobody can log in.

    docker exec -it 1cyber-comply python -m app.cli list-users
    docker exec -it 1cyber-comply python -m app.cli reset-password <username>
    docker exec -it 1cyber-comply python -m app.cli create-admin <username>
"""
import argparse
import secrets
import sys

from app import auth
from app.db import get_conn, init_db


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list-users")
    for name in ("reset-password", "create-admin"):
        sub.add_parser(name).add_argument("username")
    args = parser.parse_args(argv)
    init_db()

    if args.cmd == "list-users":
        for u in auth.list_users():
            state = "disabled" if u["disabled"] else "active"
            print(f"{u['username']:<24} {u['role']:<8} {state:<9} last login: {u['last_login'] or 'never'}")
        return 0

    temp = secrets.token_urlsafe(12)
    if args.cmd == "create-admin":
        try:
            auth.create_user(args.username, temp, "admin", must_change=True)
        except auth.AuthError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        auth.audit("cli.admin_created", "cli", args.username)
    else:
        with get_conn() as conn:
            row = conn.execute("SELECT id FROM users WHERE username = ?", (args.username,)).fetchone()
        if not row:
            print(f"Error: no user named {args.username}", file=sys.stderr)
            return 1
        auth.set_password(row["id"], temp, must_change=True)
        auth.update_user(row["id"], disabled=False)
        auth.audit("cli.password_reset", "cli", args.username)
    print(f"Temporary password for {args.username}: {temp}")
    print("It must be changed at the first login.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
