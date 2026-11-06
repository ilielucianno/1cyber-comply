# Security policy

1cyber Comply holds sensitive information about an organisation's security posture, so
security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub:
**Security → Report a vulnerability** on this repository
(https://github.com/ilielucianno/1cyber-comply/security/advisories/new).

Include the version, how to reproduce it and the impact you expect. You will get an
acknowledgement within 5 working days. Fixes are released as soon as practical and credited
to the reporter unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes. Upgrade by running the installer again or
installing the newest `.deb`.

## Design principles

- **Read-only towards your systems.** Collectors only read; credentials should be dedicated,
  least-privilege accounts (see the README).
- **Secrets stay in `.env`** (mode 600), never in the database, logs or reports.
- **Defence in depth in the web app:** login on every page, role checks, CSRF tokens,
  SameSite=Strict cookies, strict Content-Security-Policy, scrypt password hashes,
  server-side sessions, lockout, audit log.
- **Uploaded files are untrusted:** random names on disk, extension allow-list, size limit,
  always served as downloads with `nosniff`.
- **Container runs as an unprivileged user**; the UI binds to `127.0.0.1` unless you choose
  otherwise.

## Hardening your installation

- Keep `COMPLY_TLS=true` and replace the self-signed certificate with your own when the app is
  reachable from the network.
- Restrict network access to the port with your firewall.
- Use separate accounts per person; give auditors and management the `viewer` role.
- Back up the `1cyber-comply_comply-data` Docker volume.
