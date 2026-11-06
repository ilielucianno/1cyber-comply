# 1cyber Comply

Open-source compliance automation for small and medium organisations.
Collects evidence automatically from your existing security tools and maps it to regulatory controls.

**Status:** early development (v0.6.0) — stage 4, manual evidence and PDF reports.

## Why

Commercial compliance platforms cost five figures per year. NIS2 now requires thousands of
mid-sized EU organisations to prove their cybersecurity measures. 1cyber Comply aims to do this
for free, using tools many teams already run.

## Roadmap

| Stage | Scope | Status |
|---|---|---|
| 0 | Project foundation, database, web UI, Docker | done |
| 1 | NIS2 Art. 21 control catalogue (41 controls) | done |
| 2a | Wazuh collector (Server API + Indexer): 7 automated checks | done |
| 2b | OPNsense collector: 6 automated checks | done |
| 3 | Scheduled collection, compliance score and history | done |
| 4 | Manual evidence upload, PDF reports | done |
| 5 | Login, user accounts, HTTPS — required before exposing the app on a network | next |
| 6 | One-line installer, .deb package | planned |

## Quick start (Docker)

```bash
git clone https://github.com/ilielucianno/1cyber-comply.git
cd 1cyber-comply
./install.sh
```

Open http://127.0.0.1:8080

## Development (without Docker)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt pytest
pytest -q
uvicorn app.main:app --reload --port 8080
```

## Compliance score

The score is the share of a framework's controls with **passing** evidence. Failed, unknown
and not-yet-evidenced controls all count as not passing, so the score never claims more
than has been proven. The dashboard shows the overall score, the automated-controls score
and a history chart; a snapshot is stored after every collection.

Collection runs automatically every `COLLECT_INTERVAL_HOURS` (default 24, `0` disables it).
The internal check `nis2-f-03` passes only while automatic collection keeps running.

## Manual evidence and reports

Open any manual control and add evidence: a pass/fail assessment, a note, the reviewer's
name, a validity date (default one year) and optionally a file (PDF, images, Office/ODF
documents, text; max 10 MB). Expired evidence automatically counts as failed, so annual
reviews cannot be silently skipped. Every piece of evidence is kept as an audit trail.

Uploaded files are stored under random names and only ever served as downloads, never
rendered in the browser. Their SHA-256 hash is listed in the report.

**PDF report:** *Download PDF report* on the dashboard or controls page. It contains the
score and history, findings to address, every control with its current evidence, an
appendix of evidence files with hashes, and a statement that it supports but does not
replace an assessment by the authority or an accredited auditor. Set `ORG_NAME` in `.env`.

## Connecting Wazuh

Create a dedicated read-only API user (role `readonly`) and set in `.env`:

```
WAZUH_URL=https://host.docker.internal:55000
WAZUH_USER=comply
WAZUH_PASSWORD=...
```

Alerts and vulnerabilities live in the Wazuh Indexer (Wazuh 4.8+). Optionally add a
read-only indexer user with `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD`.

**Wazuh on the same machine (all-in-one install).** The Wazuh Indexer usually listens only on
`127.0.0.1`, which a container cannot reach. Enable host-network mode by adding to `.env`:

```
COMPOSE_FILE=docker-compose.yml:docker-compose.hostnet.yml
WAZUH_URL=https://127.0.0.1:55000
WAZUH_INDEXER_URL=https://127.0.0.1:9200
```

The web UI still listens on 127.0.0.1 only.

> Security note: until stage 5 the web UI has no login. Keep it bound to 127.0.0.1 (default).

## Connecting OPNsense

OPNsense has no read-only API role, so 1cyber Comply only sends GET requests and needs the
smallest privilege set possible. Create a user **without** group membership, assign only:

| Privilege | Used for |
|---|---|
| Lobby: Dashboard | installed version (firmware check) |
| Diagnostics: Firewall Statistics | active pf ruleset, works for legacy and new rules |
| Firewall: Rules New | optional, rules created in the new rule engine |
| Services: Intrusion Detection | IDS/IPS enabled and running |
| VPN: WireGuard (Configuration, Status) | remote access VPN |
| Interfaces: VLAN | network segmentation |

Do **not** grant `System: Firmware`, `Diagnostics: Backup & Restore` or
`Diagnostics: Configuration History`: they allow updates, full config download or restore.
Firmware currency is checked by comparing the installed version with the latest public
OPNsense release on GitHub (disable with `OPNSENSE_CHECK_LATEST=false` on offline networks).
Create the API key from System > Access > Users and set `OPNSENSE_URL`, `OPNSENSE_KEY`,
`OPNSENSE_SECRET` in `.env`.

## Architecture

```
app/
  main.py          FastAPI app, routes
  config.py        settings from environment (.env)
  db.py            SQLite schema: frameworks, controls, evidence
  collectors/      one module per data source (Wazuh, OPNsense, ...)
  templates/       web UI
controls/          control catalogues (YAML), one file per framework
tests/
```

## Licence

Apache License 2.0
