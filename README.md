# 1cyber Comply

Open-source compliance automation for small and medium organisations.
Collects evidence automatically from your existing security tools and maps it to regulatory controls.

**Status:** early development (v0.3.1) — stage 2a, Wazuh collector.

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
| 2b | OPNsense collector: 7 automated checks | next |
| 3 | Evidence-to-control mapping, compliance score | planned |
| 4 | PDF reports, manual evidence upload | planned |
| 5 | Login, user accounts, HTTPS — required before exposing the app on a network | planned |
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

## Connecting Wazuh

Create a dedicated read-only API user (role `readonly`) and set in `.env`:

```
WAZUH_URL=https://host.docker.internal:55000
WAZUH_USER=comply
WAZUH_PASSWORD=...
```

Alerts and vulnerabilities live in the Wazuh Indexer (Wazuh 4.8+). Optionally add a
read-only indexer user with `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD`.

> Security note: until stage 5 the web UI has no login. Keep it bound to 127.0.0.1 (default).

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
