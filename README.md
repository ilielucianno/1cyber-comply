# 1cyber Comply

Open-source compliance automation for small and medium organisations.
Collects evidence automatically from your existing security tools and maps it to regulatory controls.

**Status:** early development (v0.1.0) — stage 0, project foundation.

## Why

Commercial compliance platforms cost five figures per year. NIS2 now requires thousands of
mid-sized EU organisations to prove their cybersecurity measures. 1cyber Comply aims to do this
for free, using tools many teams already run.

## Roadmap

| Stage | Scope | Status |
|---|---|---|
| 0 | Project foundation, database, web UI, Docker | done |
| 1 | NIS2 Art. 21 control catalogue (YAML) | next |
| 2 | Collectors: Wazuh API, OPNsense API | planned |
| 3 | Evidence-to-control mapping, compliance score | planned |
| 4 | PDF reports, manual evidence upload | planned |
| 5 | One-line installer, .deb package | planned |

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
