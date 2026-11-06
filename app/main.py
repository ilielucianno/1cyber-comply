"""Punctul de intrare al aplicatiei 1cyber Comply."""
import logging
from contextlib import asynccontextmanager

from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app import catalog, config, evidence
from app.db import get_conn, init_db

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
templates = Jinja2Templates(directory=str(config.BASE_DIR / "app" / "templates"))


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()            # creeaza / actualizeaza tabelele
    catalog.load_all()   # incarca controalele din controls/*.yaml
    yield


app = FastAPI(title=config.APP_NAME, version=config.APP_VERSION, lifespan=lifespan)


def _stats() -> dict:
    with get_conn() as conn:
        one = lambda sql: conn.execute(sql).fetchone()[0]  # noqa: E731
        return {
            "frameworks": one("SELECT COUNT(*) FROM frameworks"),
            "controls": one("SELECT COUNT(*) FROM controls"),
            "automated": one("SELECT COUNT(*) FROM controls WHERE check_type='automated'"),
            "manual": one("SELECT COUNT(*) FROM controls WHERE check_type='manual'"),
            "evidence": one("SELECT COUNT(*) FROM evidence"),
        }


def _sources() -> dict:
    return {
        "wazuh": bool(config.WAZUH_URL and config.WAZUH_USER),
        "opnsense": bool(config.OPNSENSE_URL and config.OPNSENSE_KEY),
    }


def _collector(source: str):
    collectors = evidence.get_collectors()
    if source not in collectors:
        raise HTTPException(status_code=404, detail=f"Sursa '{source}' nu are colector inca")
    return collectors[source]


def _frameworks() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT f.*, COUNT(c.id) AS control_count FROM frameworks f
               LEFT JOIN controls c ON c.framework_id = f.id GROUP BY f.id ORDER BY f.name"""
        ).fetchall()
    return [dict(r) for r in rows]


def _framework(framework_id: str) -> dict:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM frameworks WHERE id = ?", (framework_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Framework '{framework_id}' nu exista")
    return dict(row)


# ---------- API ----------

@app.get("/health")
def health():
    """Folosit de Docker healthcheck si de monitorizare."""
    return {"status": "ok", "version": config.APP_VERSION}


@app.get("/api/status")
def status():
    return {"app": config.APP_NAME, "version": config.APP_VERSION,
            "stats": _stats(), "sources_configured": _sources()}


@app.get("/api/frameworks")
def api_frameworks():
    return _frameworks()


@app.get("/api/frameworks/{framework_id}/controls")
def api_controls(framework_id: str):
    fw = _framework(framework_id)
    latest = evidence.latest_by_control(framework_id)
    cats = catalog.controls_by_category(framework_id)
    for cat in cats:
        for c in cat["controls"]:
            e = latest.get(c["id"])
            c["latest_evidence"] = ({k: e[k] for k in ("status", "summary", "source", "collected_at")}
                                   if e else None)
    return {"framework": fw, "status_counts": evidence.status_counts(framework_id), "categories": cats}


@app.post("/api/sources/{source}/test")
def api_test_source(source: str):
    ok, message = _collector(source).test_connection()
    return {"ok": ok, "message": message}


@app.post("/api/sources/{source}/collect")
def api_collect(source: str):
    return evidence.run_collection(source, _collector(source))


# Formulare din UI: ruleaza actiunea si revin pe dashboard cu mesajul rezultatului

@app.post("/sources/{source}/test")
def ui_test_source(source: str):
    ok, message = _collector(source).test_connection()
    return RedirectResponse(f"/?ok={int(ok)}&msg={quote(f'{source}: {message}')}", status_code=303)


@app.post("/sources/{source}/collect")
def ui_collect(source: str):
    result = evidence.run_collection(source, _collector(source))
    return RedirectResponse(f"/?ok={int(result['ok'])}&msg={quote(f'{source}: ' + result['message'])}",
                            status_code=303)


# ---------- UI ----------

@app.get("/", response_class=HTMLResponse)
def index(request: Request, msg: str | None = None, ok: int = 1):
    frameworks = _frameworks()
    for fw in frameworks:
        fw["status_counts"] = evidence.status_counts(fw["id"])
    return templates.TemplateResponse(request, "index.html", {
        "app_name": config.APP_NAME, "version": config.APP_VERSION, "page": "home",
        "stats": _stats(), "sources": _sources(), "frameworks": frameworks,
        "collectors": evidence.get_collectors(), "runs": evidence.last_runs(),
        "flash": msg, "flash_ok": bool(ok),
    })


@app.get("/controls", response_class=HTMLResponse)
@app.get("/controls/{framework_id}", response_class=HTMLResponse)
def controls_page(request: Request, framework_id: str = "nis2"):
    fw = _framework(framework_id)
    return templates.TemplateResponse(request, "controls.html", {
        "app_name": config.APP_NAME, "version": config.APP_VERSION, "page": "controls",
        "framework": fw, "categories": catalog.controls_by_category(framework_id),
        "latest": evidence.latest_by_control(framework_id),
        "counts": evidence.status_counts(framework_id),
    })
