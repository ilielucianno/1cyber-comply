"""Punctul de intrare al aplicatiei 1cyber Comply."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app import catalog, config
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
    return {"framework": fw, "categories": catalog.controls_by_category(framework_id)}


# ---------- UI ----------

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {
        "app_name": config.APP_NAME, "version": config.APP_VERSION, "page": "home",
        "stats": _stats(), "sources": _sources(), "frameworks": _frameworks(),
    })


@app.get("/controls", response_class=HTMLResponse)
@app.get("/controls/{framework_id}", response_class=HTMLResponse)
def controls_page(request: Request, framework_id: str = "nis2"):
    fw = _framework(framework_id)
    return templates.TemplateResponse(request, "controls.html", {
        "app_name": config.APP_NAME, "version": config.APP_VERSION, "page": "controls",
        "framework": fw, "categories": catalog.controls_by_category(framework_id),
    })
