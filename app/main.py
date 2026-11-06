"""Punctul de intrare al aplicatiei 1cyber Comply."""
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app import config
from app.db import get_conn, init_db

templates = Jinja2Templates(directory=str(config.BASE_DIR / "app" / "templates"))


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()  # creeaza tabelele la primul start
    yield


app = FastAPI(title=config.APP_NAME, version=config.APP_VERSION, lifespan=lifespan)


def _stats() -> dict:
    with get_conn() as conn:
        return {
            "frameworks": conn.execute("SELECT COUNT(*) FROM frameworks").fetchone()[0],
            "controls": conn.execute("SELECT COUNT(*) FROM controls").fetchone()[0],
            "evidence": conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0],
        }


def _sources() -> dict:
    return {
        "wazuh": bool(config.WAZUH_URL and config.WAZUH_USER),
        "opnsense": bool(config.OPNSENSE_URL and config.OPNSENSE_KEY),
    }


@app.get("/health")
def health():
    """Folosit de Docker healthcheck si de monitorizare."""
    return {"status": "ok", "version": config.APP_VERSION}


@app.get("/api/status")
def status():
    return {"app": config.APP_NAME, "version": config.APP_VERSION,
            "stats": _stats(), "sources_configured": _sources()}


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {
        "app_name": config.APP_NAME, "version": config.APP_VERSION,
        "stats": _stats(), "sources": _sources(),
    })
