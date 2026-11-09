"""1cyber Comply application entry point."""
import logging
from contextlib import asynccontextmanager

from urllib.parse import quote

from datetime import date, timedelta

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from app import auth, auth_routes, catalog, config, evidence, manual, maturity, report, scoring
from app.guard import client_ip, guard
from app.scheduler import run_all, scheduler
from app.db import get_conn, init_db

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
templates = Jinja2Templates(directory=str(config.BASE_DIR / "app" / "templates"))


def _filesize(n: int) -> str:
    for unit in ("B", "KB", "MB"):
        if n < 1024 or unit == "MB":
            return f"{n} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} MB"


def _number(x: float) -> str:
    return f"{x:g}"


templates.env.filters["filesize"] = _filesize
templates.env.filters["number"] = _number
templates.env.globals["source_label"] = evidence.SOURCE_LABELS


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()            # create / migrate tables
    catalog.load_all()   # load controls from controls/*.yaml
    maturity.load_all()  # load maturity models from controls/maturity/*.yaml
    scheduler.start()    # automatic collection (if COLLECT_INTERVAL_HOURS > 0)
    yield
    scheduler.stop()


app = FastAPI(title=config.APP_NAME, version=config.APP_VERSION, lifespan=lifespan,
              dependencies=[Depends(guard)], docs_url=None, redoc_url=None, openapi_url=None)
auth_routes.templates = templates
app.include_router(auth_routes.router)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                                "frame-ancestors 'none'; form-action 'self'")
    if request.url.scheme == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return response


def _who(request: Request) -> str:
    return request.state.user["username"] if getattr(request.state, "user", None) else "system"


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
        "microsoft365": bool(config.M365_TENANT_ID and config.M365_CLIENT_ID),
    }


def _collector(source: str):
    collectors = evidence.get_collectors()
    if source not in collectors:
        raise HTTPException(status_code=404, detail=f"Source '{source}' has no collector yet")
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
        raise HTTPException(status_code=404, detail=f"Framework '{framework_id}' does not exist")
    return dict(row)


# ---------- API ----------

@app.get("/health")
def health():
    """Used by the Docker healthcheck and monitoring."""
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


@app.get("/api/frameworks/{framework_id}/score")
def api_score(framework_id: str):
    _framework(framework_id)
    return {**scoring.compute(framework_id), "history": scoring.history(framework_id)}


# ---------- Maturity model API ----------

def _maturity(framework_id: str) -> maturity.Catalogue:
    cat = maturity.get(framework_id)
    if not cat:
        raise HTTPException(status_code=404, detail=f"Maturity framework '{framework_id}' does not exist")
    return cat


@app.get("/api/maturity")
def api_maturity_list():
    return [{"id": c.id, "name": c.name, "authority": c.authority, "reference": c.reference,
             "target_level": c.target_level, "measures": len(c.measures),
             "requirements": c.requirement_count} for c in maturity.catalogues()]


@app.get("/api/maturity/{framework_id}")
def api_maturity_score(framework_id: str):
    _maturity(framework_id)
    return {**maturity.compute(framework_id), "history": maturity.history(framework_id)}


@app.get("/api/maturity/{framework_id}/measures/{measure_id}")
def api_maturity_measure(framework_id: str, measure_id: str):
    cat = _maturity(framework_id)
    m = cat.measure(measure_id)
    if not m:
        raise HTTPException(status_code=404, detail=f"Measure '{measure_id}' does not exist")
    answers = maturity.latest_answers(framework_id)
    score = maturity.score_measure(m, answers, cat.target_level)
    return {**score, "objective": m.objective, "description": m.description, "source": m.source,
            "page": m.page, "level0": m.level0,
            "requirements": [maturity.req_view(r, answers.get((m.id, r.id))) for r in m.requirements],
            "history": maturity.answer_history(framework_id, measure_id)}


@app.post("/api/maturity/{framework_id}/answers")
async def api_maturity_answer(request: Request, framework_id: str):
    """Body: {"measure_id", "requirement_id", "answer": met|not_met|na, "note"} or a list of them."""
    _maturity(framework_id)
    body = await request.json()
    items = body if isinstance(body, list) else [body]
    if not items or len(items) > 500 or not all(isinstance(i, dict) for i in items):
        raise HTTPException(status_code=400, detail="Send one answer object or a list of up to 500")
    who = _who(request)
    for i in items:     # validate everything first, so a bad item saves nothing
        m = maturity.get(framework_id).measure(str(i.get("measure_id", "")))
        if not m or not m.requirement(str(i.get("requirement_id", ""))):
            raise HTTPException(status_code=400, detail=f"Unknown measure/requirement in {i}")
        if i.get("answer") not in maturity.ANSWERS:
            raise HTTPException(status_code=400, detail=f"answer must be one of {', '.join(maturity.ANSWERS)}")
        if i["answer"] == "na" and not str(i.get("note") or "").strip():
            raise HTTPException(status_code=400, detail="A justification (note) is required for na")
    ids = [maturity.save_answer(framework_id, str(i["measure_id"]), str(i["requirement_id"]), i["answer"],
                                str(i.get("note") or ""), who) for i in items]
    auth.audit("maturity.answer", who, f"{framework_id}: {len(ids)} answer(s)", client_ip(request))
    s = maturity.snapshot(framework_id)
    return {"saved": len(ids), "mature": s["mature"], "measures_at_target": s["measures_at_target"],
            "measures_total": s["measures_total"]}


@app.get("/api/schedule")
def api_schedule():
    fmt = lambda d: d.strftime("%Y-%m-%d %H:%M UTC") if d else None  # noqa: E731
    return {"enabled": scheduler.enabled, "interval_hours": config.COLLECT_INTERVAL_HOURS,
            "next_run": fmt(scheduler.next_run), "last_run": fmt(scheduler.last_run)}


@app.post("/api/collect-all")
def api_collect_all(request: Request):
    auth.audit("collect.all", _who(request), ip=client_ip(request))
    return run_all()


@app.post("/api/sources/{source}/test")
def api_test_source(source: str):
    ok, message = _collector(source).test_connection()
    return {"ok": ok, "message": message}


@app.post("/api/sources/{source}/collect")
def api_collect(request: Request, source: str):
    auth.audit("collect.source", _who(request), source, client_ip(request))
    return evidence.run_collection(source, _collector(source))


# UI forms: run the action, then return to the dashboard with the result message

@app.post("/sources/{source}/test")
def ui_test_source(source: str):
    ok, message = _collector(source).test_connection()
    return RedirectResponse(f"/?ok={int(ok)}&msg={quote(f'{source}: {message}')}", status_code=303)


@app.post("/sources/{source}/collect")
def ui_collect(request: Request, source: str):
    auth.audit("collect.source", _who(request), source, client_ip(request))
    result = evidence.run_collection(source, _collector(source))
    return RedirectResponse(f"/?ok={int(result['ok'])}&msg={quote(f'{source}: ' + result['message'])}",
                            status_code=303)


@app.post("/collect-all")
def ui_collect_all(request: Request):
    auth.audit("collect.all", _who(request), ip=client_ip(request))
    results = run_all()
    ok = all(r["ok"] for r in results.values()) if results else False
    msg = "; ".join(f"{k}: {v['message']}" for k, v in results.items() if k != "comply") or "No sources configured"
    return RedirectResponse(f"/?ok={int(ok)}&msg={quote(msg)}", status_code=303)


# ---------- UI ----------

@app.get("/", response_class=HTMLResponse)
def index(request: Request, msg: str | None = None, ok: int = 1):
    frameworks = _frameworks()
    for fw in frameworks:
        fw["status_counts"] = evidence.status_counts(fw["id"])
        fw["score"] = scoring.compute(fw["id"])
        fw["chart"] = scoring.chart_svg(scoring.history(fw["id"]))
    return templates.TemplateResponse(request, "index.html", {
        "app_name": config.APP_NAME, "version": config.APP_VERSION, "page": "home",
        "stats": _stats(), "sources": _sources(), "frameworks": frameworks,
        "collectors": evidence.get_collectors(), "runs": evidence.last_runs(),
        "schedule": api_schedule(), "flash": msg, "flash_ok": bool(ok),
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


def _control(framework_id: str, control_id: str) -> dict:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM controls WHERE id = ? AND framework_id = ?",
                           (control_id, framework_id)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"Control '{control_id}' does not exist")
    return dict(row)


@app.get("/controls/{framework_id}/{control_id}", response_class=HTMLResponse)
def control_page(request: Request, framework_id: str, control_id: str, msg: str | None = None, ok: int = 1):
    fw = _framework(framework_id)
    return templates.TemplateResponse(request, "control.html", {
        "app_name": config.APP_NAME, "version": config.APP_VERSION, "page": "controls",
        "framework": fw, "control": _control(framework_id, control_id),
        "history": evidence.history_for_control(control_id),
        "default_valid_until": (date.today() + timedelta(days=365)).isoformat(),
        "today": date.today().isoformat(), "allowed": ", ".join(sorted(manual.ALLOWED_EXTENSIONS)),
        "flash": msg, "flash_ok": bool(ok),
    })


@app.post("/controls/{framework_id}/{control_id}/evidence")
async def add_evidence(request: Request, framework_id: str, control_id: str,
                       status: str = Form(...), note: str = Form(""),
                       valid_until: str = Form(""), file: UploadFile | None = File(None)):
    reviewer = _who(request)   # always the logged-in user, cannot be typed in
    _control(framework_id, control_id)
    upload = None
    if file is not None and file.filename:
        data = await file.read(manual.MAX_FILE_BYTES + 1)
        upload = manual.Upload(file.filename, data)
    base = f"/controls/{framework_id}/{control_id}"
    try:
        manual.add_manual_evidence(control_id, status, note, reviewer, valid_until or None, upload)
    except manual.EvidenceError as exc:
        return RedirectResponse(f"{base}?ok=0&msg={quote(str(exc))}", status_code=303)
    scoring.snapshot_all()
    auth.audit("evidence.added", reviewer, f"{control_id} {status}" + (f" + {upload.filename}" if upload else ""),
               client_ip(request))
    return RedirectResponse(f"{base}?ok=1&msg={quote('Evidence saved.')}", status_code=303)


@app.get("/attachments/{attachment_id}")
def download_attachment(attachment_id: int):
    found = manual.get_attachment(attachment_id)
    if not found:
        raise HTTPException(status_code=404, detail="Attachment not found")
    meta, path = found
    # Always a download, never rendered inline: uploaded files cannot run in the app's origin.
    return FileResponse(path, media_type="application/octet-stream", filename=meta["filename"],
                        headers={"X-Content-Type-Options": "nosniff"})


@app.get("/reports/{framework_id}.pdf")
def pdf_report(framework_id: str):
    fw = _framework(framework_id)
    pdf = report.build_pdf(fw)
    name = f"{framework_id}-compliance-report-{date.today().isoformat()}.pdf"
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})
