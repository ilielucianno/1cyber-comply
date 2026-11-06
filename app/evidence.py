"""Ruleaza colectorii si salveaza rezultatele ca dovezi atasate controalelor."""
import json
import logging

from app.collectors.base import BaseCollector, CheckResult
from app.db import get_conn

log = logging.getLogger("comply.evidence")


def get_collectors() -> dict[str, BaseCollector]:
    from app.collectors.wazuh import WazuhCollector
    return {"wazuh": WazuhCollector()}


def save_results(source: str, results: list[CheckResult]) -> int:
    """Leaga fiecare rezultat de controalele cu automation = '<source>:<check>'."""
    saved = 0
    with get_conn() as conn:
        for r in results:
            control_ids = [row["id"] for row in conn.execute(
                "SELECT id FROM controls WHERE automation = ?", (f"{source}:{r.check}",))]
            if not control_ids:
                log.info("Verificarea %s:%s nu e legata de niciun control", source, r.check)
            for cid in control_ids:
                conn.execute(
                    "INSERT INTO evidence (control_id, source, status, summary, raw_json) VALUES (?, ?, ?, ?, ?)",
                    (cid, source, r.status, r.summary, json.dumps(r.raw, ensure_ascii=False, default=str)),
                )
                saved += 1
    return saved


def run_collection(source: str, collector: BaseCollector | None = None) -> dict:
    collector = collector or get_collectors()[source]
    if not collector.is_configured():
        return {"ok": False, "message": f"{source} nu este configurat in .env", "saved": 0}

    with get_conn() as conn:
        run_id = conn.execute("INSERT INTO collection_runs (source) VALUES (?)", (source,)).lastrowid

    try:
        results = collector.collect()
        saved = save_results(source, results)
        counts = {s: sum(1 for r in results if r.status == s) for s in ("pass", "fail", "unknown")}
        ok = True
        message = (f"{len(results)} verificari: {counts['pass']} pass, {counts['fail']} fail, "
                   f"{counts['unknown']} unknown; {saved} dovezi salvate")
    except Exception as exc:  # noqa: BLE001
        ok, saved, message = False, 0, f"Colectarea a esuat: {exc}"
        log.exception("Colectarea %s a esuat", source)

    with get_conn() as conn:
        conn.execute("UPDATE collection_runs SET finished_at = datetime('now'), ok = ?, message = ? WHERE id = ?",
                     (int(ok), message, run_id))
    return {"ok": ok, "message": message, "saved": saved}


def last_runs() -> dict[str, dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT * FROM collection_runs WHERE id IN
               (SELECT MAX(id) FROM collection_runs GROUP BY source)""").fetchall()
    return {r["source"]: dict(r) for r in rows}


def latest_by_control(framework_id: str) -> dict[str, dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT e.* FROM evidence e JOIN controls c ON c.id = e.control_id
               WHERE c.framework_id = ? AND e.id IN
                 (SELECT MAX(id) FROM evidence GROUP BY control_id)""", (framework_id,)).fetchall()
    return {r["control_id"]: dict(r) for r in rows}


def status_counts(framework_id: str) -> dict[str, int]:
    latest = latest_by_control(framework_id)
    counts = {"pass": 0, "fail": 0, "unknown": 0}
    for e in latest.values():
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    return counts
