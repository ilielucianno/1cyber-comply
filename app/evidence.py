"""Runs collectors and stores their results as evidence attached to controls."""
import json
import logging
from datetime import date

from app.collectors.base import BaseCollector, CheckResult
from app.db import get_conn

log = logging.getLogger("comply.evidence")


def get_collectors() -> dict[str, BaseCollector]:
    from app.collectors.comply import ComplyCollector
    from app.collectors.microsoft365 import Microsoft365Collector
    from app.collectors.opnsense import OPNsenseCollector
    from app.collectors.wazuh import WazuhCollector
    return {"wazuh": WazuhCollector(), "opnsense": OPNsenseCollector(),
            "microsoft365": Microsoft365Collector(), "comply": ComplyCollector()}


def save_results(source: str, results: list[CheckResult]) -> int:
    """Attach each result to the controls with automation = '<source>:<check>'."""
    saved = 0
    with get_conn() as conn:
        for r in results:
            control_ids = [row["id"] for row in conn.execute(
                "SELECT id FROM controls WHERE ',' || automation || ',' LIKE ?", (f"%,{source}:{r.check},%",))]
            if not control_ids:
                log.info("Check %s:%s is not linked to any control", source, r.check)
            for cid in control_ids:
                conn.execute(
                    "INSERT INTO evidence (control_id, source, status, summary, raw_json) VALUES (?, ?, ?, ?, ?)",
                    (cid, source, r.status, r.summary, json.dumps(r.raw, ensure_ascii=False, default=str)),
                )
                saved += 1
    return saved


def run_collection(source: str, collector: BaseCollector | None = None, snapshot: bool = True) -> dict:
    collector = collector or get_collectors()[source]
    if not collector.is_configured():
        return {"ok": False, "message": f"{source} is not configured in .env", "saved": 0}

    with get_conn() as conn:
        run_id = conn.execute("INSERT INTO collection_runs (source) VALUES (?)", (source,)).lastrowid

    try:
        results = collector.collect()
        saved = save_results(source, results)
        counts = {s: sum(1 for r in results if r.status == s) for s in ("pass", "fail", "unknown")}
        ok = True
        message = (f"{len(results)} checks: {counts['pass']} pass, {counts['fail']} fail, "
                   f"{counts['unknown']} unknown; {saved} evidence records saved")
    except Exception as exc:  # noqa: BLE001
        ok, saved, message = False, 0, f"Collection failed: {exc}"
        log.exception("Collection %s failed", source)

    with get_conn() as conn:
        conn.execute("UPDATE collection_runs SET finished_at = datetime('now'), ok = ?, message = ? WHERE id = ?",
                     (int(ok), message, run_id))
    if ok and snapshot:
        from app import scoring
        scoring.snapshot_all()
    return {"ok": ok, "message": message, "saved": saved}


def last_runs() -> dict[str, dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT * FROM collection_runs WHERE id IN
               (SELECT MAX(id) FROM collection_runs GROUP BY source)""").fetchall()
    return {r["source"]: dict(r) for r in rows}


def effective(e: dict, today: str | None = None) -> dict:
    """Expired manual evidence no longer proves compliance: it counts as fail."""
    today = today or date.today().isoformat()
    e = dict(e)
    e["expired"] = bool(e.get("valid_until") and e["valid_until"] < today)
    if e["expired"]:
        e["status"] = "fail"
        e["summary"] = f"EXPIRED on {e['valid_until']}. {e.get('summary') or ''}".strip()
    return e


SOURCE_LABELS = {"wazuh": "Wazuh", "opnsense": "OPNsense", "microsoft365": "Microsoft 365",
                 "comply": "1cyber Comply", "manual": "manual"}


def combine(parts: list[dict]) -> dict:
    """One status per control from the latest result of every source.

    'unknown' from one source does not hide a definitive answer from another
    (e.g. a manual record for OpenVPN when no WireGuard instance exists);
    any definitive fail makes the control fail; otherwise it passes.
    """
    parts = sorted(parts, key=lambda e: e["id"], reverse=True)
    definitive = [e["status"] for e in parts if e["status"] != "unknown"]
    status = "unknown" if not definitive else ("fail" if "fail" in definitive else "pass")
    multi = len(parts) > 1
    manual = next((e for e in parts if e["source"] == "manual"), None)
    return {
        "control_id": parts[0]["control_id"],
        "status": status,
        "summary": " | ".join(
            (f"{SOURCE_LABELS.get(e['source'], e['source'])}: " if multi else "") + (e["summary"] or "")
            for e in parts),
        "source": ", ".join(SOURCE_LABELS.get(e["source"], e["source"]) for e in parts),
        "collected_at": parts[0]["collected_at"],
        "reviewer": manual["reviewer"] if manual else None,
        "valid_until": manual["valid_until"] if manual else None,
        "expired": any(e.get("expired") for e in parts),
        "attachment_count": sum(e.get("attachment_count") or 0 for e in parts),
        "parts": parts,
    }


def latest_by_control(framework_id: str) -> dict[str, dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT e.*, (SELECT COUNT(*) FROM attachments a WHERE a.evidence_id = e.id) AS attachment_count
               FROM evidence e JOIN controls c ON c.id = e.control_id
               WHERE c.framework_id = ? AND e.id IN
                 (SELECT MAX(id) FROM evidence GROUP BY control_id, source)""", (framework_id,)).fetchall()
    by_control: dict[str, list] = {}
    for r in rows:
        by_control.setdefault(r["control_id"], []).append(effective(dict(r)))
    return {cid: combine(parts) for cid, parts in by_control.items()}


def history_for_control(control_id: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM evidence WHERE control_id = ? ORDER BY id DESC", (control_id,)).fetchall()
        atts = conn.execute(
            """SELECT a.* FROM attachments a JOIN evidence e ON e.id = a.evidence_id
               WHERE e.control_id = ? ORDER BY a.id""", (control_id,)).fetchall()
    by_ev: dict[int, list] = {}
    for a in atts:
        by_ev.setdefault(a["evidence_id"], []).append(dict(a))
    out = []
    for r in rows:
        e = effective(dict(r))
        e["attachments"] = by_ev.get(r["id"], [])
        out.append(e)
    return out


def status_counts(framework_id: str) -> dict[str, int]:
    latest = latest_by_control(framework_id)
    counts = {"pass": 0, "fail": 0, "unknown": 0}
    for e in latest.values():
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    return counts
