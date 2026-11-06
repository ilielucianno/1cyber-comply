"""Compliance score: share of a framework's controls that have passing evidence.

Unknown results and controls without evidence count as not passing, so the
score never looks better than what has actually been proven.
"""
from app.db import get_conn


def compute(framework_id: str) -> dict:
    with get_conn() as conn:
        controls = conn.execute(
            "SELECT id, check_type FROM controls WHERE framework_id = ?", (framework_id,)).fetchall()
        latest = {r["control_id"]: r["status"] for r in conn.execute(
            """SELECT e.control_id, e.status FROM evidence e JOIN controls c ON c.id = e.control_id
               WHERE c.framework_id = ? AND e.id IN (SELECT MAX(id) FROM evidence GROUP BY control_id)""",
            (framework_id,))}

    total = len(controls)
    automated = [c["id"] for c in controls if c["check_type"] == "automated"]
    manual = [c["id"] for c in controls if c["check_type"] == "manual"]
    counts = {"pass": 0, "fail": 0, "unknown": 0}
    for status in latest.values():
        counts[status] = counts.get(status, 0) + 1

    def pct(ids: list[str]) -> float:
        return round(100 * sum(1 for i in ids if latest.get(i) == "pass") / len(ids), 1) if ids else 0.0

    return {
        "framework_id": framework_id,
        "score": pct([c["id"] for c in controls]),
        "automated_score": pct(automated),
        "manual_score": pct(manual),
        "passed": counts["pass"],
        "failed": counts["fail"],
        "unknown": counts["unknown"],
        "missing": total - len(latest),
        "total": total,
        "automated_total": len(automated),
        "manual_total": len(manual),
    }


def snapshot(framework_id: str) -> dict:
    s = compute(framework_id)
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO score_history (framework_id, score, automated_score, passed, failed, unknown, missing, total)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (framework_id, s["score"], s["automated_score"], s["passed"], s["failed"],
             s["unknown"], s["missing"], s["total"]))
    return s


def snapshot_all() -> None:
    with get_conn() as conn:
        ids = [r["id"] for r in conn.execute("SELECT id FROM frameworks")]
    for fw in ids:
        snapshot(fw)


def history(framework_id: str, limit: int = 90) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT * FROM (SELECT * FROM score_history WHERE framework_id = ?
                              ORDER BY id DESC LIMIT ?) ORDER BY id""", (framework_id, limit)).fetchall()
    return [dict(r) for r in rows]


def last_snapshot_age_hours(framework_id: str) -> float | None:
    with get_conn() as conn:
        row = conn.execute(
            """SELECT (julianday('now') - julianday(MAX(taken_at))) * 24 AS age
               FROM score_history WHERE framework_id = ?""", (framework_id,)).fetchone()
    return None if row is None or row["age"] is None else row["age"]


def chart_svg(points: list[dict], width: int = 640, height: int = 160) -> str:
    """Small server-side SVG line chart of the score history (no JavaScript needed)."""
    if not points:
        return ""
    pad_l, pad_r, pad_t, pad_b = 36, 12, 12, 24
    w, h = width - pad_l - pad_r, height - pad_t - pad_b
    n = len(points)

    def x(i: int) -> float:
        return pad_l + (w * i / (n - 1) if n > 1 else w / 2)

    def y(v: float) -> float:
        return pad_t + h - h * v / 100

    grid = "".join(
        f'<line x1="{pad_l}" x2="{pad_l + w}" y1="{y(v):.1f}" y2="{y(v):.1f}" class="g"/>'
        f'<text x="{pad_l - 6}" y="{y(v) + 4:.1f}" text-anchor="end" class="t">{v}%</text>'
        for v in (0, 50, 100))
    line = " ".join(f"{x(i):.1f},{y(p['score']):.1f}" for i, p in enumerate(points))
    auto = " ".join(f"{x(i):.1f},{y(p['automated_score'] or 0):.1f}" for i, p in enumerate(points))
    dots = "".join(
        f'<circle cx="{x(i):.1f}" cy="{y(p["score"]):.1f}" r="3" class="d">'
        f'<title>{p["taken_at"]} UTC: {p["score"]}%</title></circle>' for i, p in enumerate(points))
    first, last = points[0]["taken_at"][:10], points[-1]["taken_at"][:10]
    labels = (f'<text x="{pad_l}" y="{height - 6}" class="t">{first}</text>'
              f'<text x="{pad_l + w}" y="{height - 6}" text-anchor="end" class="t">{last}</text>')
    return (f'<svg viewBox="0 0 {width} {height}" width="100%" role="img" aria-label="Compliance score history">'
            f'{grid}<polyline points="{auto}" class="la"/><polyline points="{line}" class="l"/>{dots}{labels}</svg>')
