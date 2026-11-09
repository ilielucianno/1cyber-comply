"""Maturity model assessments (e.g. Cyprus DSA K.D.P. 245/2024 Annex E).

A maturity catalogue lists measures; each measure has requirements grouped by
level 1-5. Level 0 is the state where nothing is in place.

Scoring rule (cumulative, "first failure caps the level"):
  * A measure reaches level N only when every requirement of levels 1..N is met.
  * The first requirement that is not met, in level order and then in catalogue
    order, is the blocking requirement. The measure scores the level below it.
    Example: requirement 1.3 not met -> level 0, blocked by 1.3, even if every
    level 2 and 3 requirement is met.
  * An unanswered requirement counts as not met (the result never looks better
    than what has been assessed) but is reported as "not assessed".
  * "na" (not applicable) is accepted only on requirements the catalogue marks
    with an `na` section (for the DSA model: requirements that only apply when
    cloud services are used). It counts as met, needs a written justification
    noted on the requirement, and reports list it under its section (e.g. Cloud).
  * The organisation is mature when every measure reaches the target level.

Catalogues live in controls/maturity/*.yaml and are kept in memory; the
answers live in the database with full history (the latest answer wins).
"""
import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from app.config import CONTROLS_DIR
from app.db import get_conn

log = logging.getLogger("comply.maturity")

MATURITY_DIR = CONTROLS_DIR / "maturity"
ANSWERS = ("met", "not_met", "na")
LEVELS = (1, 2, 3, 4, 5)


class MaturityCatalogError(ValueError):
    pass


@dataclass
class Requirement:
    id: str          # original numbering, e.g. "3.4"
    level: int
    text: str
    common: str | None = None   # K1 / K2 / R1 when the requirement repeats across measures
    na: str | None = None       # section under which "not applicable" is accepted, e.g. cloud


@dataclass
class Measure:
    id: str
    title: str
    category_id: str
    category_title: str
    objective: str = ""
    description: str = ""
    source: str = ""
    page: int | None = None
    level0: str = ""
    requirements: list[Requirement] = field(default_factory=list)   # level order, then catalogue order

    def requirement(self, req_id: str) -> Requirement | None:
        return next((r for r in self.requirements if r.id == req_id), None)


@dataclass
class Catalogue:
    id: str
    name: str
    authority: str
    reference: str
    target_level: int
    translation: str
    measures: list[Measure]
    file: str = ""
    na_sections: dict = field(default_factory=dict)   # {"cloud": {"title": "Cloud", "condition": "..."}}

    def measure(self, measure_id: str) -> Measure | None:
        return next((m for m in self.measures if m.id == measure_id), None)

    @property
    def requirement_count(self) -> int:
        return sum(len(m.requirements) for m in self.measures)


_catalogues: dict[str, Catalogue] = {}


# ---------- loading ----------

def parse(data: dict, source: str) -> Catalogue:
    """Validate a maturity YAML document and turn it into a Catalogue."""
    fw = data.get("framework") or {}
    for key in ("id", "name"):
        if not fw.get(key):
            raise MaturityCatalogError(f"{source}: framework.{key} is missing")
    scoring = fw.get("scoring") or {}
    if scoring.get("type") != "maturity":
        raise MaturityCatalogError(f"{source}: framework.scoring.type must be 'maturity'")
    target = scoring.get("target_level", 3)
    if target not in LEVELS:
        raise MaturityCatalogError(f"{source}: target_level must be one of {LEVELS}")
    common = {str(k): str(v) for k, v in (fw.get("common_requirements") or {}).items()}
    na_sections = {str(k): dict(v or {}) for k, v in (fw.get("not_applicable") or {}).items()}
    for k, v in na_sections.items():
        if not v.get("title"):
            raise MaturityCatalogError(f"{source}: not_applicable.{k} has no title")

    measures: list[Measure] = []
    seen: set[str] = set()
    for cat in data.get("categories") or []:
        if not cat.get("id") or not cat.get("title"):
            raise MaturityCatalogError(f"{source}: category without id or title")
        for m in cat.get("measures") or []:
            mid = m.get("id")
            if not mid or not m.get("title"):
                raise MaturityCatalogError(f"{source}: measure without id or title in category {cat['id']}")
            if mid in seen:
                raise MaturityCatalogError(f"{source}: duplicate measure id {mid}")
            seen.add(mid)
            levels = m.get("levels") or {}
            bad = set(levels) - set(LEVELS)
            if bad:
                raise MaturityCatalogError(f"{source}: {mid} has invalid levels {sorted(bad)}")
            missing = [lv for lv in LEVELS if not levels.get(lv)]
            if missing:
                raise MaturityCatalogError(f"{source}: {mid} has no requirements for level(s) {missing}")
            reqs: list[Requirement] = []
            req_ids: set[str] = set()
            for lv in LEVELS:
                for r in levels[lv]:
                    rid = str(r.get("id") or "")
                    if not rid:
                        raise MaturityCatalogError(f"{source}: {mid} level {lv} has a requirement without id")
                    if rid in req_ids:
                        raise MaturityCatalogError(f"{source}: {mid} has duplicate requirement {rid}")
                    if rid.split(".")[0] != str(lv):
                        raise MaturityCatalogError(f"{source}: {mid} requirement {rid} is listed under level {lv}")
                    req_ids.add(rid)
                    tag = r.get("common")
                    if tag and tag not in common:
                        raise MaturityCatalogError(f"{source}: {mid} {rid} refers to unknown common requirement {tag}")
                    na = r.get("na")
                    if na and na not in na_sections:
                        raise MaturityCatalogError(f"{source}: {mid} {rid} refers to unknown not_applicable section {na}")
                    text = str(r.get("text") or (common.get(tag) if tag else "") or "").strip()
                    if not text:
                        raise MaturityCatalogError(f"{source}: {mid} {rid} has no text")
                    reqs.append(Requirement(rid, lv, text, tag, na))
            measures.append(Measure(
                id=mid, title=m["title"], category_id=cat["id"], category_title=cat["title"],
                objective=(m.get("objective") or "").strip(), description=(m.get("description") or "").strip(),
                source=m.get("source") or "", page=m.get("page"), level0=(m.get("level0") or "").strip(),
                requirements=reqs))
    if not measures:
        raise MaturityCatalogError(f"{source}: no measures")
    return Catalogue(id=fw["id"], name=fw["name"], authority=fw.get("authority", ""),
                     reference=fw.get("reference", ""), target_level=target,
                     translation=(fw.get("translation") or "").strip(), measures=measures, file=source,
                     na_sections=na_sections)


def load_all(directory: Path = MATURITY_DIR) -> dict[str, int]:
    """Load every maturity catalogue; a broken file stops start-up with a clear message."""
    loaded: dict[str, Catalogue] = {}
    for path in sorted(directory.glob("*.yaml")) if directory.is_dir() else []:
        cat = parse(yaml.safe_load(path.read_text(encoding="utf-8")) or {}, path.name)
        if cat.id in loaded:
            raise MaturityCatalogError(f"{path.name}: framework id {cat.id} already loaded from {loaded[cat.id].file}")
        loaded[cat.id] = cat
        log.info("Maturity catalogue %s: %d measures, %d requirements from %s",
                 cat.id, len(cat.measures), cat.requirement_count, path.name)
    _catalogues.clear()
    _catalogues.update(loaded)
    return {k: len(v.measures) for k, v in loaded.items()}


def catalogues() -> list[Catalogue]:
    return list(_catalogues.values())


def get(framework_id: str) -> Catalogue | None:
    return _catalogues.get(framework_id)


# ---------- answers ----------

def save_answer(framework_id: str, measure_id: str, requirement_id: str, answer: str,
                note: str = "", answered_by: str = "system", evidence_id: int | None = None) -> int:
    """Record an assessment answer. History is kept; the newest answer counts."""
    cat = get(framework_id)
    if not cat:
        raise KeyError(f"Maturity framework '{framework_id}' does not exist")
    measure = cat.measure(measure_id)
    if not measure:
        raise KeyError(f"Measure '{measure_id}' does not exist in {framework_id}")
    req = measure.requirement(requirement_id)
    if not req:
        raise KeyError(f"Requirement '{requirement_id}' does not exist in {measure_id}")
    error = answer_error(req, answer, note)
    if error:
        raise ValueError(error)
    note = (note or "").strip()
    if len(note) > 4000:
        raise ValueError("Note is too long (max 4000 characters)")
    with get_conn() as conn:
        return conn.execute(
            """INSERT INTO maturity_answers (framework_id, measure_id, requirement_id, answer, note,
                                             answered_by, evidence_id) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (framework_id, measure_id, requirement_id, answer, note or None, answered_by, evidence_id),
        ).lastrowid


def answer_error(req: Requirement, answer: str, note: str | None) -> str | None:
    """Why an answer is not acceptable for this requirement, or None if it is."""
    if answer not in ANSWERS:
        return f"Answer must be one of {', '.join(ANSWERS)}"
    if answer == "na":
        if not req.na:
            return f"Requirement {req.id} cannot be marked not applicable"
        if not (note or "").strip():
            return "A justification is required when a requirement is marked not applicable"
    return None


def latest_answers(framework_id: str) -> dict[tuple[str, str], dict]:
    """{(measure_id, requirement_id): newest answer row}."""
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT a.* FROM maturity_answers a
               JOIN (SELECT measure_id, requirement_id, MAX(id) AS id FROM maturity_answers
                     WHERE framework_id = ? GROUP BY measure_id, requirement_id) l ON l.id = a.id""",
            (framework_id,)).fetchall()
    return {(r["measure_id"], r["requirement_id"]): dict(r) for r in rows}


def answer_history(framework_id: str, measure_id: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT * FROM maturity_answers WHERE framework_id = ? AND measure_id = ?
               ORDER BY id DESC""", (framework_id, measure_id)).fetchall()
    return [dict(r) for r in rows]


# ---------- scoring ----------

def req_view(r: Requirement, a: dict | None) -> dict:
    return {"id": r.id, "level": r.level, "text": r.text, "common": r.common, "na_section": r.na,
            "answer": a["answer"] if a else None, "note": a["note"] if a else None,
            "answered_by": a["answered_by"] if a else None, "answered_at": a["answered_at"] if a else None}


def score_measure(measure: Measure, answers: dict[tuple[str, str], dict], target: int) -> dict:
    """Apply the cumulative rule to one measure."""
    level = 5
    blocking = None
    for r in measure.requirements:   # already in level order
        a = answers.get((measure.id, r.id))
        if not a or a["answer"] == "not_met":
            blocking = {**req_view(r, a), "reason": "not_met" if a else "not_assessed"}
            level = r.level - 1
            break

    def is_met(r):
        a = answers.get((measure.id, r.id))
        return bool(a) and a["answer"] in ("met", "na")

    per_level = {}
    for lv in LEVELS:
        reqs = [r for r in measure.requirements if r.level == lv]
        per_level[lv] = {"total": len(reqs), "met": sum(1 for r in reqs if is_met(r))}
    answered = sum(1 for r in measure.requirements if (measure.id, r.id) in answers)
    # Everything still open up to the target level: the remediation list for this measure
    gaps = [req_view(r, answers.get((measure.id, r.id))) for r in measure.requirements
            if r.level <= target and not is_met(r)]
    na = [req_view(r, answers[(measure.id, r.id)]) for r in measure.requirements
          if answers.get((measure.id, r.id), {}).get("answer") == "na"]
    return {
        "id": measure.id, "title": measure.title,
        "category_id": measure.category_id, "category_title": measure.category_title,
        "level": level, "meets_target": level >= target, "blocking": blocking,
        "per_level": per_level, "answered": answered, "total": len(measure.requirements),
        "gaps_to_target": gaps, "not_applicable": na,
    }


def compute(framework_id: str) -> dict:
    cat = get(framework_id)
    if not cat:
        raise KeyError(f"Maturity framework '{framework_id}' does not exist")
    answers = latest_answers(framework_id)
    measures = [score_measure(m, answers, cat.target_level) for m in cat.measures]

    categories: dict[str, dict] = {}
    for s in measures:
        c = categories.setdefault(s["category_id"], {"id": s["category_id"], "title": s["category_title"],
                                                     "measures": []})
        c["measures"].append(s)
    for c in categories.values():
        lv = [s["level"] for s in c["measures"]]
        c["min_level"] = min(lv)
        c["avg_level"] = round(sum(lv) / len(lv), 2)
        c["below_target"] = sum(1 for s in c["measures"] if not s["meets_target"])

    levels = [s["level"] for s in measures]
    total_reqs = sum(s["total"] for s in measures)
    answered = sum(s["answered"] for s in measures)
    return {
        "framework_id": cat.id, "name": cat.name, "authority": cat.authority, "reference": cat.reference,
        "target_level": cat.target_level,
        "mature": all(s["meets_target"] for s in measures),
        "measures_total": len(measures),
        "measures_at_target": sum(1 for s in measures if s["meets_target"]),
        "below_target": sum(1 for s in measures if not s["meets_target"]),
        "min_level": min(levels), "avg_level": round(sum(levels) / len(levels), 2),
        "distribution": {lv: levels.count(lv) for lv in (0, *LEVELS)},
        "requirements_total": total_reqs, "requirements_answered": answered,
        "not_applicable_total": sum(len(s["not_applicable"]) for s in measures),
        "not_applicable_sections": [
            {"id": sec, "title": info.get("title", sec), "condition": info.get("condition", ""),
             "items": [{"measure_id": s["id"], "measure_title": s["title"], **r}
                       for s in measures for r in s["not_applicable"] if r["na_section"] == sec]}
            for sec, info in cat.na_sections.items()],
        "categories": list(categories.values()),
    }


def snapshot(framework_id: str) -> dict:
    """Record the current result. Saves within the same hour update one row, so an
    assessment session of many answers leaves one history point, not hundreds."""
    s = compute(framework_id)
    values = (int(s["mature"]), s["avg_level"], s["min_level"], s["measures_at_target"],
              s["measures_total"], s["requirements_answered"], s["requirements_total"])
    with get_conn() as conn:
        recent = conn.execute(
            """SELECT id FROM maturity_history WHERE framework_id = ?
               AND taken_at >= datetime('now', '-1 hour') ORDER BY id DESC LIMIT 1""",
            (framework_id,)).fetchone()
        if recent:
            conn.execute(
                """UPDATE maturity_history SET mature = ?, avg_level = ?, min_level = ?, at_target = ?,
                   total = ?, answered = ?, requirements_total = ?, taken_at = datetime('now') WHERE id = ?""",
                (*values, recent["id"]))
        else:
            conn.execute(
                """INSERT INTO maturity_history (mature, avg_level, min_level, at_target, total, answered,
                                                 requirements_total, framework_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""", (*values, framework_id))
    return s


def history(framework_id: str, limit: int = 90) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT * FROM (SELECT * FROM maturity_history WHERE framework_id = ?
                              ORDER BY id DESC LIMIT ?) ORDER BY id""", (framework_id, limit)).fetchall()
    return [dict(r) for r in rows]
