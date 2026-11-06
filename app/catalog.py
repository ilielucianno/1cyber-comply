"""Loads control catalogues from controls/*.yaml into the database.

Runs at every start: the YAML files are the source of truth for controls.
Evidence already collected is never touched.
"""
import logging
from pathlib import Path

import yaml

from app.config import CONTROLS_DIR
from app.db import get_conn

log = logging.getLogger("comply.catalog")

VALID_CHECK_TYPES = {"automated", "manual"}


class CatalogError(ValueError):
    pass


def automation_keys(value) -> list[str]:
    """`automation` in YAML may be one 'source:check' string or a list of them."""
    if not value:
        return []
    items = value if isinstance(value, list) else str(value).split(",")
    return [str(i).strip() for i in items if str(i).strip()]


def validate(data: dict, source: str) -> None:
    """Stop loading with a clear message if the YAML file has mistakes."""
    fw = data.get("framework") or {}
    for key in ("id", "name"):
        if not fw.get(key):
            raise CatalogError(f"{source}: framework.{key} is missing")
    seen: set[str] = set()
    for cat in data.get("categories") or []:
        for key in ("id", "reference", "title"):
            if not cat.get(key):
                raise CatalogError(f"{source}: category {cat} has no '{key}'")
        for ctl in cat.get("controls") or []:
            cid = ctl.get("id")
            if not cid or not ctl.get("title"):
                raise CatalogError(f"{source}: control without id or title in category {cat['id']}")
            if cid in seen:
                raise CatalogError(f"{source}: duplicate id {cid}")
            seen.add(cid)
            ctype = ctl.get("check_type", "manual")
            if ctype not in VALID_CHECK_TYPES:
                raise CatalogError(f"{source}: {cid} has invalid check_type '{ctype}'")
            if ctype == "automated" and not automation_keys(ctl.get("automation")):
                raise CatalogError(f"{source}: {cid} is automated but has no 'automation'")
            for key in automation_keys(ctl.get("automation")):
                if ":" not in key:
                    raise CatalogError(f"{source}: {cid} automation '{key}' must look like source:check")


def load_file(path: Path) -> tuple[str, int]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    validate(data, path.name)
    fw = data["framework"]

    rows = []
    order = 0
    for cat in data.get("categories") or []:
        for ctl in cat.get("controls") or []:
            order += 1
            rows.append((
                ctl["id"], fw["id"], cat["reference"], ctl["title"],
                (ctl.get("description") or "").strip(),
                ctl.get("check_type", "manual"),
                cat["id"], cat["title"], ",".join(automation_keys(ctl.get("automation"))) or None,
                (ctl.get("evidence_hint") or "").strip(), order,
            ))

    with get_conn() as conn:
        conn.execute(
            """INSERT INTO frameworks (id, name, version, description) VALUES (?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET name=excluded.name, version=excluded.version,
                                             description=excluded.description""",
            (fw["id"], fw["name"], str(fw.get("version") or ""), (fw.get("description") or "").strip()),
        )
        conn.executemany(
            """INSERT INTO controls (id, framework_id, reference, title, description, check_type,
                                     category_id, category_title, automation, evidence_hint, sort_order)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                 framework_id=excluded.framework_id, reference=excluded.reference,
                 title=excluded.title, description=excluded.description,
                 check_type=excluded.check_type, category_id=excluded.category_id,
                 category_title=excluded.category_title, automation=excluded.automation,
                 evidence_hint=excluded.evidence_hint, sort_order=excluded.sort_order""",
            rows,
        )
        # Controls removed from the YAML are deleted only if they have no evidence
        ids = [r[0] for r in rows]
        placeholders = ",".join("?" * len(ids)) or "''"
        conn.execute(
            f"""DELETE FROM controls WHERE framework_id = ? AND id NOT IN ({placeholders})
                AND id NOT IN (SELECT DISTINCT control_id FROM evidence)""",
            [fw["id"], *ids],
        )
    return fw["id"], len(rows)


def load_all(directory: Path = CONTROLS_DIR) -> dict[str, int]:
    loaded = {}
    for path in sorted(directory.glob("*.yaml")):
        fw_id, count = load_file(path)
        loaded[fw_id] = count
        log.info("Catalogue %s: %d controls loaded from %s", fw_id, count, path.name)
    return loaded


def controls_by_category(framework_id: str) -> list[dict]:
    """A framework's controls grouped by category, for the UI and API."""
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT * FROM controls WHERE framework_id = ? ORDER BY sort_order""",
            (framework_id,),
        ).fetchall()
    groups: dict[str, dict] = {}
    for r in rows:
        g = groups.setdefault(r["category_id"], {
            "id": r["category_id"], "title": r["category_title"],
            "reference": r["reference"], "controls": [],
        })
        g["controls"].append(dict(r))
    return list(groups.values())
