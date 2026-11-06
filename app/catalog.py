"""Incarca cataloagele de controale din controls/*.yaml in baza de date.

Ruleaza la fiecare pornire: YAML-ul este sursa de adevar pentru controale.
Dovezile deja colectate raman neatinse.
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


def validate(data: dict, source: str) -> None:
    """Opreste incarcarea daca fisierul YAML are greseli, cu mesaj clar."""
    fw = data.get("framework") or {}
    for key in ("id", "name"):
        if not fw.get(key):
            raise CatalogError(f"{source}: framework.{key} lipseste")
    seen: set[str] = set()
    for cat in data.get("categories") or []:
        for key in ("id", "reference", "title"):
            if not cat.get(key):
                raise CatalogError(f"{source}: categoria {cat} nu are '{key}'")
        for ctl in cat.get("controls") or []:
            cid = ctl.get("id")
            if not cid or not ctl.get("title"):
                raise CatalogError(f"{source}: control fara id sau title in categoria {cat['id']}")
            if cid in seen:
                raise CatalogError(f"{source}: id duplicat {cid}")
            seen.add(cid)
            ctype = ctl.get("check_type", "manual")
            if ctype not in VALID_CHECK_TYPES:
                raise CatalogError(f"{source}: {cid} are check_type invalid '{ctype}'")
            if ctype == "automated" and not ctl.get("automation"):
                raise CatalogError(f"{source}: {cid} este automated dar nu are 'automation'")


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
                cat["id"], cat["title"], ctl.get("automation"),
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
        # Controale scoase din YAML: le stergem doar daca nu au dovezi atasate
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
        log.info("Catalog %s: %d controale incarcate din %s", fw_id, count, path.name)
    return loaded


def controls_by_category(framework_id: str) -> list[dict]:
    """Controalele unui framework, grupate pe categorii, pentru UI si API."""
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
