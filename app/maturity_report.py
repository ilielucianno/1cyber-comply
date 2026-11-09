"""PDF maturity assessment report (e.g. Cyprus DSA K.D.P. 245/2024 Annex E).

Structure: summary, maturity by category, result per measure with its blocking
requirement, a remediation plan to reach the target level, not-applicable
requirements by section (Cloud), automated evidence conflicts, the assessment
record, and a statement of what the report does and does not prove.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import CondPageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app import config, maturity
from app.report import LINE, MUTED, _p, _styles, _table

LEVEL_COLORS = ["#cf222e", "#bc4c00", "#9a6700", "#1a7f37", "#116329", "#0969da"]
ANSWER_LABELS = {"met": "Met", "not_met": "Not met", "na": "Not applicable", None: "Not assessed"}


def _level_cell(level: int, target: int, s) -> Paragraph:
    color = "#1a7f37" if level >= target else ("#9a6700" if level >= target - 1 else "#cf222e")
    return Paragraph(f'<font color="{color}"><b>{level}</b></font>', s["body"])


def _priority(level: int) -> str:
    return {0: "P1", 1: "P2"}.get(level, "P3")


def build_pdf(framework_id: str) -> bytes:
    s = _styles()
    cat = maturity.get(framework_id)
    if not cat:
        raise KeyError(framework_id)
    r = maturity.compute(framework_id)
    answers = maturity.latest_answers(framework_id)
    target = cat.target_level
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    measures = [m for c in r["categories"] for m in c["measures"]]
    title = f"{cat.name}: maturity assessment report"

    story = [
        _p(title, s["title"]),
        _p(f"{config.ORG_NAME} · {cat.authority} · {cat.reference} · generated {now} · "
           f"{config.APP_NAME} v{config.APP_VERSION}", s["muted"]),
        Spacer(1, 8 * mm),
    ]

    # -- summary
    verdict = ("MATURE: every measure reaches the target level" if r["mature"]
               else f"NOT MATURE: {r['below_target']} of {r['measures_total']} measures are below level {target}")
    vcolor = "#1a7f37" if r["mature"] else "#cf222e"
    summary = [[
        _p(f"{r['measures_at_target']}/{r['measures_total']}", s["big"]),
        [Paragraph(f'<font color="{vcolor}"><b>{verdict}</b></font>', s["body"]),
         _p(f"Target: level {target} or higher on every measure", s["body"]),
         _p(f"Average level {r['avg_level']} · lowest level {r['min_level']}", s["body"]),
         _p(f"{r['requirements_answered']} of {r['requirements_total']} requirements assessed"
            + (f" · {r['not_applicable_total']} not applicable" if r["not_applicable_total"] else ""), s["muted"])],
    ]]
    t = Table(summary, colWidths=[45 * mm, 125 * mm])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BOX", (0, 0), (-1, -1), 0.6, LINE),
                           ("LEFTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 8),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    dist = Table([[_p(f"Level {lv}", s["cell_b"]) for lv in r["distribution"]],
                  [Paragraph(f'<font color="{LEVEL_COLORS[lv]}"><b>{n}</b></font>', s["body"])
                   for lv, n in r["distribution"].items()]], colWidths=[170 * mm / 6] * 6)
    dist.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, LINE), ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                              ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f6f8fa"))]))
    story += [_p("Summary", s["h1"]), t, Spacer(1, 4 * mm), _p("Measures per maturity level", s["h2"]), dist,
              Spacer(1, 3 * mm),
              _p("Levels are cumulative. A measure reaches a level only when every requirement of that level "
                 "and of all levels below it is met; the first unmet requirement is the blocking requirement "
                 "and caps the measure. Requirements not yet assessed count as not met.", s["muted"])]

    # -- by category
    rows = [[_p(h, s["cell_b"]) for h in ("Category", "Measures", "Lowest", "Average", f"Below {target}")]]
    for c in r["categories"]:
        rows.append([_p(c["title"], s["small"]), _p(f"{len(c['measures'])}", s["small"]),
                     _level_cell(c["min_level"], target, s), _p(f"{c['avg_level']:.2f}", s["small"]),
                     _p(f"{c['below_target']}", s["small"])])
    story += [_p("Maturity by category", s["h1"]), _table(rows, [80 * mm, 22 * mm, 22 * mm, 22 * mm, 24 * mm], s)]

    # -- per measure
    story += [CondPageBreak(60 * mm), _p("Result per measure", s["h1"])]
    rows = [[_p(h, s["cell_b"]) for h in ("ID", "Measure", "Level", "Blocking requirement", "Assessed")]]
    for m in measures:
        b = m["blocking"]
        if b:
            block = [_p(f"{b['id']} ({'not met' if b['reason'] == 'not_met' else 'not assessed'})", s["cell_b"]),
                     _p(b["text"], s["muted"])]
        else:
            block = _p("None: all requirements up to level 5 are met", s["muted"])
        rows.append([_p(m["id"], s["small"]), _p(m["title"], s["small"]), _level_cell(m["level"], target, s),
                     block, _p(f"{m['answered']}/{m['total']}", s["small"])])
    story.append(_table(rows, [14 * mm, 48 * mm, 13 * mm, 77 * mm, 18 * mm], s))

    # -- remediation plan
    below = sorted([m for m in measures if not m["meets_target"]], key=lambda m: m["level"])
    story += [CondPageBreak(60 * mm), _p(f"Remediation plan to reach level {target}", s["h1"])]
    if below:
        story.append(_p(
            f"Every measure below level {target}, lowest level first. Priority P1: the measure is at level 0; "
            f"P2: level 1; P3: level {target - 1}. Each table lists every requirement up to level {target} that "
            "is not met or not yet assessed, in the order in which they block the measure. Owner and due date "
            "are for the organisation to fill in.", s["muted"]))
        for m in below:
            head = _p(f"{_priority(m['level'])} · {m['id']} {m['title']} · level {m['level']} → {target} · "
                      f"{len(m['gaps_to_target'])} open requirement(s)", s["h2"])
            rows = [[_p(h, s["cell_b"]) for h in ("Req.", "Requirement", "Status / note", "Owner", "Due")]]
            for g in m["gaps_to_target"]:
                status = [_p(ANSWER_LABELS[g["answer"]], s["cell_b"])]
                if g.get("note"):
                    status.append(_p(g["note"], s["muted"]))
                rows.append([_p(g["id"], s["small"]), _p(g["text"], s["small"]), status, "", ""])
            # Keep the heading with the first rows; a long table continues on the next page with its header
            story += [CondPageBreak(45 * mm), head, _table(rows, [12 * mm, 88 * mm, 36 * mm, 18 * mm, 16 * mm], s)]
    else:
        story.append(_p(f"No remediation needed: every measure is at level {target} or higher.", s["body"]))

    # -- not applicable
    for sec in r["not_applicable_sections"]:
        story += [_p(f"{sec['title']}: requirements marked not applicable", s["h1"]),
                  _p(sec["condition"], s["muted"]), Spacer(1, 2 * mm)]
        if sec["items"]:
            rows = [[_p(h, s["cell_b"]) for h in ("Req.", "Requirement", "Justification", "Assessed by")]]
            for i in sec["items"]:
                rows.append([_p(f"{i['measure_id']} {i['id']}", s["small"]), _p(i["text"], s["small"]),
                             _p(i["note"], s["small"]), _p(f"{i['answered_by']} · {(i['answered_at'] or '')[:10]}",
                                                           s["muted"])])
            story.append(_table(rows, [18 * mm, 72 * mm, 52 * mm, 28 * mm], s))
        else:
            story.append(_p("No requirement in this section is marked not applicable.", s["body"]))

    # -- automated evidence
    if r["evidence_mapped"]:
        story += [_p("Automated evidence", s["h1"]),
                  _p(f"{r['evidence_mapped']} requirements are linked to automated checks (Wazuh, OPNsense, "
                     "Microsoft 365). Evidence suggests answers but never replaces the assessor's answer. "
                     "The conflicts below are saved answers that the current evidence contradicts; they should "
                     "be reviewed before the assessment is final.", s["muted"]), Spacer(1, 2 * mm)]
        if r["evidence_conflicts"]:
            rows = [[_p(h, s["cell_b"]) for h in ("Req.", "Saved answer", "Current evidence")]]
            for c in r["evidence_conflicts"]:
                ev = [_p(f"{x['check']}: {x['status'] or 'not collected'} · {x['summary'] or ''}", s["small"])
                      for x in c["checks"]]
                rows.append([_p(f"{c['measure_id']} {c['requirement_id']}", s["small"]),
                             _p(ANSWER_LABELS[c["answer"]], s["cell_b"]), ev])
            story.append(_table(rows, [20 * mm, 25 * mm, 125 * mm], s))
        else:
            story.append(_p("No conflicts between saved answers and current evidence.", s["body"]))

    # -- assessment record
    story += [CondPageBreak(60 * mm), _p("Appendix: assessment record", s["h1"]),
              _p("The current answer for every assessed requirement, with who recorded it and when. "
                 "The full change history is kept in the application.", s["muted"]), Spacer(1, 2 * mm)]
    rows = [[_p(h, s["cell_b"]) for h in ("Req.", "Answer", "Note / evidence", "By", "Date")]]
    order = {(m.id, q.id): i for i, (m, q) in enumerate((m, q) for m in cat.measures for q in m.requirements)}
    for key in sorted(answers, key=lambda k: order.get(k, 1 << 30)):
        a = answers[key]
        rows.append([_p(f"{key[0]} {key[1]}", s["small"]), _p(ANSWER_LABELS[a["answer"]], s["small"]),
                     _p(a["note"] or "", s["muted"]), _p(a["answered_by"], s["small"]),
                     _p((a["answered_at"] or "")[:10], s["small"])])
    if len(rows) > 1:
        story.append(_table(rows, [20 * mm, 22 * mm, 88 * mm, 20 * mm, 20 * mm], s))
    else:
        story.append(_p("No requirement has been assessed yet.", s["body"]))

    # -- statement
    story += [_p("About this report", s["h1"]),
              _p(f"This report shows the self-assessment recorded in {config.APP_NAME} at the time of generation "
                 f"against {cat.reference}. Answers are recorded by the named assessors; automated evidence comes "
                 "from read-only queries to the organisation's security tools. It supports, but does not replace, "
                 "an assessment by the competent authority or an accredited auditor, and it is not a "
                 "certification of compliance.", s["body"])]
    if cat.translation:
        story += [Spacer(1, 2 * mm), _p(cat.translation, s["muted"])]

    buf = io.BytesIO()

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont(s["font"], 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(20 * mm, 10 * mm, f"{config.ORG_NAME} · {cat.name} · {now}")
        canvas.drawRightString(190 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
                            topMargin=18 * mm, bottomMargin=18 * mm, title=title, author=config.ORG_NAME,
                            creator=f"{config.APP_NAME} {config.APP_VERSION}")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()

