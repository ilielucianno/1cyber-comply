"""PDF compliance report (ReportLab, BSD licence).

Structure: summary and score history, findings to fix, every control with its
current evidence, an appendix of attached files with SHA-256 hashes, and a
statement of what the report does and does not prove.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.graphics.charts.lineplots import LinePlot
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (CondPageBreak, KeepTogether, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

from app import catalog, config, evidence, scoring
from app.db import get_conn

STATUS_COLORS = {
    "pass": colors.HexColor("#1a7f37"),
    "fail": colors.HexColor("#cf222e"),
    "unknown": colors.HexColor("#6e7781"),
    "none": colors.HexColor("#9a6700"),
}
INK = colors.HexColor("#1f2328")
MUTED = colors.HexColor("#59636e")
LINE = colors.HexColor("#d0d7de")
ACCENT = colors.HexColor("#0969da")

_FONT_CANDIDATES = [
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
    ("/usr/share/fonts/TTF/DejaVuSans.ttf", "/usr/share/fonts/TTF/DejaVuSans-Bold.ttf"),
]


def _fonts() -> tuple[str, str]:
    """DejaVu covers Romanian/Greek/etc. diacritics; fall back to Helvetica if absent."""
    if "Comply" in pdfmetrics.getRegisteredFontNames():
        return "Comply", "Comply-Bold"
    for regular, bold in _FONT_CANDIDATES:
        if Path(regular).is_file() and Path(bold).is_file():
            pdfmetrics.registerFont(TTFont("Comply", regular))
            pdfmetrics.registerFont(TTFont("Comply-Bold", bold))
            return "Comply", "Comply-Bold"
    return "Helvetica", "Helvetica-Bold"


def _styles():
    font, bold = _fonts()
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontName=bold, fontSize=22, leading=26,
                                alignment=TA_LEFT, textColor=INK, spaceAfter=4),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName=bold, fontSize=14, leading=18,
                             textColor=INK, spaceBefore=10, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName=bold, fontSize=11, leading=14,
                             textColor=INK, spaceBefore=10, spaceAfter=4),
        "body": ParagraphStyle("b", parent=base["BodyText"], fontName=font, fontSize=9.5, leading=13, textColor=INK),
        "small": ParagraphStyle("s", parent=base["BodyText"], fontName=font, fontSize=8, leading=10.5, textColor=INK),
        "muted": ParagraphStyle("m", parent=base["BodyText"], fontName=font, fontSize=8, leading=10.5, textColor=MUTED),
        "cell_b": ParagraphStyle("cb", parent=base["BodyText"], fontName=bold, fontSize=8, leading=10.5, textColor=INK),
        "big": ParagraphStyle("big", parent=base["BodyText"], fontName=bold, fontSize=34, leading=38, textColor=INK),
        "font": font, "bold": bold,
    }


def _p(text, style) -> Paragraph:
    return Paragraph(escape(str(text or "")), style)


def _status_cell(status: str, s) -> Paragraph:
    label = {"none": "NO EVIDENCE"}.get(status, status.upper())
    color = STATUS_COLORS.get(status, MUTED).hexval()[2:]
    return Paragraph(f'<font color="#{color}"><b>{label}</b></font>', s["small"])


def _history_chart(points: list[dict], s) -> Drawing | None:
    if len(points) < 2:
        return None
    d = Drawing(170 * mm, 45 * mm)
    lp = LinePlot()
    lp.x, lp.y, lp.width, lp.height = 12 * mm, 8 * mm, 150 * mm, 32 * mm
    lp.data = [[(i, p["score"]) for i, p in enumerate(points)],
               [(i, p["automated_score"] or 0) for i, p in enumerate(points)]]
    lp.lines[0].strokeColor, lp.lines[0].strokeWidth = ACCENT, 1.6
    lp.lines[1].strokeColor, lp.lines[1].strokeWidth = STATUS_COLORS["pass"], 1
    lp.lines[1].strokeDashArray = (3, 2)
    lp.yValueAxis.valueMin, lp.yValueAxis.valueMax, lp.yValueAxis.valueStep = 0, 100, 25
    lp.yValueAxis.labels.fontName, lp.yValueAxis.labels.fontSize = s["font"], 7
    lp.yValueAxis.labelTextFormat = "%d%%"
    lp.xValueAxis.visibleLabels = False
    lp.yValueAxis.gridStrokeColor, lp.yValueAxis.visibleGrid = LINE, True
    d.add(lp)
    d.add(String(12 * mm, 2 * mm, points[0]["taken_at"][:10], fontName=s["font"], fontSize=7, fillColor=MUTED))
    d.add(String(162 * mm, 2 * mm, points[-1]["taken_at"][:10], fontName=s["font"], fontSize=7,
                 fillColor=MUTED, textAnchor="end"))
    return d


def _table(rows, widths, s, header=True, zebra=True) -> Table:
    t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f6f8fa")),
                  ("LINEBELOW", (0, 0), (-1, 0), 0.8, INK)]
    t.setStyle(TableStyle(style))
    return t


def _attachments(framework_id: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT a.*, e.control_id, e.reviewer FROM attachments a
               JOIN evidence e ON e.id = a.evidence_id JOIN controls c ON c.id = e.control_id
               WHERE c.framework_id = ? AND e.id IN (SELECT MAX(id) FROM evidence GROUP BY control_id)
               ORDER BY e.control_id, a.id""", (framework_id,)).fetchall()
    return [dict(r) for r in rows]


def build_pdf(framework: dict) -> bytes:
    s = _styles()
    fw_id = framework["id"]
    score = scoring.compute(fw_id)
    hist = scoring.history(fw_id)
    latest = evidence.latest_by_control(fw_id)
    categories = catalog.controls_by_category(fw_id)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    story = [
        _p(f"{framework['name']} compliance report", s["title"]),
        _p(f"{config.ORG_NAME} · generated {now} · {config.APP_NAME} v{config.APP_VERSION}", s["muted"]),
        Spacer(1, 8 * mm),
    ]

    # -- summary
    summary = [
        [_p(f"{score['score']:.0f}%", s["big"]),
         [_p(f"{score['passed']} of {score['total']} controls proven compliant", s["body"]),
          _p(f"Automated controls: {score['automated_score']:.0f}% of {score['automated_total']}", s["body"]),
          _p(f"Manual controls: {score['manual_score']:.0f}% of {score['manual_total']}", s["body"]),
          _p(f"{score['failed']} fail · {score['unknown']} unknown · {score['missing']} without evidence",
             s["muted"])]],
    ]
    t = Table(summary, colWidths=[45 * mm, 125 * mm])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                           ("BOX", (0, 0), (-1, -1), 0.6, LINE), ("LEFTPADDING", (0, 0), (-1, -1), 8),
                           ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story += [_p("Summary", s["h1"]), t, Spacer(1, 3 * mm),
              _p("The score counts only controls with current passing evidence. Failed, unknown, "
                 "expired and not-yet-evidenced controls all count as not compliant.", s["muted"])]
    chart = _history_chart(hist, s)
    if chart:
        story += [_p("Score history", s["h2"]), chart,
                  _p("Solid line: overall score. Dashed line: automated controls.", s["muted"])]

    # -- findings
    findings = []
    for cat in categories:
        for c in cat["controls"]:
            e = latest.get(c["id"])
            if e and e["status"] in ("fail", "unknown"):
                findings.append([_p(c["id"], s["small"]), _p(c["title"], s["cell_b"]),
                                 _status_cell(e["status"], s), _p(e["summary"], s["small"])])
    story.append(_p("Findings to address", s["h1"]))
    if findings:
        story.append(_table([[_p(h, s["cell_b"]) for h in ("Control", "Title", "Status", "Detail")], *findings],
                            [22 * mm, 45 * mm, 20 * mm, 83 * mm], s))
    else:
        story.append(_p("No failed or unknown controls.", s["body"]))

    # -- all controls
    story += [CondPageBreak(70 * mm), _p("All controls", s["h1"])]
    for cat in categories:
        rows = [[_p(h, s["cell_b"]) for h in ("Control", "Requirement", "Type", "Status", "Evidence")]]
        for c in cat["controls"]:
            e = latest.get(c["id"])
            if e:
                meta = f"{e['source']} · {e['collected_at'][:16]} UTC"
                if e.get("reviewer"):
                    meta += f" · reviewed by {e['reviewer']}"
                if e.get("valid_until"):
                    meta += f" · valid until {e['valid_until']}"
                ev = [_p(e["summary"], s["small"]), _p(meta, s["muted"])]
                status = e["status"]
            else:
                ev = [_p(f"Expected: {c['evidence_hint']}", s["muted"])]
                status = "none"
            rows.append([_p(c["id"], s["small"]),
                         [_p(c["title"], s["cell_b"]), _p(c["description"], s["muted"])],
                         _p(c["check_type"], s["small"]), _status_cell(status, s), ev])
        story.append(KeepTogether([_p(f"{cat['reference']} · {cat['title']}", s["h2"])]))
        story.append(_table(rows, [19 * mm, 53 * mm, 19 * mm, 21 * mm, 58 * mm], s))

    # -- attachments
    atts = _attachments(fw_id)
    story.append(_p("Appendix: evidence files", s["h1"]))
    if atts:
        rows = [[_p(h, s["cell_b"]) for h in ("Control", "File", "Uploaded", "SHA-256")]]
        for a in atts:
            rows.append([_p(a["control_id"], s["small"]), _p(a["filename"], s["small"]),
                         _p(a["uploaded_at"][:16], s["small"]), _p(a["sha256"], s["muted"])])
        story.append(_table(rows, [22 * mm, 50 * mm, 26 * mm, 72 * mm], s))
        story.append(_p("The SHA-256 hash lets an auditor verify that a file has not been changed since upload.",
                        s["muted"]))
    else:
        story.append(_p("No files attached.", s["body"]))

    # -- statement
    story += [_p("About this report", s["h1"]),
              _p("This report shows the evidence collected by 1cyber Comply at the time of generation. "
                 "Automated results come from read-only queries to the organisation's security tools; manual "
                 "results are assessments recorded by the named reviewers. It supports, but does not replace, "
                 "an assessment by the competent authority or an accredited auditor, and it is not a "
                 "certification of compliance.", s["body"])]

    buf = io.BytesIO()

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont(s["font"], 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(20 * mm, 10 * mm, f"{config.ORG_NAME} · {framework['name']} compliance report · {now}")
        canvas.drawRightString(190 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
                            topMargin=18 * mm, bottomMargin=18 * mm,
                            title=f"{framework['name']} compliance report", author=config.ORG_NAME,
                            creator=f"{config.APP_NAME} {config.APP_VERSION}")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
