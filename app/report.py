from __future__ import annotations
from io import BytesIO
from html import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from .models import ThreatModel


def render_pdf(model: ThreatModel) -> bytes:
    out = BytesIO(); styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=8, leading=10))
    doc = SimpleDocTemplate(out, pagesize=A4, rightMargin=16*mm, leftMargin=16*mm, topMargin=16*mm, bottomMargin=16*mm, title=model.title)
    safe = lambda value: escape(str(value))
    story = [Paragraph(safe(model.title), styles["Title"]), Paragraph("Executive threat assessment", styles["Heading2"]), Paragraph(safe(model.summary), styles["BodyText"]), Spacer(1, 8)]
    counts = {s: sum(f.severity == s for f in model.findings) for s in ("Critical", "High", "Medium", "Low")}
    table = Table([["Critical", "High", "Medium", "Low"], [counts[x] for x in ("Critical", "High", "Medium", "Low")]], colWidths=[40*mm]*4)
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#172554")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("ALIGN", (0,0), (-1,-1), "CENTER"), ("GRID", (0,0), (-1,-1), .5, colors.grey), ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold")]))
    story += [table, Spacer(1, 10), Paragraph("Priority actions", styles["Heading2"])]
    story += [Paragraph(f"• {safe(r)}", styles["BodyText"]) for r in model.recommendations[:8]]
    story += [PageBreak(), Paragraph("STRIDE findings", styles["Heading1"])]
    for f in model.findings:
        story += [Paragraph(safe(f"{f.id} · {f.severity} · {f.stride} · confidence {f.confidence}"), styles["Heading3"]), Paragraph(f"<b>{safe(f.title)}</b> — {safe(f.description)}", styles["BodyText"]), Paragraph(safe("Evidence: " + "; ".join(f.evidence)), styles["Small"]), Paragraph(safe("MITRE ATT&CK: " + "; ".join(f.mitre_attack)), styles["Small"]), Spacer(1, 5)]
    if model.attack_paths:
        story += [PageBreak(), Paragraph("Attack paths", styles["Heading1"])]
        for p in model.attack_paths: story += [Paragraph(safe(f"{p.id} · {p.title}"), styles["Heading3"]), Paragraph(safe(" → ".join(p.steps)), styles["BodyText"]), Paragraph(safe(p.rationale), styles["Small"])]
    story += [PageBreak(), Paragraph("Coverage and assumptions", styles["Heading1"]), Paragraph(safe(str(model.architecture.coverage)), styles["BodyText"])]
    story += [Paragraph("Assumptions", styles["Heading2"])] + [Paragraph("• " + safe(x), styles["BodyText"]) for x in model.architecture.assumptions]
    story += [Paragraph("Parser warnings", styles["Heading2"])] + [Paragraph("• " + safe(x), styles["BodyText"]) for x in model.architecture.warnings]
    story += [Spacer(1, 12), Paragraph(model.methodology, styles["Small"]), Paragraph(model.disclaimer, styles["Small"])]
    doc.build(story); return out.getvalue()
