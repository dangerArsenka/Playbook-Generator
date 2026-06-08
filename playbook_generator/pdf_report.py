import html
import json
import os
import re

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    Preformatted,
)

from database import get_analysis_by_id
from markdown_helpers import html_to_plain_text
from settings import OUTPUT_DIR


def row_get(row, key, default=None):
    try:
        if key in row.keys():
            return row[key]
    except Exception:
        pass
    return default


def setup_pdf_fonts():
    candidates_regular = [
        r"C:\Windows\Fonts\arial.ttf",
        r"C:\Windows\Fonts\calibri.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
    ]
    candidates_bold = [
        r"C:\Windows\Fonts\arialbd.ttf",
        r"C:\Windows\Fonts\calibrib.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf",
    ]

    regular_path = next((p for p in candidates_regular if os.path.exists(p)), None)
    bold_path = next((p for p in candidates_bold if os.path.exists(p)), None)

    if regular_path:
        try:
            pdfmetrics.registerFont(TTFont("AppFont", regular_path))
            if bold_path:
                pdfmetrics.registerFont(TTFont("AppFont-Bold", bold_path))
            else:
                pdfmetrics.registerFont(TTFont("AppFont-Bold", regular_path))
            pdfmetrics.registerFontFamily(
                "AppFont",
                normal="AppFont",
                bold="AppFont-Bold",
                italic="AppFont",
                boldItalic="AppFont-Bold",
            )
            return "AppFont", "AppFont-Bold"
        except Exception:
            pass
    return "Helvetica", "Helvetica-Bold"


def labels(language):
    if language == "uk":
        return {
            "title": "SOC-звіт: плейбук реагування на інцидент",
            "scenario": "1. Початковий сценарій інциденту",
            "summary": "2. AI-оцінка інциденту",
            "iocs": "3. Виявлені IOC та результати Threat Intelligence",
            "mitre": "4. AI-рекомендації MITRE ATT&CK",
            "playbook": "5. Згенерований плейбук реагування на інцидент",
            "appendix": "Додаток: вихідний код Mermaid",
            "rationale": "Обґрунтування",
            "ioc_context": "Контекст IOC",
            "no_iocs": "IOC не були виявлені у сценарії.",
            "no_mitre": "Можливі техніки MITRE ATT&CK не були запропоновані.",
            "no_playbook": "Плейбук не був згенерований.",
            "evidence": "Evidence",
            "summary_col": "Summary",
        }
    return {
        "title": "SOC Incident Response Playbook Report",
        "scenario": "1. Original Incident Scenario",
        "summary": "2. AI-Based Incident Summary",
        "iocs": "3. Extracted IOCs and Threat Intelligence Results",
        "mitre": "4. AI-Assisted MITRE ATT&CK Suggestions",
        "playbook": "5. Generated Incident Response Playbook",
        "appendix": "Appendix: Mermaid Source Code",
        "rationale": "Rationale",
        "ioc_context": "IOC Context Note",
        "no_iocs": "No IOCs were extracted from the scenario.",
        "no_mitre": "No possible MITRE ATT&CK techniques were suggested.",
        "no_playbook": "No playbook content was generated.",
        "evidence": "Evidence",
        "summary_col": "Summary",
    }


def escape_pdf_text(value):
    return html.escape(str(value or "-"), quote=False)


def clean_inline_markdown(text):
    if not text:
        return ""
    text = str(text).strip()
    text = re.sub(r"\*\*(.*?)\*\*", r"\1", text)
    text = re.sub(r"__(.*?)__", r"\1", text)
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = text.replace("\\_", "_")
    text = text.replace("\\*", "*")
    text = re.sub(r"\s+", " ", text).strip()
    return text


def remove_code_blocks(markdown_text):
    if not markdown_text:
        return ""
    text = re.sub(r"```mermaid\s*.*?```", "", markdown_text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    return text.strip()


PLAYBOOK_CATEGORY_PATTERNS = [
    "short-term actions", "long-term actions", "validation checks", "logs/tools to check",
    "logs and tools to check", "tools/logs to check", "assess severity", "root cause analysis",
    "root cause analysis summary", "recommendations", "steps to restore systems",
    "steps to remove root cause", "initial triage", "evidence collection",
    "affected assets", "possible mitre", "mitre attack", "containment actions",
    "eradication actions", "recovery actions", "lessons learned"
]


def is_category_line(text):
    cleaned = clean_inline_markdown(text).strip().lower().rstrip(":")
    if not cleaned:
        return False
    if text.strip().endswith(":") and len(cleaned.split()) <= 7:
        return True
    return any(pattern in cleaned for pattern in PLAYBOOK_CATEGORY_PATTERNS)


def add_playbook_markdown(story, markdown_text, styles, no_playbook_text):
    if not markdown_text:
        story.append(Paragraph(no_playbook_text, styles["NormalWrap"]))
        return

    text = remove_code_blocks(markdown_text)
    if not text:
        text = html_to_plain_text(markdown_text)

    pending_paragraph = []

    def flush_paragraph():
        if pending_paragraph:
            paragraph_text = clean_inline_markdown(" ".join(pending_paragraph))
            if paragraph_text:
                story.append(Paragraph(escape_pdf_text(paragraph_text), styles["NormalWrap"]))
                story.append(Spacer(1, 0.04 * cm))
            pending_paragraph.clear()

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            flush_paragraph()
            continue

        heading_match = re.match(r"^(#{1,6})\s+(.+)$", line)
        numbered_heading_match = re.match(r"^([1-5])\.\s+(.+)$", line)

        if heading_match:
            flush_paragraph()
            heading_text = clean_inline_markdown(heading_match.group(2))
            story.append(Spacer(1, 0.06 * cm))
            story.append(Paragraph(escape_pdf_text(heading_text), styles["PlaybookPhase"]))
            continue

        if numbered_heading_match:
            flush_paragraph()
            heading_text = clean_inline_markdown(line)
            story.append(Spacer(1, 0.06 * cm))
            story.append(Paragraph(escape_pdf_text(heading_text), styles["PlaybookPhase"]))
            continue

        bullet_match = re.match(r"^[\*\-•]\s+(.+)$", line)
        if bullet_match:
            flush_paragraph()
            bullet_text = clean_inline_markdown(bullet_match.group(1))
            if not bullet_text:
                continue
            if is_category_line(bullet_text):
                story.append(Paragraph(escape_pdf_text(bullet_text), styles["CategoryBullet"], bulletText="•"))
            else:
                story.append(Paragraph(escape_pdf_text(bullet_text), styles["ActionLine"]))
            continue

        line = re.sub(r"^\*+\s*", "", line).strip()
        if line:
            if is_category_line(line):
                flush_paragraph()
                story.append(Paragraph(escape_pdf_text(clean_inline_markdown(line)), styles["CategoryBullet"], bulletText="•"))
            else:
                pending_paragraph.append(line)

    flush_paragraph()


def build_pdf_report(analysis_id):
    row = get_analysis_by_id(analysis_id)
    if not row:
        return None

    iocs = json.loads(row["iocs_json"] or "[]")
    mitre = json.loads(row["mitre_json"] or "[]")
    language = row_get(row, "language", "en") or "en"
    text = labels(language)
    base_font, bold_font = setup_pdf_fonts()

    pdf_path = os.path.join(OUTPUT_DIR, f"soc_playbook_report_{analysis_id}.pdf")

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        rightMargin=1.25 * cm,
        leftMargin=1.25 * cm,
        topMargin=1.3 * cm,
        bottomMargin=1.3 * cm,
    )

    styles = getSampleStyleSheet()
    for style_name in styles.byName:
        styles[style_name].fontName = base_font
    styles["Title"].fontName = bold_font
    styles.add(ParagraphStyle(name="Small", fontName=base_font, fontSize=7.5, leading=9.2, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="TableHeaderSmall", fontName=bold_font, fontSize=7.3, leading=8.7, textColor=colors.white, alignment=1, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="SectionTitle", fontName=bold_font, fontSize=14, leading=18, spaceAfter=8, spaceBefore=10, textColor=colors.HexColor("#0B3D91")))
    styles.add(ParagraphStyle(name="NormalWrap", fontName=base_font, fontSize=9.2, leading=12.2, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="PlaybookPhase", fontName=bold_font, fontSize=10.4, leading=13, spaceBefore=7, spaceAfter=4, textColor=colors.HexColor("#111111")))
    styles.add(ParagraphStyle(name="BulletClean", parent=styles["NormalWrap"], leftIndent=14, firstLineIndent=0, bulletIndent=4, spaceAfter=2))
    styles.add(ParagraphStyle(name="CategoryBullet", parent=styles["NormalWrap"], fontName=bold_font, leftIndent=14, firstLineIndent=0, bulletIndent=4, spaceBefore=3, spaceAfter=2))
    styles.add(ParagraphStyle(name="ActionLine", parent=styles["NormalWrap"], leftIndent=20, firstLineIndent=0, spaceAfter=2))
    styles.add(ParagraphStyle(name="CodeBlock", fontName=base_font, fontSize=7.2, leading=8.6, wordWrap="CJK"))

    story = []
    story.append(Paragraph(text["title"], styles["Title"]))
    story.append(Spacer(1, 0.2 * cm))

    meta = [
        ["Report ID", str(row["id"])],
        ["Created At", row["created_at"]],
        ["Severity", row["severity"] or "Unknown"],
        ["Severity Confidence", row["severity_confidence"] or "Low"],
    ]
    table = Table(meta, colWidths=[4 * cm, 12.7 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eeeeee")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTNAME", (0, 0), (0, -1), bold_font),
        ("FONTNAME", (1, 0), (1, -1), base_font),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(table)

    story.append(Paragraph(text["scenario"], styles["SectionTitle"]))
    story.append(Paragraph(escape_pdf_text(row["scenario"]).replace("\n", "<br/>")[:5000], styles["NormalWrap"]))

    story.append(Paragraph(text["summary"], styles["SectionTitle"]))
    story.append(Paragraph(f"<b>Severity:</b> {escape_pdf_text(row['severity'])} | <b>Confidence:</b> {escape_pdf_text(row['severity_confidence'])}", styles["NormalWrap"]))
    story.append(Paragraph(f"<b>{text['rationale']}:</b> {escape_pdf_text(row['severity_rationale'])}", styles["NormalWrap"]))
    story.append(Paragraph(f"<b>{text['ioc_context']}:</b> {escape_pdf_text(row['ioc_context_note'])}", styles["NormalWrap"]))

    story.append(Paragraph(text["iocs"], styles["SectionTitle"]))
    if iocs:
        data = [[
            Paragraph("IOC", styles["TableHeaderSmall"]),
            Paragraph("Type", styles["TableHeaderSmall"]),
            Paragraph("Verdict", styles["TableHeaderSmall"]),
            Paragraph("Confidence", styles["TableHeaderSmall"]),
            Paragraph("Sources", styles["TableHeaderSmall"]),
            Paragraph(text["summary_col"], styles["TableHeaderSmall"]),
        ]]
        for ioc in iocs:
            checked_count = len(ioc.get("sources_checked") or [])
            malicious_count = ioc.get("malicious_sources", 0)
            sources_value = f"{malicious_count}/{checked_count}" if checked_count else str(malicious_count)
            data.append([
                Paragraph(escape_pdf_text(ioc.get("value", "-")), styles["Small"]),
                Paragraph(escape_pdf_text(ioc.get("type", "-")), styles["Small"]),
                Paragraph(escape_pdf_text(ioc.get("verdict", "-")), styles["Small"]),
                Paragraph(escape_pdf_text(ioc.get("confidence", "-")), styles["Small"]),
                Paragraph(escape_pdf_text(sources_value), styles["Small"]),
                Paragraph(escape_pdf_text(ioc.get("display_summary", ioc.get("summary", "-"))), styles["Small"]),
            ])
        t = Table(data, colWidths=[4.6 * cm, 1.8 * cm, 2.5 * cm, 2.0 * cm, 1.35 * cm, 4.45 * cm], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTNAME", (0, 0), (-1, -1), base_font),
            ("FONTNAME", (0, 0), (-1, 0), bold_font),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
    else:
        story.append(Paragraph(text["no_iocs"], styles["NormalWrap"]))

    story.append(Paragraph(text["mitre"], styles["SectionTitle"]))
    if mitre:
        data = [[
            Paragraph("ID", styles["TableHeaderSmall"]),
            Paragraph("Technique", styles["TableHeaderSmall"]),
            Paragraph("Tactic", styles["TableHeaderSmall"]),
            Paragraph("Confidence", styles["TableHeaderSmall"]),
            Paragraph(text["evidence"], styles["TableHeaderSmall"]),
        ]]
        for item in mitre:
            data.append([
                Paragraph(escape_pdf_text(item.get("technique_id", "-")), styles["Small"]),
                Paragraph(escape_pdf_text(item.get("technique_name", "-")), styles["Small"]),
                Paragraph(escape_pdf_text(item.get("tactic", "-")), styles["Small"]),
                Paragraph(escape_pdf_text(item.get("confidence", "-")), styles["Small"]),
                Paragraph(escape_pdf_text(item.get("evidence", "-")), styles["Small"]),
            ])
        t = Table(data, colWidths=[1.6 * cm, 4.1 * cm, 3.0 * cm, 2.0 * cm, 6.0 * cm], repeatRows=1)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111111")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTNAME", (0, 0), (-1, -1), base_font),
            ("FONTNAME", (0, 0), (-1, 0), bold_font),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
    else:
        story.append(Paragraph(text["no_mitre"], styles["NormalWrap"]))

    story.append(Paragraph(text["playbook"], styles["SectionTitle"]))
    add_playbook_markdown(
        story,
        row["playbook_markdown"] or html_to_plain_text(row["playbook_html"] or ""),
        styles,
        text["no_playbook"],
    )

    if row["mermaid_code"]:
        story.append(PageBreak())
        story.append(Paragraph(text["appendix"], styles["SectionTitle"]))
        story.append(Preformatted(row["mermaid_code"], styles["CodeBlock"]))

    doc.build(story)
    return pdf_path
