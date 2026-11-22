"""Builds a PDF investigation report with ReportLab.

Security notes:
- Every piece of email-derived text is escaped before it goes into a PDF
  paragraph, because ReportLab paragraphs interpret <b>, <a href=...> and similar
  markup. Without escaping, a hostile subject line could inject markup.
- URLs, domains and IPs are shown defanged (hxxp, [.]).
- The email body is deliberately NOT included. The report holds metadata and
  evidence only, so sharing it leaks less.
- Nothing is fetched or opened. The report only formats data already extracted.
"""

from datetime import datetime, timezone
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from triage.extractors import defang

MAX_FIELD_CHARS = 300   # long strings are cut so one hostile field cannot wreck the layout
MAX_ROWS = 100          # same idea for long lists

LEVEL_COLORS = {
    "Low": colors.HexColor("#2e7d32"),
    "Medium": colors.HexColor("#ef8f00"),
    "High": colors.HexColor("#c62828"),
}

ACTIONS = {
    "High": [
        "Do not click any links or open any attachments in this message.",
        "Quarantine or delete the message from the recipient's mailbox.",
        "Report it to the security team and keep the original .eml as evidence.",
        "Block the sender address, sender domain and listed URLs or IPs at the email gateway and web proxy.",
        "Search other mailboxes for the same sender, URLs or attachment hashes.",
        "If anyone clicked a link or opened an attachment, treat the account as compromised: reset credentials and escalate.",
    ],
    "Medium": [
        "Do not act on the message until the sender is verified through a separate, known channel (phone or a saved contact).",
        "Hold the message and ask a security analyst to review the evidence listed below.",
        "Check whether similar messages were sent to other users.",
        "Escalate to High handling if verification fails.",
    ],
    "Low": [
        "No strong indicators were found by the automated rules.",
        "Still confirm any unexpected request for payment, credentials or sensitive data with the sender.",
        "A Low score does not prove the message is safe; some attacks use no technical indicators.",
    ],
}


def _safe(value, limit=MAX_FIELD_CHARS):
    """Escape for ReportLab markup, cut to length, and drop characters the PDF font cannot draw."""
    text = str(value if value is not None else "")
    if len(text) > limit:
        text = text[:limit] + "..."
    text = text.encode("latin-1", "replace").decode("latin-1")
    return escape(text)


def _cell(value, style, limit=MAX_FIELD_CHARS):
    return Paragraph(_safe(value, limit), style)


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", parent=base["Title"], fontSize=20, spaceAfter=4),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=13, spaceBefore=12, spaceAfter=6),
        "body": ParagraphStyle("body", parent=base["BodyText"], fontSize=9.5, leading=12.5),
        "small": ParagraphStyle("small", parent=base["BodyText"], fontSize=8.5, leading=11),
        "mono": ParagraphStyle("mono", parent=base["BodyText"], fontName="Courier", fontSize=8, leading=10),
        "note": ParagraphStyle("note", parent=base["BodyText"], fontSize=8.5, leading=11,
                               textColor=colors.HexColor("#555555")),
    }


def _table(rows, widths, header=True):
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#bbbbbb")),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee")))
    table.setStyle(TableStyle(style))
    return table


def _more_note(items, st):
    if len(items) > MAX_ROWS:
        return [Paragraph(f"Showing first {MAX_ROWS} of {len(items)} items.", st["note"])]
    return []


def build_report(email, detection, assessment, generated_at=None):
    """Return the PDF as bytes. Takes the three objects the pipeline already produces."""
    st = _styles()
    when = generated_at or datetime.now(timezone.utc)
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter, leftMargin=0.7 * inch, rightMargin=0.7 * inch,
        topMargin=0.7 * inch, bottomMargin=0.7 * inch,
        title="Phishing Email Investigation Report", author="Phishing Triage Bot",
    )
    story = []

    # --- Title and summary ---
    story.append(Paragraph("Phishing Email Investigation Report", st["title"]))
    story.append(Paragraph(f"Generated {when.strftime('%Y-%m-%d %H:%M UTC')} by Phishing Triage Bot", st["note"]))
    story.append(Spacer(1, 10))

    level_color = LEVEL_COLORS.get(assessment.level, colors.black)
    verdict = Table(
        [[Paragraph(f"<font color='white' size='20'><b>{assessment.score}/100</b></font>", st["body"]),
          Paragraph(f"<font color='white' size='16'><b>{_safe(assessment.level)} risk</b></font>", st["body"])]],
        colWidths=[1.6 * inch, 5.4 * inch],
    )
    verdict.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), level_color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(verdict)
    story.append(Spacer(1, 6))
    story.append(Paragraph(_safe(assessment.disclaimer, 1000), st["body"]))

    top = assessment.top_contributions(3)
    if top:
        story.append(Paragraph("Main reasons for this score", st["h2"]))
        for item in top:
            story.append(Paragraph(f"&bull; {_safe(item.description)} (+{item.counted})", st["body"]))
    else:
        story.append(Paragraph("No detection rules fired.", st["body"]))

    # --- Email details ---
    story.append(Paragraph("Email details", st["h2"]))
    sender = f"{email.sender_display_name} <{email.sender_address}>" if email.sender_display_name else email.sender_address
    details = [
        ("From", sender),
        ("Reply-To", email.reply_to_address or "(none)"),
        ("Return-Path", email.return_path or "(none)"),
        ("To", ", ".join(email.recipients) or "(none)"),
        ("Subject", email.subject or "(none)"),
        ("Date header", email.date_raw or "(none)"),
        ("Message-ID", email.message_id or "(none)"),
    ]
    story.append(_table([[_cell(k, st["small"]), _cell(v, st["small"])] for k, v in details],
                        [1.3 * inch, 5.7 * inch], header=False))
    if email.parse_warnings:
        story.append(Paragraph("Parsing warnings: " + _safe("; ".join(email.parse_warnings), 600), st["note"]))

    # --- Authentication ---
    auth = detection.auth
    story.append(Paragraph("Authentication results (read from headers, not verified through DNS)", st["h2"]))
    auth_rows = [
        [_cell("Check", st["small"]), _cell("Result", st["small"]), _cell("Domain", st["small"])],
        [_cell("SPF", st["small"]), _cell(auth.spf, st["small"]), _cell(auth.spf_domain or "-", st["small"])],
        [_cell("DKIM", st["small"]), _cell(auth.dkim, st["small"]), _cell(auth.dkim_domain or "-", st["small"])],
        [_cell("DMARC", st["small"]), _cell(auth.dmarc, st["small"]), _cell(auth.dmarc_domain or "-", st["small"])],
    ]
    story.append(_table(auth_rows, [1.3 * inch, 2.0 * inch, 3.7 * inch]))
    for note in auth.notes:
        story.append(Paragraph(_safe(note, 400), st["note"]))

    # --- Score breakdown ---
    story.append(Paragraph("Score breakdown and evidence", st["h2"]))
    if assessment.contributions:
        ordered = sorted(assessment.contributions, key=lambda c: c.counted, reverse=True)[:MAX_ROWS]
        rows = [[_cell("Rule", st["small"]), _cell("Points", st["small"]), _cell("What was found", st["small"])]]
        for item in ordered:
            text = f"<b>{_safe(item.description)}</b><br/>Evidence: {_safe(item.evidence)}"
            if item.note:
                text += f"<br/><i>{_safe(item.note)}</i>"
            rows.append([
                Paragraph(_safe(item.rule_id), st["mono"]),
                Paragraph(f"{item.counted} / {item.weight}", st["small"]),
                Paragraph(text, st["small"]),
            ])
        story.append(_table(rows, [2.2 * inch, 0.7 * inch, 4.1 * inch]))
        story.extend(_more_note(assessment.contributions, st))
        story.append(Paragraph("Points shown as counted / full weight. Related rules share a cap so one problem is not counted twice.", st["note"]))
    else:
        story.append(Paragraph("No findings.", st["body"]))

    # --- IOCs ---
    iocs = detection.iocs
    story.append(Paragraph("Indicators of compromise (defanged)", st["h2"]))
    ioc_groups = [
        ("URLs", [defang(u) for u in iocs.urls]),
        ("Domains", [defang(d) for d in iocs.domains]),
        ("IP addresses", [defang(i) for i in iocs.ips]),
        ("Email addresses", list(iocs.email_addresses)),
    ]
    ioc_rows = []
    for label, values in ioc_groups:
        shown = values[:MAX_ROWS]
        text = "<br/>".join(_safe(v) for v in shown) if shown else "(none)"
        if len(values) > MAX_ROWS:
            text += f"<br/>(+{len(values) - MAX_ROWS} more)"
        ioc_rows.append([Paragraph(label, st["small"]), Paragraph(text, st["mono"])])
    story.append(_table(ioc_rows, [1.3 * inch, 5.7 * inch], header=False))

    # --- Attachments ---
    story.append(Paragraph("Attachments (never opened or executed)", st["h2"]))
    if email.attachments:
        rows = [[_cell("File name", st["small"]), _cell("Type", st["small"]),
                 _cell("Size", st["small"]), _cell("SHA-256", st["small"])]]
        for att in email.attachments[:MAX_ROWS]:
            rows.append([
                _cell(att.filename, st["small"]), _cell(att.content_type, st["small"]),
                _cell(f"{att.size_bytes} bytes", st["small"]), Paragraph(_safe(att.sha256), st["mono"]),
            ])
        story.append(_table(rows, [1.6 * inch, 1.2 * inch, 0.8 * inch, 3.4 * inch]))
        story.extend(_more_note(email.attachments, st))
    else:
        story.append(Paragraph("No attachments.", st["body"]))

    # --- Actions and method ---
    story.append(Paragraph(f"Recommended actions ({_safe(assessment.level)} risk)", st["h2"]))
    for action in ACTIONS.get(assessment.level, ACTIONS["Medium"]):
        story.append(Paragraph(f"&bull; {_safe(action, 500)}", st["body"]))

    story.append(Paragraph("Method and limits", st["h2"]))
    story.append(Paragraph(
        "The score comes from transparent rules with fixed weights. It was produced without opening "
        "links or attachments and without sending any email content to an external service. "
        "Rules can miss attacks that use no technical indicators and can flag legitimate mail. "
        "This report is a triage aid, not proof. A human analyst should confirm before taking action.",
        st["body"]))

    doc.build(story)
    return buffer.getvalue()


if __name__ == "__main__":
    import sys
    from pathlib import Path

    from triage.engine import run_all_detectors
    from triage.parser import parse_eml_file
    from triage.scorer import score_findings

    if len(sys.argv) != 3:
        print("Usage: python -m triage.report <input.eml> <output.pdf>")
        sys.exit(1)

    parsed = parse_eml_file(sys.argv[1])
    detected = run_all_detectors(parsed)
    assessed = score_findings(detected.findings)
    out_path = Path(sys.argv[2])
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(build_report(parsed, detected, assessed))
    print(f"Wrote {out_path} ({out_path.stat().st_size} bytes)")

    