"""Tests for triage/report.py. All data here is synthetic."""

from reportlab import rl_config

from tests.test_engine import LEGITIMATE_EMAIL, PHISHING_EMAIL
from triage.engine import run_all_detectors
from triage.models import AttachmentInfo, ParsedEmail
from triage.parser import parse_eml
from triage.report import ACTIONS, _safe, build_report
from triage.scorer import score_findings


def make_report(email):
    detection = run_all_detectors(email)
    assessment = score_findings(detection.findings)
    return build_report(email, detection, assessment)


def test_report_is_a_valid_looking_pdf():
    pdf = make_report(parse_eml(PHISHING_EMAIL))
    assert pdf.startswith(b"%PDF")
    assert pdf.rstrip().endswith(b"%%EOF")
    assert len(pdf) > 2000


def test_legitimate_email_report_builds():
    assert make_report(parse_eml(LEGITIMATE_EMAIL)).startswith(b"%PDF")


def test_empty_email_report_builds():
    assert make_report(ParsedEmail()).startswith(b"%PDF")


def test_safe_escapes_markup():
    assert "<" not in _safe("<b>bold</b><a href='x'>y</a>")
    assert "&amp;" in _safe("a & b")


def test_safe_truncates_long_text():
    assert len(_safe("a" * 5000)) < 400


def test_safe_replaces_characters_the_pdf_font_cannot_draw():
    assert _safe("\u202e\u4e2d\u6587") == "???"


def test_hostile_markup_in_fields_does_not_break_the_report():
    email = ParsedEmail(
        sender_display_name="<b>Unclosed <i>tags",
        sender_address="x@example.com",
        subject="<a href='http://evil.example'>click</a> & <font color=red>",
        recipients=["<para>bad@example.com"],
        attachments=[AttachmentInfo("<b>x</b>.exe", "application/<x>", 5, "0" * 64)],
    )
    assert make_report(email).startswith(b"%PDF")


def test_huge_fields_and_many_attachments_still_build():
    email = ParsedEmail(
        subject="s" * 100_000,
        attachments=[AttachmentInfo(f"f{i}.exe", "application/octet-stream", i, "0" * 64) for i in range(300)],
    )
    assert make_report(email).startswith(b"%PDF")


def test_every_risk_level_has_recommended_actions():
    assert set(ACTIONS) == {"Low", "Medium", "High"}
    assert all(ACTIONS[level] for level in ACTIONS)


def test_report_contains_metadata_but_not_the_message_body(monkeypatch):
    monkeypatch.setattr(rl_config, "pageCompression", 0)  # make PDF text searchable in this test
    email = ParsedEmail(subject="Quarterly figures", body_text="BODYSECRETWORDS " * 5)
    pdf = make_report(email)
    assert b"Quarterly figures" in pdf
    assert b"BODYSECRETWORDS" not in pdf


def test_urls_appear_defanged_in_the_report(monkeypatch):
    monkeypatch.setattr(rl_config, "pageCompression", 0)
    pdf = make_report(parse_eml(PHISHING_EMAIL))
    assert b"hxxp://examplebank-verify[.]example/login" in pdf
    assert b"http://examplebank-verify.example/login" not in pdf

    