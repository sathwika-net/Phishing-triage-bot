"""Tests for triage/content_checks.py. All data here is synthetic."""

from triage.content_checks import check_attachments, check_language
from triage.models import AttachmentInfo, ParsedEmail


def ids(findings):
    return {finding.rule_id for finding in findings}


def attachment(name, content_type="application/octet-stream", size=10):
    return AttachmentInfo(filename=name, content_type=content_type, size_bytes=size, sha256="0" * 64)


def email_with_attachments(*names):
    return ParsedEmail(attachments=[attachment(name) for name in names])


# ---------------------------------------------------------------------------
# Language checks
# ---------------------------------------------------------------------------

def test_two_urgency_phrases_are_flagged():
    email = ParsedEmail(body_text="This is urgent. Your account will be suspended.")
    assert "LANG_URGENCY" in ids(check_language(email))


def test_a_single_urgency_phrase_is_not_flagged():
    email = ParsedEmail(body_text="Please reply immediately if you have any questions.")
    assert "LANG_URGENCY" not in ids(check_language(email))


def test_credential_request_is_flagged():
    email = ParsedEmail(body_text="Please verify your account and confirm your password.")
    assert "LANG_CREDENTIAL_REQUEST" in ids(check_language(email))


def test_normal_business_email_is_not_flagged():
    email = ParsedEmail(
        subject="Agenda for Thursday",
        body_text="Hi Bob, attached is the agenda for Thursday's meeting. Thanks, Alex",
    )
    assert check_language(email) == []


def test_generic_greeting_is_flagged():
    assert "LANG_GENERIC_GREETING" in ids(check_language(ParsedEmail(body_text="Dear customer, hello")))


def test_prize_and_gift_card_lures_are_flagged():
    email = ParsedEmail(body_text="Congratulations, you have won! Pay the fee with a gift card.")
    assert "LANG_MONEY_OR_PRIZE_LURE" in ids(check_language(email))


def test_subject_line_is_analysed_too():
    email = ParsedEmail(subject="Final notice: act now")
    assert "LANG_URGENCY" in ids(check_language(email))


def test_visible_html_text_is_analysed():
    email = ParsedEmail(body_html="<p>Please <b>verify your account</b> today</p>")
    assert "LANG_CREDENTIAL_REQUEST" in ids(check_language(email))


def test_evidence_shows_the_matched_phrases():
    email = ParsedEmail(body_text="Please verify your account.")
    finding = check_language(email)[0]
    assert "verify your account" in finding.evidence


def test_empty_email_gives_no_language_findings():
    assert check_language(ParsedEmail()) == []


def test_huge_message_is_handled_quickly_and_safely():
    assert check_language(ParsedEmail(body_text="a" * 500_000)) == []


# ---------------------------------------------------------------------------
# Attachment checks
# ---------------------------------------------------------------------------

def test_executable_attachment_is_flagged():
    assert "ATTACHMENT_EXECUTABLE" in ids(check_attachments(email_with_attachments("setup.exe")))


def test_extension_check_ignores_case():
    assert "ATTACHMENT_EXECUTABLE" in ids(check_attachments(email_with_attachments("SETUP.EXE")))


def test_plain_pdf_is_not_flagged():
    assert check_attachments(email_with_attachments("report.pdf")) == []


def test_file_without_extension_is_not_flagged():
    assert check_attachments(email_with_attachments("README")) == []


def test_no_attachments_gives_no_findings():
    assert check_attachments(ParsedEmail()) == []


def test_double_extension_is_flagged_along_with_executable():
    found = ids(check_attachments(email_with_attachments("invoice.pdf.exe")))
    assert {"ATTACHMENT_DOUBLE_EXTENSION", "ATTACHMENT_EXECUTABLE"} <= found


def test_trailing_space_trick_is_still_caught():
    assert "ATTACHMENT_EXECUTABLE" in ids(check_attachments(email_with_attachments("invoice.exe ")))


def test_macro_document_is_flagged():
    assert "ATTACHMENT_MACRO_DOCUMENT" in ids(check_attachments(email_with_attachments("budget.xlsm")))


def test_archive_and_disk_image_are_flagged():
    assert "ATTACHMENT_ARCHIVE" in ids(check_attachments(email_with_attachments("files.zip")))
    assert "ATTACHMENT_ARCHIVE" in ids(check_attachments(email_with_attachments("setup.iso")))


def test_html_attachment_is_flagged():
    assert "ATTACHMENT_HTML" in ids(check_attachments(email_with_attachments("login.html")))


def test_hidden_direction_characters_are_flagged():
    found = ids(check_attachments(email_with_attachments("invoice\u202egpj.exe")))
    assert "ATTACHMENT_HIDDEN_CHARACTERS" in found


def test_many_attachments_produce_one_summarised_finding():
    findings = check_attachments(email_with_attachments(*[f"tool{i}.exe" for i in range(5)]))
    executable = [f for f in findings if f.rule_id == "ATTACHMENT_EXECUTABLE"]
    assert len(executable) == 1
    assert "more" in executable[0].evidence
    