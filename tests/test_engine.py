"""End-to-end tests: raw .eml bytes -> parser -> every detector. All data is synthetic."""

from triage.engine import run_all_detectors
from triage.models import ParsedEmail
from triage.parser import parse_eml

PHISHING_EMAIL = (
    b"Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=examplebank-verify.example; "
    b"dkim=none; dmarc=fail header.from=examplebank-verify.example\r\n"
    b'From: "ExampleBank Support" <security@examplebank-verify.example>\r\n'
    b"To: victim@example.com\r\n"
    b"Reply-To: collect@mailbox-drop.example\r\n"
    b"Subject: Urgent: Verify your account now\r\n"
    b"Date: Mon, 16 Nov 2026 09:15:00 -0700\r\n"
    b"MIME-Version: 1.0\r\n"
    b'Content-Type: multipart/mixed; boundary="B"\r\n'
    b"\r\n"
    b"--B\r\n"
    b'Content-Type: text/plain; charset="utf-8"\r\n'
    b"\r\n"
    b"Your account is suspended. Verify now: http://examplebank-verify.example/login\r\n"
    b"--B\r\n"
    b'Content-Type: application/octet-stream; name="invoice.pdf.exe"\r\n'
    b'Content-Disposition: attachment; filename="invoice.pdf.exe"\r\n'
    b"Content-Transfer-Encoding: base64\r\n"
    b"\r\n"
    b"SGVsbG8gd29ybGQ=\r\n"
    b"--B--\r\n"
)

LEGITIMATE_EMAIL = (
    b"Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=company.example; "
    b"dkim=pass header.d=company.example; dmarc=pass header.from=company.example\r\n"
    b'From: "Alex Chen" <alex@company.example>\r\n'
    b"To: bob@company.example\r\n"
    b"Subject: Agenda for Thursday\r\n"
    b"Date: Mon, 16 Nov 2026 09:15:00 -0700\r\n"
    b"\r\n"
    b"Hi Bob, here is the agenda for Thursday's meeting. Thanks, Alex\r\n"
)


def test_phishing_email_triggers_rules_in_every_category():
    result = run_all_detectors(parse_eml(PHISHING_EMAIL))
    found = {finding.rule_id for finding in result.findings}
    assert {
        "SENDER_BRAND_IMPERSONATION",
        "SENDER_LOOKALIKE_DOMAIN",
        "REPLY_TO_MISMATCH",
        "SPF_FAIL",
        "DMARC_FAIL",
        "URL_LOOKALIKE_DOMAIN",
        "LANG_URGENCY",
        "LANG_CREDENTIAL_REQUEST",
        "ATTACHMENT_EXECUTABLE",
        "ATTACHMENT_DOUBLE_EXTENSION",
    } <= found


def test_result_carries_iocs_and_authentication_results():
    result = run_all_detectors(parse_eml(PHISHING_EMAIL))
    assert result.iocs.urls == ["http://examplebank-verify.example/login"]
    assert result.auth.spf == "fail"


def test_legitimate_email_produces_no_findings():
    result = run_all_detectors(parse_eml(LEGITIMATE_EMAIL))
    assert result.findings == []


def test_empty_email_runs_without_crashing():
    result = run_all_detectors(ParsedEmail())
    assert {finding.rule_id for finding in result.findings} == {"AUTH_RESULTS_MISSING"}

    