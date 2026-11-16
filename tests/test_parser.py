"""Tests for triage/parser.py. All emails here are synthetic."""

import pytest

from triage.parser import MAX_EMAIL_BYTES, EmailParseError, parse_eml

SIMPLE_EMAIL = (
    b'From: "Alice Example" <alice@example.com>\r\n'
    b"To: bob@example.com\r\n"
    b"Subject: Hello\r\n"
    b"Date: Mon, 16 Nov 2026 09:15:00 -0700\r\n"
    b"\r\n"
    b"Plain body text.\r\n"
)

EMAIL_WITH_ATTACHMENT = (
    b"From: sender@example.com\r\n"
    b"To: bob@example.com\r\n"
    b"Subject: Invoice\r\n"
    b"Date: Mon, 16 Nov 2026 09:15:00 -0700\r\n"
    b"MIME-Version: 1.0\r\n"
    b'Content-Type: multipart/mixed; boundary="B"\r\n'
    b"\r\n"
    b"--B\r\n"
    b'Content-Type: text/plain; charset="utf-8"\r\n'
    b"\r\n"
    b"See attached.\r\n"
    b"--B\r\n"
    b'Content-Type: application/octet-stream; name="invoice.pdf.exe"\r\n'
    b'Content-Disposition: attachment; filename="invoice.pdf.exe"\r\n'
    b"Content-Transfer-Encoding: base64\r\n"
    b"\r\n"
    b"SGVsbG8gd29ybGQ=\r\n"
    b"--B--\r\n"
)


def test_parses_basic_fields():
    email = parse_eml(SIMPLE_EMAIL)
    assert email.sender_display_name == "Alice Example"
    assert email.sender_address == "alice@example.com"
    assert email.recipients == ["bob@example.com"]
    assert email.subject == "Hello"
    assert "Plain body text." in email.body_text
    assert email.parse_warnings == []


def test_sender_address_is_lowercased():
    raw = b"From: Alice <ALICE@Example.COM>\r\nTo: b@example.com\r\nSubject: x\r\nDate: d\r\n\r\nhi\r\n"
    assert parse_eml(raw).sender_address == "alice@example.com"


def test_encoded_display_name_is_decoded():
    raw = b"From: =?utf-8?B?Q2Fmw6k=?= <cafe@example.com>\r\nTo: b@example.com\r\nSubject: x\r\nDate: d\r\n\r\nhi\r\n"
    assert parse_eml(raw).sender_display_name == "Café"


def test_attachment_metadata_extracted_not_executed():
    email = parse_eml(EMAIL_WITH_ATTACHMENT)
    assert len(email.attachments) == 1
    attachment = email.attachments[0]
    assert attachment.filename == "invoice.pdf.exe"
    assert attachment.size_bytes == 11  # b"Hello world"
    assert len(attachment.sha256) == 64


def test_plain_email_has_no_attachments():
    assert parse_eml(SIMPLE_EMAIL).attachments == []


def test_empty_input_raises():
    with pytest.raises(EmailParseError):
        parse_eml(b"")


def test_oversized_input_rejected():
    with pytest.raises(EmailParseError):
        parse_eml(b"A" * (MAX_EMAIL_BYTES + 1))


def test_garbage_input_returns_warnings_instead_of_crashing():
    email = parse_eml(b"this is not an email at all")
    assert email.sender_address == ""
    assert any("From" in w for w in email.parse_warnings)