"""Safe .eml parser.

Security stance: the email is UNTRUSTED input. We only read it as data.
We never open URLs, never write attachments to disk, never execute anything.
"""

import hashlib
import re
import sys
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from pathlib import Path

from triage.models import AttachmentInfo, ParsedEmail

# Refuse absurdly large files so a hostile upload cannot exhaust memory.
MAX_EMAIL_BYTES = 10 * 1024 * 1024  # 10 MB

# Control characters have no business in a filename; strip them before display.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class EmailParseError(Exception):
    """Raised when the input cannot be treated as an email at all."""


def _header(msg: Message, name: str) -> str:
    """Return a header value as clean text, or '' if missing/unreadable."""
    try:
        value = msg.get(name)
        return str(value).strip() if value is not None else ""
    except Exception:
        return ""


def _address_only(header_value: str) -> str:
    """'Name <a@b.com>' -> 'a@b.com' (lowercased)."""
    return parseaddr(header_value)[1].strip().lower()


def _body(msg: Message, kind: str) -> str:
    """Get the 'plain' or 'html' body, tolerating bad encodings."""
    try:
        part = msg.get_body(preferencelist=(kind,))
    except Exception:
        return ""
    if part is None:
        return ""
    try:
        return str(part.get_content()).strip()
    except Exception:
        # Unknown charset or broken encoding: decode manually, replacing bad bytes.
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace").strip()


def _attachments(msg: Message) -> list[AttachmentInfo]:
    """List attachments as metadata only. File bytes are hashed in memory, never saved."""
    found: list[AttachmentInfo] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        try:
            filename = part.get_filename()
            disposition = part.get_content_disposition()
        except Exception:
            continue
        if not filename and disposition != "attachment":
            continue  # an ordinary body part, not an attachment
        data = part.get_payload(decode=True) or b""
        safe_name = _CONTROL_CHARS.sub("", filename or "(no filename)")[:255]
        found.append(
            AttachmentInfo(
                filename=safe_name,
                content_type=part.get_content_type(),
                size_bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
            )
        )
    return found


def parse_eml(raw: bytes) -> ParsedEmail:
    """Turn raw .eml bytes into a ParsedEmail. Raises EmailParseError only for unusable input."""
    if not isinstance(raw, (bytes, bytearray)):
        raise EmailParseError("Input must be bytes.")
    if len(raw) == 0:
        raise EmailParseError("The file is empty.")
    if len(raw) > MAX_EMAIL_BYTES:
        raise EmailParseError(f"File is larger than the {MAX_EMAIL_BYTES // (1024 * 1024)} MB limit.")

    try:
        msg = BytesParser(policy=policy.default).parsebytes(bytes(raw))
    except Exception as exc:  # the parser is tolerant, but never trust that completely
        raise EmailParseError(f"Could not parse the file as an email: {exc}") from exc

    from_header = _header(msg, "From")
    display_name, address = parseaddr(from_header)

    recipient_values = [str(v) for v in (msg.get_all("To") or []) + (msg.get_all("Cc") or [])]
    recipients = [addr.lower() for _, addr in getaddresses(recipient_values) if addr]

    headers: list[tuple[str, str]] = []
    for name, value in msg.items():
        try:
            headers.append((name, str(value)))
        except Exception:
            headers.append((name, "<unreadable header value>"))

    parsed = ParsedEmail(
        sender_display_name=display_name.strip(),
        sender_address=address.strip().lower(),
        reply_to_address=_address_only(_header(msg, "Reply-To")),
        return_path=_address_only(_header(msg, "Return-Path")),
        recipients=recipients,
        subject=_header(msg, "Subject"),
        date_raw=_header(msg, "Date"),
        message_id=_header(msg, "Message-ID"),
        body_text=_body(msg, "plain"),
        body_html=_body(msg, "html"),
        headers=headers,
        attachments=_attachments(msg),
    )

    # Record problems instead of crashing: analysts still want a partial result.
    warnings = parsed.parse_warnings
    if not parsed.sender_address:
        warnings.append("Missing or unreadable From header.")
    if not parsed.recipients:
        warnings.append("Missing or unreadable To/Cc header.")
    if not parsed.subject:
        warnings.append("Missing Subject header.")
    if not parsed.date_raw:
        warnings.append("Missing Date header.")
    if not parsed.body_text and not parsed.body_html:
        warnings.append("No readable message body found.")
    if msg.defects:
        warnings.append(f"Parser reported {len(msg.defects)} structural defect(s) in the message.")

    return parsed


def parse_eml_file(path: str | Path) -> ParsedEmail:
    """Convenience wrapper for reading an .eml file from disk (checks size before reading)."""
    file_path = Path(path)
    if not file_path.is_file():
        raise EmailParseError(f"File not found: {file_path}")
    if file_path.stat().st_size > MAX_EMAIL_BYTES:
        raise EmailParseError("File is larger than the size limit.")
    return parse_eml(file_path.read_bytes())


if __name__ == "__main__":
    # Quick manual check:  python -m triage.parser samples\quick_test.eml
    if len(sys.argv) != 2:
        print("Usage: python -m triage.parser <path-to-.eml>")
        raise SystemExit(1)
    email = parse_eml_file(sys.argv[1])
    print("Sender name   :", email.sender_display_name)
    print("Sender address:", email.sender_address)
    print("Reply-To      :", email.reply_to_address)
    print("To            :", email.recipients)
    print("Subject       :", email.subject)
    print("Date          :", email.date_raw)
    print("Body (start)  :", email.body_text[:100])
    print("Attachments   :", [(a.filename, a.content_type, a.size_bytes) for a in email.attachments])
    print("Headers parsed:", len(email.headers))
    print("Warnings      :", email.parse_warnings or "none")