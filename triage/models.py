"""Data models shared by every module in the triage pipeline.

Dataclasses are plain containers for data. Keeping them in one file means the
parser, detectors, scorer, report generator and UI all agree on the same shape.
"""

from dataclasses import dataclass, field


@dataclass
class AttachmentInfo:
    """Metadata about one attachment. We NEVER save or run the file itself."""

    filename: str
    content_type: str
    size_bytes: int
    sha256: str  # hash of the file bytes: a standard IOC analysts search for


@dataclass
class ParsedEmail:
    """Everything we pull out of an .eml file, as simple strings and lists."""

    sender_display_name: str = ""   # the friendly name, e.g. "ExampleBank Support"
    sender_address: str = ""        # the real address, e.g. security@example.com
    reply_to_address: str = ""
    return_path: str = ""
    recipients: list[str] = field(default_factory=list)
    subject: str = ""
    date_raw: str = ""              # kept as text; dates in phishing are often odd
    message_id: str = ""
    body_text: str = ""
    body_html: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)  # (name, value), order kept
    attachments: list[AttachmentInfo] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)       # problems found while parsing


@dataclass
class Finding:
    """One piece of evidence produced by a detector (used from Module 4 onward)."""

    rule_id: str       # stable ID, e.g. "SENDER_DISPLAY_MISMATCH"
    category: str      # e.g. "sender", "url", "language", "attachment", "auth"
    description: str   # human-readable explanation
    evidence: str      # the exact data that triggered the rule