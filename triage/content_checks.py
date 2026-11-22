"""Content checks: suspicious language and risky attachments.

Like the other detectors, these return Finding objects and never assign points.
Attachments are judged by file NAME and type only. We never open or run them.
"""

import re

from triage.extractors import extract_html_links
from triage.models import AttachmentInfo, Finding, ParsedEmail

# Regexes are bounded and we cap the text length, so a hostile email cannot make us hang.
MAX_TEXT_CHARS = 200_000

# ---------------------------------------------------------------------------
# Editable language patterns. They are matched against lowercase text.
# ---------------------------------------------------------------------------

_URGENCY_PATTERNS = [
    r"\burgent(?:ly)?\b",
    r"\bimmediate(?:ly)?\b",
    r"\bact now\b",
    r"\baction required\b",
    r"\bfinal (?:notice|warning|reminder)\b",
    r"\blast (?:chance|warning)\b",
    r"\bwithin (?:24|48|72) hours\b",
    r"\bexpires? (?:today|soon|in)\b",
    r"\b(?:has been|is|will be|been) (?:suspended|closed|locked|disabled|terminated|deactivated)\b",
    r"\bunusual (?:activity|sign[- ]?in)\b",
    r"\bverify now\b",
    r"\bright away\b",
]

_CREDENTIAL_PATTERNS = [
    r"\b(?:enter|provide|confirm|verify|update|send|submit)\b.{0,30}\b(?:password|passcode|pin|credentials|login details)\b",
    r"\b(?:verify|confirm|validate) your (?:account|identity|email|information|details)\b",
    r"\b(?:update|confirm) your (?:payment|billing)\b",
    r"\b(?:social security|social insurance) number\b",
    r"\b(?:credit|debit) card (?:number|details|information)\b|\bcvv\b",
    r"\b(?:log ?in|sign ?in)\b.{0,30}\bto (?:verify|confirm|restore|unlock|secure)\b",
]

_LURE_PATTERNS = [
    r"\byou (?:have )?won\b|\bclaim your (?:prize|reward|gift)\b|\blottery\b|\binheritance\b|\bfree gift\b",
    r"\bgift cards?\b",
    r"\bwire transfer\b",
    r"\b(?:bitcoin|cryptocurrency|western union|moneygram)\b",
]

_GENERIC_GREETING_PATTERNS = [
    r"\bdear (?:valued )?(?:customer|user|member|client|account holder|sir|madam|sir/madam|friend)\b",
]


def _compile(patterns: list[str]) -> list[re.Pattern]:
    return [re.compile(pattern, re.IGNORECASE) for pattern in patterns]


_URGENCY = _compile(_URGENCY_PATTERNS)
_CREDENTIAL = _compile(_CREDENTIAL_PATTERNS)
_LURE = _compile(_LURE_PATTERNS)
_GREETING = _compile(_GENERIC_GREETING_PATTERNS)


def _message_text(email: ParsedEmail) -> str:
    """Subject + plain body + the visible text of the HTML body, lowercased and length-capped."""
    visible_html = extract_html_links(email.body_html)[1]
    return f"{email.subject}\n{email.body_text}\n{visible_html}"[:MAX_TEXT_CHARS].lower()


def _first_matches(patterns: list[re.Pattern], text: str) -> list[str]:
    """The first match of each pattern that matched (so each pattern counts once)."""
    matches = []
    for pattern in patterns:
        found = pattern.search(text)
        if found:
            matches.append(" ".join(found.group(0).split()))
    return matches


def _quoted(items: list[str], limit: int = 5) -> str:
    return ", ".join(f"'{item}'" for item in items[:limit])


# ---------------------------------------------------------------------------
# Language checks
# ---------------------------------------------------------------------------

def check_language(email: ParsedEmail) -> list[Finding]:
    """Look for pressure tactics, requests for secrets, lures and impersonal greetings."""
    text = _message_text(email)
    findings: list[Finding] = []

    credential = _first_matches(_CREDENTIAL, text)
    if credential:
        findings.append(Finding(
            "LANG_CREDENTIAL_REQUEST", "language",
            "The message asks the reader to verify, confirm or provide account or personal details.",
            "Phrases: " + _quoted(credential),
        ))

    # One urgent word is common in normal business email, so we require two different
    # urgency patterns. This is a tuning choice to reduce false positives.
    urgency = _first_matches(_URGENCY, text)
    if len(urgency) >= 2:
        findings.append(Finding(
            "LANG_URGENCY", "language",
            "The message uses several urgency or threat phrases to pressure the reader.",
            "Phrases: " + _quoted(urgency),
        ))

    lure = _first_matches(_LURE, text)
    if lure:
        findings.append(Finding(
            "LANG_MONEY_OR_PRIZE_LURE", "language",
            "The message mentions prizes, gift cards, wire transfers or cryptocurrency.",
            "Phrases: " + _quoted(lure),
        ))

    greeting = _first_matches(_GREETING, text)
    if greeting:
        findings.append(Finding(
            "LANG_GENERIC_GREETING", "language",
            "The message uses an impersonal greeting instead of the recipient's name.",
            "Phrases: " + _quoted(greeting),
        ))

    return findings


# ---------------------------------------------------------------------------
# Attachment checks
# ---------------------------------------------------------------------------

EXECUTABLE_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "msi", "js", "jse", "vbs", "vbe",
    "wsf", "wsh", "ps1", "jar", "hta", "lnk", "cpl", "reg", "dll",
}
MACRO_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xlam"}
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "iso", "img", "gz", "tar"}
HTML_EXTENSIONS = {"html", "htm", "shtml", "xhtml"}

# Harmless-looking extensions attackers put in front of the real one: invoice.pdf.exe
_DECOY_EXTENSIONS = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "gif", "csv", "rtf"}

# Characters that reverse or reorder text direction can hide the real extension.
_HIDDEN_CHARS = re.compile("[\u202a-\u202e\u2066-\u2069]")


def _extension(filename: str) -> str:
    """Lowercase extension, ignoring trailing dots and spaces ('invoice.exe ' -> 'exe')."""
    cleaned = filename.strip().rstrip(". ").lower()
    return cleaned.rsplit(".", 1)[-1] if "." in cleaned else ""


def _has_double_extension(filename: str) -> bool:
    parts = filename.strip().rstrip(". ").lower().split(".")
    risky = EXECUTABLE_EXTENSIONS | MACRO_EXTENSIONS
    return len(parts) >= 3 and parts[-1] in risky and parts[-2] in _DECOY_EXTENSIONS


def _describe(attachment: AttachmentInfo) -> str:
    return f"{attachment.filename} ({attachment.content_type}, {attachment.size_bytes} bytes)"


def _summarize(items: list[str], limit: int = 3) -> str:
    shown = "; ".join(items[:limit])
    extra = len(items) - limit
    return f"{shown} (+{extra} more)" if extra > 0 else shown


def check_attachments(email: ParsedEmail) -> list[Finding]:
    """Judge attachments by name and type only. Files are never opened or executed."""
    executables: list[str] = []
    macros: list[str] = []
    archives: list[str] = []
    html_files: list[str] = []
    double_ext: list[str] = []
    hidden: list[str] = []

    for attachment in email.attachments:
        name = attachment.filename
        ext = _extension(name)
        description = _describe(attachment)

        if ext in EXECUTABLE_EXTENSIONS:
            executables.append(description)
        elif ext in MACRO_EXTENSIONS:
            macros.append(description)
        elif ext in ARCHIVE_EXTENSIONS:
            archives.append(description)
        elif ext in HTML_EXTENSIONS:
            html_files.append(description)

        if _has_double_extension(name):
            double_ext.append(description)
        if _HIDDEN_CHARS.search(name):
            hidden.append(repr(name))  # repr() shows the hidden characters as escape codes

    findings: list[Finding] = []
    if executables:
        findings.append(Finding(
            "ATTACHMENT_EXECUTABLE", "attachment",
            "The email carries an executable or script file, a common way to deliver malware.",
            _summarize(executables),
        ))
    if double_ext:
        findings.append(Finding(
            "ATTACHMENT_DOUBLE_EXTENSION", "attachment",
            "An attachment has a document-style extension followed by a risky one, to disguise its real type.",
            _summarize(double_ext),
        ))
    if macros:
        findings.append(Finding(
            "ATTACHMENT_MACRO_DOCUMENT", "attachment",
            "The email carries a macro-enabled Office document, which can run code when opened.",
            _summarize(macros),
        ))
    if html_files:
        findings.append(Finding(
            "ATTACHMENT_HTML", "attachment",
            "The email carries an HTML file, often used to host fake login forms offline.",
            _summarize(html_files),
        ))
    if archives:
        findings.append(Finding(
            "ATTACHMENT_ARCHIVE", "attachment",
            "The email carries an archive or disk image, which can hide a payload from simple scanning.",
            _summarize(archives),
        ))
    if hidden:
        findings.append(Finding(
            "ATTACHMENT_HIDDEN_CHARACTERS", "attachment",
            "An attachment name contains hidden text-direction characters that can disguise its real extension.",
            _summarize(hidden),
        ))
    return findings
