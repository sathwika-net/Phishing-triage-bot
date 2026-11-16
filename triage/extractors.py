"""IOC (indicator of compromise) extraction.

We treat every email as untrusted TEXT. We pull out URLs, domains, IPs, email
addresses and file hashes using regex and the standard library. We never visit
a URL, resolve a domain, or open anything.
"""

import ipaddress
import re
import sys
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlparse

from triage.models import ParsedEmail

# A hostile email could contain millions of links. Cap what we keep.
MAX_ITEMS = 500

URL_PATTERN = re.compile(r"https?://[^\s<>\"'`]+", re.IGNORECASE)
IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# Punctuation that often clings to the end of a URL in prose: "see http://x.com/a)."
_TRAILING_PUNCTUATION = ".,;:!?)]}"


@dataclass
class HtmlLink:
    """A clickable link in an HTML email: where it goes vs. what it claims to be."""

    href: str  # the real destination
    text: str  # the visible link text the reader sees


@dataclass
class IOCs:
    """All indicators extracted from one email, de-duplicated, in order of appearance."""

    urls: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    email_addresses: list[str] = field(default_factory=list)
    attachment_filenames: list[str] = field(default_factory=list)
    attachment_hashes: list[str] = field(default_factory=list)
    html_links: list[HtmlLink] = field(default_factory=list)


def _dedupe(items: list[str]) -> list[str]:
    """Remove duplicates but keep the original order, and apply the size cap."""
    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            unique.append(item)
    return unique[:MAX_ITEMS]


def defang(value: str) -> str:
    """Make an indicator safe to display or paste: http -> hxxp and . -> [.]

    Defanging stops chat apps and email clients from turning IOCs into clickable links.
    """
    return re.sub(r"(?i)^http", "hxxp", value).replace(".", "[.]")


class _LinkCollector(HTMLParser):
    """Collects <a> links and visible text from HTML. HTMLParser only reads; it executes nothing."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[HtmlLink] = []
        self.text_chunks: list[str] = []
        self._in_anchor = False
        self._href = ""
        self._anchor_text: list[str] = []
        self._skip_depth = 0  # inside <script> or <style>, text is not visible to the reader

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in ("script", "style"):
            self._skip_depth += 1
        elif tag == "a":
            self._in_anchor = True
            self._href = (dict(attrs).get("href") or "").strip()
            self._anchor_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style"):
            self._skip_depth = max(0, self._skip_depth - 1)
        elif tag == "a" and self._in_anchor:
            if self._href:
                text = " ".join("".join(self._anchor_text).split())
                self.links.append(HtmlLink(href=self._href, text=text))
            self._in_anchor = False

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self.text_chunks.append(data)
        if self._in_anchor:
            self._anchor_text.append(data)


def extract_html_links(html: str) -> tuple[list[HtmlLink], str]:
    """Return (links, visible_text) from an HTML body. Never raises on bad HTML."""
    collector = _LinkCollector()
    try:
        collector.feed(html or "")
        collector.close()
    except Exception:
        pass  # keep whatever was collected before the parser gave up
    return collector.links[:MAX_ITEMS], " ".join(collector.text_chunks)


def extract_urls(text: str) -> list[str]:
    """Find http(s) URLs in plain text."""
    urls = []
    for match in URL_PATTERN.findall(text or ""):
        cleaned = match.rstrip(_TRAILING_PUNCTUATION)
        if cleaned:
            urls.append(cleaned)
    return _dedupe(urls)


def get_hostname(url: str) -> str:
    """Return the lowercase host of a URL, or '' if it cannot be read."""
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return ""
    return host.rstrip(".").lower()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def extract_ips(text: str) -> list[str]:
    """Find valid IPv4 addresses in text (999.1.1.1 is rejected)."""
    return _dedupe([ip for ip in IPV4_PATTERN.findall(text or "") if _is_ip(ip)])


def extract_iocs(email: ParsedEmail) -> IOCs:
    """Build the full IOC set for one parsed email."""
    html_links, visible_html_text = extract_html_links(email.body_html)
    text_sources = [email.body_text, visible_html_text]

    # URLs: written out in text, plus the real destinations behind HTML links.
    urls: list[str] = []
    for text in text_sources:
        urls += extract_urls(text)
    for link in html_links:
        if link.href.lower().startswith(("http://", "https://")):
            urls.append(link.href)
    urls = _dedupe(urls)

    # A URL host is either a domain name or a bare IP address.
    domains: list[str] = []
    ips: list[str] = []
    for url in urls:
        host = get_hostname(url)
        if not host:
            continue
        (ips if _is_ip(host) else domains).append(host)
    for text in text_sources:
        ips += extract_ips(text)

    # Email addresses: sender-side headers plus any written in the body.
    # Recipients are the victims, so they are not indicators.
    addresses = [email.sender_address, email.reply_to_address, email.return_path]
    for text in text_sources:
        addresses += [a.lower() for a in EMAIL_PATTERN.findall(text or "")]
    addresses = _dedupe([a for a in addresses if a])
    domains += [a.rsplit("@", 1)[1] for a in addresses if "@" in a]

    return IOCs(
        urls=urls,
        domains=_dedupe(domains),
        ips=_dedupe(ips),
        email_addresses=addresses,
        attachment_filenames=_dedupe([a.filename for a in email.attachments]),
        attachment_hashes=_dedupe([a.sha256 for a in email.attachments]),
        html_links=html_links,
    )


if __name__ == "__main__":
    # Quick manual check:  python -m triage.extractors samples\quick_test.eml
    from triage.parser import parse_eml_file

    if len(sys.argv) != 2:
        print("Usage: python -m triage.extractors <path-to-.eml>")
        raise SystemExit(1)
    iocs = extract_iocs(parse_eml_file(sys.argv[1]))
    print("URLs (defanged)  :", [defang(u) for u in iocs.urls])
    print("Domains          :", [defang(d) for d in iocs.domains])
    print("IPs              :", [defang(i) for i in iocs.ips])
    print("Email addresses  :", [defang(a) for a in iocs.email_addresses])
    print("Attachment names :", iocs.attachment_filenames)
    print("Attachment SHA256:", iocs.attachment_hashes)
    print("HTML links       :", [(defang(link.href), link.text) for link in iocs.html_links])