"""Detection engine: looks for suspicious indicators and reports them as Findings.

Each check function takes parsed email data and returns a list of Finding objects.
A Finding says WHAT was seen and shows the exact EVIDENCE. Detectors never assign
points. Scoring lives in the scorer so the rules stay transparent and configurable.
This module never contacts the internet and never calls an LLM.
"""

import ipaddress
import re
import sys
from urllib.parse import urlparse

from triage.auth import NOT_FOUND, AuthResults, parse_authentication_results
from triage.extractors import EMAIL_PATTERN, IOCs, defang, extract_iocs, get_hostname
from triage.models import Finding, ParsedEmail

# ---------------------------------------------------------------------------
# Editable detection data. Real products use much larger, maintained lists.
# ---------------------------------------------------------------------------

# Well-known brands phishers imitate, and the domains those brands really send from.
# "examplebank" is a synthetic brand used by our test emails.
BRAND_DOMAINS: dict[str, set[str]] = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "office.com", "office365.com", "outlook.com", "live.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.ca", "amazon.co.uk", "amazonaws.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "googleusercontent.com", "googleapis.com", "gstatic.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "examplebank": {"examplebank.example"},
}

# Attackers swap look-alike characters: paypa1.com instead of paypal.com
_LOOKALIKE_CHARS = str.maketrans({"1": "l", "0": "o", "3": "e", "5": "s", "4": "a"})

# URL shorteners hide the real destination of a link.
SHORTENER_DOMAINS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "tiny.cc", "shorturl.at", "rb.gy",
}

# Top-level domains that are cheap or free and often abused. This is a heuristic, not proof:
# plenty of legitimate sites use them.
SUSPICIOUS_TLDS: set[str] = {
    "zip", "mov", "top", "xyz", "click", "tk", "ml", "ga", "cf", "gq",
    "work", "country", "stream", "gdn", "loan", "icu", "buzz",
}

# Link text ending like a file name ("report.pdf") is a file, not a web address.
_FILE_EXTENSIONS: set[str] = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "png", "jpg", "jpeg", "gif", "csv", "html", "htm",
}

# Link text that is itself a web address: "http://bank.example/login", "www.bank.example", "bank.example"
_LINK_TEXT_URL = re.compile(
    r"(?:https?://)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?::\d+)?(?:/\S*)?",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _domain(address: str) -> str:
    """'user@Example.com' -> 'example.com' ('' if there is no @)."""
    return address.rsplit("@", 1)[1].lower() if "@" in address else ""


def _same_org(domain_a: str, domain_b: str) -> bool:
    """True if the domains are equal or one is a subdomain of the other.

    Simplified on purpose: a production tool would use the Public Suffix List.
    """
    if not domain_a or not domain_b:
        return False
    return domain_a == domain_b or domain_a.endswith("." + domain_b) or domain_b.endswith("." + domain_a)


def _is_legitimate_for(brand: str, sender_domain: str) -> bool:
    return any(_same_org(sender_domain, legit) for legit in BRAND_DOMAINS[brand])


def _domain_mentions_brand(domain: str, brand: str) -> bool:
    """Does a domain contain the brand name, even with look-alike characters (paypa1)?

    Short brand names must match a whole word of the domain, to avoid
    flagging innocent names like 'pineapple' for 'apple'.
    """
    normalized = domain.translate(_LOOKALIKE_CHARS)
    for token in re.split(r"[.\-]", normalized):
        if len(brand) >= 6 and brand in token:
            return True
        if token == brand:
            return True
    return False


# ---------------------------------------------------------------------------
# Sender checks
# ---------------------------------------------------------------------------

def check_sender(email: ParsedEmail) -> list[Finding]:
    """Look for spoofing signs in the From and Reply-To fields."""
    findings: list[Finding] = []
    display = email.sender_display_name
    sender_domain = _domain(email.sender_address)
    shown_from = f'"{display}" <{email.sender_address}>'

    # 1. The display name itself contains an email address from a different domain.
    #    Example: "ceo@company.com" <attacker@gmail.com>
    for shown_address in EMAIL_PATTERN.findall(display):
        shown_domain = _domain(shown_address.lower())
        if sender_domain and not _same_org(shown_domain, sender_domain):
            findings.append(Finding(
                rule_id="SENDER_DISPLAY_NAME_EMAIL_MISMATCH",
                category="sender",
                description="The display name shows an email address from a different domain than the real sender.",
                evidence=f"{shown_from}",
            ))
            break

    # 2 and 3. Brand impersonation and look-alike domains.
    #    Both findings can appear together; the scorer prevents double counting later.
    display_lower = display.lower()
    for brand in BRAND_DOMAINS:
        if not sender_domain or _is_legitimate_for(brand, sender_domain):
            continue
        if re.search(rf"\b{re.escape(brand)}\b", display_lower):
            findings.append(Finding(
                rule_id="SENDER_BRAND_IMPERSONATION",
                category="sender",
                description=f"The display name mentions '{brand}' but the sender domain does not belong to it.",
                evidence=shown_from,
            ))
            break
    for brand in BRAND_DOMAINS:
        if not sender_domain or _is_legitimate_for(brand, sender_domain):
            continue
        if _domain_mentions_brand(sender_domain, brand):
            findings.append(Finding(
                rule_id="SENDER_LOOKALIKE_DOMAIN",
                category="sender",
                description=f"The sender domain imitates '{brand}' without being one of its real domains.",
                evidence=f"Sender domain: {sender_domain}",
            ))
            break

    # 4. Replies go somewhere other than the visible sender.
    reply_domain = _domain(email.reply_to_address)
    if reply_domain and sender_domain and not _same_org(reply_domain, sender_domain):
        findings.append(Finding(
            rule_id="REPLY_TO_MISMATCH",
            category="sender",
            description="Replies would go to a different domain than the sender's domain.",
            evidence=f"From domain: {sender_domain} | Reply-To domain: {reply_domain}",
        ))

    return findings


# ---------------------------------------------------------------------------
# Authentication checks
# ---------------------------------------------------------------------------

def check_authentication(auth: AuthResults) -> list[Finding]:
    """Turn SPF/DKIM/DMARC verdicts into findings."""
    findings: list[Finding] = []

    if auth.spf == "fail":
        findings.append(Finding(
            "SPF_FAIL", "auth",
            "SPF failed: the sending server is not authorised to send for the domain.",
            f"SPF result: fail (domain: {auth.spf_domain or 'unknown'})",
        ))
    elif auth.spf == "softfail":
        findings.append(Finding(
            "SPF_SOFTFAIL", "auth",
            "SPF softfail: the sending server is probably not authorised for the domain.",
            f"SPF result: softfail (domain: {auth.spf_domain or 'unknown'})",
        ))

    if auth.dkim == "fail":
        findings.append(Finding(
            "DKIM_FAIL", "auth",
            "DKIM failed: the signature is invalid or the message was altered.",
            f"DKIM result: fail (signing domain: {auth.dkim_domain or 'unknown'})",
        ))

    if auth.dmarc == "fail":
        findings.append(Finding(
            "DMARC_FAIL", "auth",
            "DMARC failed: the From domain's owner policy was not satisfied.",
            f"DMARC result: fail (domain: {auth.dmarc_domain or 'unknown'})",
        ))

    # Missing results are NOT proof of anything (exported or forwarded emails often lose them),
    # so this is only an informational finding with a very low weight.
    if NOT_FOUND == auth.spf == auth.dkim == auth.dmarc:
        findings.append(Finding(
            "AUTH_RESULTS_MISSING", "auth",
            "No SPF, DKIM or DMARC results were found, so spoofing cannot be assessed.",
            "No Authentication-Results, Received-SPF or DKIM-Signature verdicts present",
        ))

    return findings


# ---------------------------------------------------------------------------
# URL checks
# ---------------------------------------------------------------------------

def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _has_embedded_credentials(url: str) -> bool:
    """True for http://trusted.com@evil.example/ where everything before @ is a decoy."""
    try:
        return "@" in urlparse(url).netloc
    except ValueError:
        return False


def _summarize(items: list[str], limit: int = 3) -> str:
    """Show the first few examples and say how many more there were."""
    shown = "; ".join(items[:limit])
    extra = len(items) - limit
    return f"{shown} (+{extra} more)" if extra > 0 else shown


def check_urls(email: ParsedEmail, iocs: IOCs) -> list[Finding]:
    """Look for tricks in the links of an email. We only read link text. We never visit a link.

    Each rule produces at most ONE finding, listing a few examples, so an email
    stuffed with 50 shortened links is reported once, not 50 times.
    URLs in evidence are defanged so they cannot be clicked by accident.
    """
    shorteners: list[str] = []
    ip_links: list[str] = []
    odd_tlds: list[str] = []
    credentials: list[str] = []
    punycode: list[str] = []
    lookalikes: list[str] = []

    for url in iocs.urls:
        host = get_hostname(url)
        if not host:
            continue
        safe_url = defang(url)

        if any(_same_org(host, shortener) for shortener in SHORTENER_DOMAINS):
            shorteners.append(safe_url)
        if _has_embedded_credentials(url):
            credentials.append(safe_url)
        if _looks_like_ip(host):
            ip_links.append(safe_url)
            continue  # the remaining checks are about domain names, not IPs

        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            odd_tlds.append(safe_url)
        if any(label.startswith("xn--") for label in host.split(".")):
            punycode.append(safe_url)
        for brand in BRAND_DOMAINS:
            if _is_legitimate_for(brand, host):
                continue
            if _domain_mentions_brand(host, brand):
                lookalikes.append(safe_url)
                break

    # Link text that shows one address while the link goes somewhere else.
    mismatches: list[str] = []
    for link in iocs.html_links:
        text = link.text.strip()
        target_host = get_hostname(link.href)
        match = _LINK_TEXT_URL.fullmatch(text)
        if not match or not target_host:
            continue
        shown_domain = match.group(1).lower()
        if shown_domain.rsplit(".", 1)[-1] in _FILE_EXTENSIONS:
            continue
        if not _same_org(shown_domain, target_host):
            mismatches.append(f"shows '{defang(text[:80])}' but goes to {defang(link.href)}")

    findings: list[Finding] = []
    if shorteners:
        findings.append(Finding(
            "URL_SHORTENER", "url",
            "A link uses a URL shortener, which hides its real destination.",
            _summarize(shorteners),
        ))
    if ip_links:
        findings.append(Finding(
            "URL_IP_ADDRESS", "url",
            "A link points to a raw IP address instead of a domain name.",
            _summarize(ip_links),
        ))
    if mismatches:
        findings.append(Finding(
            "URL_TEXT_MISMATCH", "url",
            "The visible link text shows one address but the link goes to a different site.",
            _summarize(mismatches),
        ))
    if odd_tlds:
        findings.append(Finding(
            "URL_SUSPICIOUS_TLD", "url",
            "A link uses a top-level domain that is frequently abused for throwaway phishing sites.",
            _summarize(odd_tlds),
        ))
    if credentials:
        findings.append(Finding(
            "URL_EMBEDDED_CREDENTIALS", "url",
            "A link has a 'name@' section before the real host, a trick that makes it look like a trusted site.",
            _summarize(credentials),
        ))
    if punycode:
        findings.append(Finding(
            "URL_PUNYCODE", "url",
            "A link domain uses punycode (xn--), which can disguise look-alike characters.",
            _summarize(punycode),
        ))
    if lookalikes:
        findings.append(Finding(
            "URL_LOOKALIKE_DOMAIN", "url",
            "A link domain imitates a well-known brand without being one of its real domains.",
            _summarize(lookalikes),
        ))
    return findings


if __name__ == "__main__":
    # Quick manual check:  python -m triage.detectors samples\quick_test.eml
    from triage.parser import parse_eml_file

    if len(sys.argv) != 2:
        print("Usage: python -m triage.detectors <path-to-.eml>")
        raise SystemExit(1)
    parsed = parse_eml_file(sys.argv[1])
    all_findings = (
        check_sender(parsed)
        + check_authentication(parse_authentication_results(parsed.headers))
        + check_urls(parsed, extract_iocs(parsed))
    )
    print(f"{len(all_findings)} finding(s)")
    for finding in all_findings:
        print(f"[{finding.category}] {finding.rule_id}")
        print(f"    {finding.description}")
        print(f"    evidence: {finding.evidence}")