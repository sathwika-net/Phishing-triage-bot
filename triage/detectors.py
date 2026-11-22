"""Detection engine: looks for suspicious indicators and reports them as Findings.

Each check function takes parsed email data and returns a list of Finding objects.
A Finding says WHAT was seen and shows the exact EVIDENCE. Detectors never assign
points. Scoring lives in the scorer so the rules stay transparent and configurable.
This module never contacts the internet and never calls an LLM.
"""

import re
import sys

from triage.auth import NOT_FOUND, AuthResults, parse_authentication_results
from triage.extractors import EMAIL_PATTERN
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
    "amazon": {"amazon.com", "amazon.ca", "amazon.co.uk"},
    "google": {"google.com", "gmail.com", "youtube.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "examplebank": {"examplebank.example"},
}

# Attackers swap look-alike characters: paypa1.com instead of paypal.com
_LOOKALIKE_CHARS = str.maketrans({"1": "l", "0": "o", "3": "e", "5": "s", "4": "a"})


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


if __name__ == "__main__":
    # Quick manual check:  python -m triage.detectors samples\quick_test.eml
    from triage.parser import parse_eml_file

    if len(sys.argv) != 2:
        print("Usage: python -m triage.detectors <path-to-.eml>")
        raise SystemExit(1)
    parsed = parse_eml_file(sys.argv[1])
    all_findings = check_sender(parsed) + check_authentication(parse_authentication_results(parsed.headers))
    print(f"{len(all_findings)} finding(s)")
    for finding in all_findings:
        print(f"[{finding.category}] {finding.rule_id}")
        print(f"    {finding.description}")
        print(f"    evidence: {finding.evidence}")