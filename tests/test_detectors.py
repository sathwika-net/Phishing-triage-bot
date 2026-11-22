"""Tests for triage/detectors.py. All data here is synthetic."""

from triage.auth import AuthResults
from triage.detectors import check_authentication, check_sender, check_urls
from triage.extractors import extract_iocs
from triage.models import ParsedEmail


def ids(findings):
    """The set of rule IDs in a list of findings, for easy assertions."""
    return {finding.rule_id for finding in findings}


# ---------------------------------------------------------------------------
# Sender checks
# ---------------------------------------------------------------------------

def test_brand_in_display_name_with_unrelated_domain_is_flagged():
    email = ParsedEmail(sender_display_name="PayPal Support", sender_address="help@random-mail.example")
    assert "SENDER_BRAND_IMPERSONATION" in ids(check_sender(email))


def test_real_brand_domain_is_not_flagged():
    email = ParsedEmail(sender_display_name="PayPal", sender_address="service@paypal.com")
    assert check_sender(email) == []


def test_subdomain_of_real_brand_is_not_flagged():
    email = ParsedEmail(sender_display_name="Microsoft", sender_address="no-reply@mail.microsoft.com")
    assert check_sender(email) == []


def test_lookalike_domain_with_swapped_characters_is_flagged():
    email = ParsedEmail(sender_display_name="Support", sender_address="security@paypa1-verify.example")
    assert "SENDER_LOOKALIKE_DOMAIN" in ids(check_sender(email))


def test_innocent_domain_containing_short_brand_is_not_flagged():
    email = ParsedEmail(sender_display_name="Recipes", sender_address="news@pineapple-recipes.example")
    assert check_sender(email) == []


def test_reply_to_on_different_domain_is_flagged():
    email = ParsedEmail(sender_address="a@company.example", reply_to_address="collect@mailbox-drop.example")
    assert "REPLY_TO_MISMATCH" in ids(check_sender(email))


def test_reply_to_on_same_domain_or_missing_is_not_flagged():
    same = ParsedEmail(sender_address="a@company.example", reply_to_address="help@company.example")
    missing = ParsedEmail(sender_address="a@company.example")
    assert check_sender(same) == []
    assert check_sender(missing) == []


def test_display_name_containing_other_domains_email_is_flagged():
    email = ParsedEmail(sender_display_name="ceo@acme.example", sender_address="x@gmail.example")
    assert "SENDER_DISPLAY_NAME_EMAIL_MISMATCH" in ids(check_sender(email))


def test_display_name_with_same_domain_email_is_not_flagged():
    email = ParsedEmail(sender_display_name="ceo@acme.example", sender_address="ceo@acme.example")
    assert check_sender(email) == []


def test_empty_email_does_not_crash_sender_checks():
    assert check_sender(ParsedEmail()) == []


def test_synthetic_phishing_sender_triggers_three_rules():
    email = ParsedEmail(
        sender_display_name="ExampleBank Support",
        sender_address="security@examplebank-verify.example",
        reply_to_address="collect@mailbox-drop.example",
    )
    assert ids(check_sender(email)) == {
        "SENDER_BRAND_IMPERSONATION",
        "SENDER_LOOKALIKE_DOMAIN",
        "REPLY_TO_MISMATCH",
    }


# ---------------------------------------------------------------------------
# Authentication checks
# ---------------------------------------------------------------------------

def test_failed_spf_dkim_dmarc_are_flagged():
    auth = AuthResults(spf="fail", dkim="fail", dmarc="fail", spf_domain="bad.example")
    assert ids(check_authentication(auth)) == {"SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL"}


def test_spf_softfail_is_flagged_separately():
    auth = AuthResults(spf="softfail", dkim="pass", dmarc="pass")
    assert ids(check_authentication(auth)) == {"SPF_SOFTFAIL"}


def test_all_pass_gives_no_findings():
    auth = AuthResults(spf="pass", dkim="pass", dmarc="pass")
    assert check_authentication(auth) == []


def test_all_results_missing_gives_informational_finding():
    assert ids(check_authentication(AuthResults())) == {"AUTH_RESULTS_MISSING"}


def test_partially_missing_results_are_not_reported_as_missing():
    auth = AuthResults(spf="pass")  # dkim and dmarc stay not_found
    assert check_authentication(auth) == []


# ---------------------------------------------------------------------------
# URL checks
# ---------------------------------------------------------------------------

def url_findings(body_text="", body_html=""):
    """Helper: run the URL checks on an email with the given body."""
    email = ParsedEmail(body_text=body_text, body_html=body_html)
    return check_urls(email, extract_iocs(email))


def test_url_shortener_is_flagged():
    assert "URL_SHORTENER" in ids(url_findings("Click http://bit.ly/abc123"))


def test_ordinary_url_is_not_flagged():
    assert url_findings("Read https://www.example.org/page") == []


def test_no_urls_gives_no_findings():
    assert url_findings("Hello, no links here.") == []


def test_ip_address_link_is_flagged():
    found = ids(url_findings("Login at http://203.0.113.5/login"))
    assert "URL_IP_ADDRESS" in found
    assert "URL_SUSPICIOUS_TLD" not in found


def test_link_text_that_differs_from_destination_is_flagged():
    html = '<a href="http://evil.example/login">http://bank.example</a>'
    assert "URL_TEXT_MISMATCH" in ids(url_findings(body_html=html))


def test_link_text_matching_destination_is_not_flagged():
    html = '<a href="https://www.example.org/a">example.org</a>'
    assert "URL_TEXT_MISMATCH" not in ids(url_findings(body_html=html))


def test_plain_words_as_link_text_are_not_flagged():
    html = '<a href="http://evil.example/x">Click here</a>'
    assert "URL_TEXT_MISMATCH" not in ids(url_findings(body_html=html))


def test_file_name_as_link_text_is_not_treated_as_a_domain():
    html = '<a href="http://files.example.org/r.pdf">report.pdf</a>'
    assert "URL_TEXT_MISMATCH" not in ids(url_findings(body_html=html))


def test_suspicious_tld_is_flagged():
    assert "URL_SUSPICIOUS_TLD" in ids(url_findings("Claim: http://free-gift.xyz/claim"))


def test_embedded_credentials_trick_is_flagged():
    assert "URL_EMBEDDED_CREDENTIALS" in ids(url_findings("Go to http://paypal.com@evil.example/login"))


def test_punycode_domain_is_flagged():
    assert "URL_PUNYCODE" in ids(url_findings("Visit http://xn--pypal-4ve.example/login"))


def test_lookalike_link_domain_is_flagged():
    assert "URL_LOOKALIKE_DOMAIN" in ids(url_findings("Sign in: http://paypa1-login.example/a"))


def test_brand_name_used_as_subdomain_of_another_site_is_flagged():
    assert "URL_LOOKALIKE_DOMAIN" in ids(url_findings("http://paypal.com.evil.example/x"))


def test_real_brand_links_are_not_flagged():
    assert url_findings("https://www.paypal.com/signin and https://lh3.googleusercontent.com/x") == []


def test_url_evidence_is_defanged():
    evidence = url_findings("http://bit.ly/abc123")[0].evidence
    assert "hxxp://" in evidence
    assert "http://" not in evidence


def test_many_links_produce_one_summarised_finding():
    body = " ".join(f"http://bit.ly/x{i}" for i in range(10))
    findings = url_findings(body)
    assert len(findings) == 1
    assert "more" in findings[0].evidence