"""Tests for triage/extractors.py. All data here is synthetic."""

from triage.extractors import (
    defang,
    extract_html_links,
    extract_iocs,
    extract_ips,
    extract_urls,
    get_hostname,
)
from triage.models import AttachmentInfo, ParsedEmail


def test_extracts_urls_from_plain_text():
    text = "Visit http://a.example/x, then https://b.example/y."
    assert extract_urls(text) == ["http://a.example/x", "https://b.example/y"]


def test_trailing_punctuation_is_stripped():
    assert extract_urls("Click (http://a.example/x).") == ["http://a.example/x"]


def test_duplicate_urls_are_removed():
    text = "http://a.example/x and again http://a.example/x"
    assert extract_urls(text) == ["http://a.example/x"]


def test_no_urls_returns_empty_list():
    assert extract_urls("no links in this message") == []


def test_hostname_is_lowercased():
    assert get_hostname("HTTP://EVIL.Example/A") == "evil.example"


def test_html_link_keeps_real_href_and_visible_text():
    html = '<p><a href="http://evil.example/login">http://bank.example</a></p>'
    links, _ = extract_html_links(html)
    assert len(links) == 1
    assert links[0].href == "http://evil.example/login"
    assert links[0].text == "http://bank.example"


def test_script_content_is_not_treated_as_visible_text():
    _, visible = extract_html_links('<script>var u="http://hidden.example"</script><p>hello</p>')
    assert "hidden.example" not in visible
    assert "hello" in visible


def test_malformed_html_does_not_crash():
    links, _ = extract_html_links('<a href="http://x.example">unclosed <b')
    assert isinstance(links, list)


def test_defang_url_and_domain():
    assert defang("http://evil.example/login") == "hxxp://evil[.]example/login"
    assert defang("https://evil.example") == "hxxps://evil[.]example"
    assert defang("mailbox-drop.example") == "mailbox-drop[.]example"


def test_valid_ip_extracted_and_invalid_ip_ignored():
    assert extract_ips("connect to 203.0.113.5 now") == ["203.0.113.5"]
    assert extract_ips("version 999.1.1.1") == []


def test_ip_host_goes_to_ips_not_domains():
    email = ParsedEmail(body_text="Login: http://203.0.113.5/login")
    iocs = extract_iocs(email)
    assert iocs.ips == ["203.0.113.5"]
    assert iocs.domains == []


def test_full_ioc_extraction():
    email = ParsedEmail(
        sender_address="security@examplebank-verify.example",
        reply_to_address="collect@mailbox-drop.example",
        recipients=["victim@example.com"],
        body_text="Verify now: http://examplebank-verify.example/login",
        attachments=[AttachmentInfo("invoice.pdf.exe", "application/octet-stream", 11, "ab" * 32)],
    )
    iocs = extract_iocs(email)
    assert iocs.urls == ["http://examplebank-verify.example/login"]
    assert "examplebank-verify.example" in iocs.domains
    assert "mailbox-drop.example" in iocs.domains
    assert "victim@example.com" not in iocs.email_addresses  # recipients are not indicators
    assert iocs.attachment_filenames == ["invoice.pdf.exe"]
    assert iocs.attachment_hashes == ["ab" * 32]


def test_empty_email_gives_empty_iocs():
    iocs = extract_iocs(ParsedEmail())
    assert iocs.urls == [] and iocs.domains == [] and iocs.ips == []