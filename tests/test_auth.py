"""Tests for triage/auth.py. All headers here are synthetic."""

from triage.auth import NOT_FOUND, UNVERIFIED, parse_authentication_results
from triage.parser import parse_eml


def headers(*pairs):
    """Small helper: headers('Name', 'value', 'Name2', 'value2') -> list of tuples."""
    return list(zip(pairs[::2], pairs[1::2]))


def test_all_three_pass():
    result = parse_authentication_results(
        headers(
            "Authentication-Results",
            "mx.example.net; spf=pass smtp.mailfrom=sender.example; "
            "dkim=pass header.d=sender.example header.s=sel1; "
            "dmarc=pass (p=REJECT) header.from=sender.example",
        )
    )
    assert (result.spf, result.dkim, result.dmarc) == ("pass", "pass", "pass")
    assert result.spf_domain == "sender.example"
    assert result.dkim_domain == "sender.example"
    assert result.dmarc_domain == "sender.example"
    assert result.checked_by == "mx.example.net"


def test_failures_are_reported():
    result = parse_authentication_results(
        headers(
            "Authentication-Results",
            "mx.example.net; spf=fail smtp.mailfrom=bad.example; dkim=none; dmarc=fail header.from=bad.example",
        )
    )
    assert (result.spf, result.dkim, result.dmarc) == ("fail", "none", "fail")


def test_missing_headers_give_not_found():
    result = parse_authentication_results(headers("Subject", "hello"))
    assert (result.spf, result.dkim, result.dmarc) == (NOT_FOUND, NOT_FOUND, NOT_FOUND)


def test_header_names_are_case_insensitive():
    result = parse_authentication_results(
        headers("AUTHENTICATION-RESULTS", "mx.example.net; spf=pass smtp.mailfrom=a.example")
    )
    assert result.spf == "pass"


def test_verdicts_are_lowercased():
    result = parse_authentication_results(headers("Authentication-Results", "mx.example.net; SPF=PASS"))
    assert result.spf == "pass"


def test_comment_text_cannot_inject_a_fake_verdict():
    result = parse_authentication_results(
        headers("Authentication-Results", "mx.example.net; spf=none (spf=pass trust me); dkim=none")
    )
    assert result.spf == "none"


def test_multiple_dkim_signatures_prefer_a_pass():
    result = parse_authentication_results(
        headers(
            "Authentication-Results",
            "mx.example.net; dkim=fail header.d=relay.example; dkim=pass header.d=sender.example",
        )
    )
    assert result.dkim == "pass"
    assert result.dkim_domain == "sender.example"


def test_only_topmost_authentication_results_is_used():
    result = parse_authentication_results(
        headers(
            "Authentication-Results", "mx.real.example; spf=fail smtp.mailfrom=bad.example",
            "Authentication-Results", "forged.example; spf=pass smtp.mailfrom=bad.example",
        )
    )
    assert result.spf == "fail"
    assert any("topmost" in note for note in result.notes)


def test_received_spf_is_used_as_fallback():
    result = parse_authentication_results(headers("Received-SPF", "softfail (mx.example.net: ...) client-ip=203.0.113.9;"))
    assert result.spf == "softfail"
    assert any("Received-SPF" in note for note in result.notes)


def test_dkim_signature_without_verdict_is_unverified():
    result = parse_authentication_results(
        headers("DKIM-Signature", "v=1; a=rsa-sha256; d=sender.example; s=sel1; b=abc123")
    )
    assert result.dkim == UNVERIFIED
    assert result.dkim_domain == "sender.example"


def test_malformed_header_does_not_crash():
    result = parse_authentication_results(headers("Authentication-Results", ";;; === ((( spf"))
    assert (result.spf, result.dkim, result.dmarc) == (NOT_FOUND, NOT_FOUND, NOT_FOUND)


def test_works_end_to_end_with_the_parser():
    raw = (
        b"Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=bad.example; "
        b"dmarc=fail header.from=bad.example\r\n"
        b"From: a@bad.example\r\nTo: b@example.com\r\nSubject: x\r\nDate: d\r\n\r\nhi\r\n"
    )
    auth = parse_authentication_results(parse_eml(raw).headers)
    assert auth.spf == "fail"
    assert auth.dmarc == "fail"
    