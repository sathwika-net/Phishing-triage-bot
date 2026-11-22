"""Hostile-input tests: the tool must stay fast and must not crash on malicious files.

These come from a security review. Time limits are deliberately generous so the
tests do not fail on a slow machine, but they are far below the pre-fix behaviour
(one input used to take about 30 seconds).
"""

import re
import time
from pathlib import Path

import pytest

from triage.parser import MAX_EMAIL_BYTES, EmailParseError
from triage.pipeline import analyze_bytes

HEADERS = b"From: a@b.example\r\nTo: c@d.example\r\nSubject: x\r\n"
TIME_LIMIT = 5.0

PROJECT_ROOT = Path(__file__).parent.parent
BIDI = re.compile("[" + chr(0x202A) + "-" + chr(0x202E) + chr(0x2066) + "-" + chr(0x2069) + "]")


def analyze_quickly(raw):
    start = time.perf_counter()
    analysis = analyze_bytes(raw)
    assert time.perf_counter() - start < TIME_LIMIT
    return analysis


def test_long_run_of_dots_does_not_cause_quadratic_slowdown():
    analyze_quickly(HEADERS + b"\r\nhttp://" + b"a." * 100_000 + b"com")


def test_very_long_url_is_handled():
    analyze_quickly(HEADERS + b"\r\nhttp://" + b"a" * 200_000)


def test_many_urls_are_capped():
    analysis = analyze_quickly(HEADERS + b"\r\n" + b"http://a.example/x " * 100_000)
    assert len(analysis.detection.iocs.urls) <= 500


def test_deeply_nested_html_is_handled():
    analyze_quickly(HEADERS + b"Content-Type: text/html\r\n\r\n" + b"<div>" * 50_000)


def test_thousands_of_unclosed_links_are_handled():
    analyze_quickly(HEADERS + b"Content-Type: text/html\r\n\r\n" + b"<a href='http://x.example'>" * 50_000)


def test_ten_thousand_headers_are_handled():
    raw = b"".join(b"X-%d: v\r\n" % i for i in range(10_000)) + HEADERS + b"\r\nhi"
    analyze_quickly(raw)


def test_authentication_header_with_deep_comment_nesting_is_handled():
    raw = b"Authentication-Results: " + b"(" * 20_000 + b"spf=pass" + b")" * 20_000 + b"\r\n" + HEADERS + b"\r\nhi"
    analysis = analyze_quickly(raw)
    assert analysis.detection.auth.spf != "pass"  # a verdict hidden inside comments must not be trusted


def test_thousands_of_attachments_are_handled():
    parts = b"".join(
        b"--B\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=f%d.exe\r\n\r\nxx\r\n" % i
        for i in range(2000)
    )
    raw = HEADERS + b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n' + parts + b"--B--\r\n"
    analyze_quickly(raw)


def test_deeply_nested_multipart_is_handled():
    nested = b"".join(b'Content-Type: multipart/mixed; boundary="B%d"\r\n\r\n--B%d\r\n' % (i, i) for i in range(300))
    analyze_quickly(HEADERS + nested)


def test_random_binary_garbage_does_not_crash():
    import random

    rng = random.Random(1)
    analyze_quickly(bytes(rng.randrange(256) for _ in range(200_000)))


def test_oversized_file_is_rejected_before_parsing():
    with pytest.raises(EmailParseError):
        analyze_bytes(b"a" * (MAX_EMAIL_BYTES + 1))


def test_source_files_contain_no_hidden_bidirectional_characters():
    """'Trojan Source' check: invisible direction characters in code can hide what it really does."""
    offenders = []
    for folder in ("triage", "tests", "scripts"):
        for path in (PROJECT_ROOT / folder).glob("*.py"):
            if BIDI.search(path.read_text(encoding="utf-8")):
                offenders.append(path.name)
    if (PROJECT_ROOT / "app.py").exists() and BIDI.search((PROJECT_ROOT / "app.py").read_text(encoding="utf-8")):
        offenders.append("app.py")
    assert offenders == []
    