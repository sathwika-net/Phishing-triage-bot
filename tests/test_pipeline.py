"""Tests for triage/pipeline.py. All data here is synthetic."""

import pytest

from tests.test_engine import LEGITIMATE_EMAIL, PHISHING_EMAIL
from triage.parser import MAX_EMAIL_BYTES, EmailParseError
from triage.pipeline import analyze_bytes


def test_phishing_email_is_analyzed_end_to_end():
    analysis = analyze_bytes(PHISHING_EMAIL)
    assert analysis.assessment.level == "High"
    assert analysis.email.sender_address == "security@examplebank-verify.example"
    assert analysis.detection.iocs.urls


def test_legitimate_email_is_low():
    assert analyze_bytes(LEGITIMATE_EMAIL).assessment.level == "Low"


def test_findings_and_score_agree():
    analysis = analyze_bytes(PHISHING_EMAIL)
    assert len(analysis.assessment.contributions) == len(analysis.detection.findings)


def test_empty_input_is_rejected_cleanly():
    with pytest.raises(EmailParseError):
        analyze_bytes(b"")


def test_oversized_input_is_rejected_cleanly():
    with pytest.raises(EmailParseError):
        analyze_bytes(b"a" * (MAX_EMAIL_BYTES + 1))
        