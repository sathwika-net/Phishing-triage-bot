"""Tests for triage/scorer.py. All data here is synthetic."""

from tests.test_engine import LEGITIMATE_EMAIL, PHISHING_EMAIL
from triage import scoring_config
from triage.engine import run_all_detectors
from triage.models import Finding
from triage.parser import parse_eml
from triage.scorer import classify, score_findings


def finding(rule_id, category="test"):
    return Finding(rule_id=rule_id, category=category, description=rule_id, evidence="x")


def test_no_findings_scores_zero_and_low():
    result = score_findings([])
    assert result.score == 0
    assert result.level == "Low"


def test_single_weak_signal_stays_low():
    result = score_findings([finding("LANG_GENERIC_GREETING")])
    assert result.score == 4
    assert result.level == "Low"


def test_score_is_the_sum_of_independent_rules():
    result = score_findings([finding("URL_TEXT_MISMATCH"), finding("LANG_CREDENTIAL_REQUEST")])
    assert result.score == 25 + 15


def test_related_rules_are_capped_to_avoid_double_counting():
    findings = [
        finding("SENDER_LOOKALIKE_DOMAIN"),
        finding("URL_LOOKALIKE_DOMAIN"),
        finding("SENDER_BRAND_IMPERSONATION"),
    ]
    result = score_findings(findings)
    assert result.score == 40  # 30 + 30 + 25 would be 85 without the cap


def test_capped_contribution_explains_why():
    findings = [finding("ATTACHMENT_EXECUTABLE"), finding("ATTACHMENT_DOUBLE_EXTENSION")]
    result = score_findings(findings)
    notes = [c.note for c in result.contributions if c.note]
    assert result.score == 45
    assert len(notes) == 1 and "Capped" in notes[0]


def test_highest_weight_rule_keeps_its_points_inside_a_capped_group():
    findings = [finding("ATTACHMENT_EXECUTABLE"), finding("ATTACHMENT_DOUBLE_EXTENSION")]
    result = score_findings(findings)
    by_id = {c.rule_id: c for c in result.contributions}
    assert by_id["ATTACHMENT_EXECUTABLE"].counted == 35
    assert by_id["ATTACHMENT_DOUBLE_EXTENSION"].counted == 10


def test_score_never_exceeds_100():
    everything = [finding(rule) for rule in scoring_config.RULE_WEIGHTS]
    assert score_findings(everything).score == 100


def test_unknown_rule_gets_default_weight():
    assert score_findings([finding("SOME_NEW_RULE")]).score == 5


def test_custom_weights_change_the_score():
    result = score_findings([finding("SPF_FAIL")], weights={"SPF_FAIL": 50}, groups={})
    assert result.score == 50


def test_classification_boundaries():
    assert classify(0) == "Low"
    assert classify(29) == "Low"
    assert classify(30) == "Medium"
    assert classify(59) == "Medium"
    assert classify(60) == "High"
    assert classify(100) == "High"


def test_authentication_missing_alone_is_low():
    result = score_findings([finding("AUTH_RESULTS_MISSING")])
    assert result.level == "Low"


def test_disclaimer_is_always_present():
    assert "not proof" in score_findings([]).disclaimer


def test_top_contributions_are_sorted_by_points():
    result = score_findings([finding("LANG_GENERIC_GREETING"), finding("URL_TEXT_MISMATCH")])
    assert result.top_contributions(1)[0].rule_id == "URL_TEXT_MISMATCH"


def test_end_to_end_phishing_email_is_high():
    result = score_findings(run_all_detectors(parse_eml(PHISHING_EMAIL)).findings)
    assert result.level == "High"


def test_end_to_end_legitimate_email_is_low():
    result = score_findings(run_all_detectors(parse_eml(LEGITIMATE_EMAIL)).findings)
    assert result.score == 0 and result.level == "Low"
    