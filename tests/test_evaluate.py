"""Tests for triage/evaluate.py. Builds its own tiny dataset, so it needs no generated files."""

from triage.evaluate import EvalRow, evaluate_dataset, summarise

LEGIT = (
    b"Authentication-Results: mx.example.net; spf=pass; dkim=pass; dmarc=pass\r\n"
    b'From: "Alex" <alex@company.example>\r\nTo: bob@company.example\r\n'
    b"Subject: Hi\r\nDate: Mon, 16 Nov 2026 09:15:00 -0700\r\n\r\nSee you Thursday.\r\n"
)


def row(true_label, expected, level, score=0):
    return EvalRow("x.eml", true_label, expected, score, level)


def test_row_matches_when_level_equals_expected():
    assert row("legitimate", "Low", "Low").matched
    assert not row("legitimate", "Low", "High").matched


def test_summary_counts_are_correct():
    rows = [
        row("malicious", "High", "High"),
        row("malicious", "High", "Medium"),
        row("legitimate", "Low", "Low"),
        row("inconclusive", "Medium", "Low"),
    ]
    s = summarise(rows)
    assert s["total"] == 4
    assert s["matched_expected"] == 2
    assert (s["malicious_rated_high"], s["malicious_total"]) == (1, 2)
    assert (s["legitimate_rated_low"], s["legitimate_total"]) == (1, 1)


def test_evaluate_dataset_reads_labels_and_scores_emails(tmp_path):
    (tmp_path / "ok.eml").write_bytes(LEGIT)
    (tmp_path / "labels.csv").write_text(
        "filename,true_label,expected_level\nok.eml,legitimate,Low\n", encoding="utf-8"
    )
    rows = evaluate_dataset(tmp_path)
    assert len(rows) == 1
    assert rows[0].score == 0 and rows[0].level == "Low" and rows[0].matched

    