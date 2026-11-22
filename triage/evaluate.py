"""Measures the triage tool against the labelled synthetic dataset.

The labels (expected_level) were written BEFORE the tool was run, as the level
a careful analyst would expect. Results are whatever the tool actually
produces. Nothing here is tuned to make the numbers look good.

Run:  python -m triage.evaluate
"""

import csv
import sys
from dataclasses import dataclass
from pathlib import Path

from triage.engine import run_all_detectors
from triage.parser import parse_eml_file
from triage.scorer import score_findings

DEFAULT_FOLDER = Path("samples") / "dataset"


@dataclass
class EvalRow:
    filename: str
    true_label: str
    expected_level: str
    score: int
    level: str

    @property
    def matched(self):
        return self.level == self.expected_level


def evaluate_dataset(folder=DEFAULT_FOLDER):
    """Run every labelled email through the pipeline and return EvalRow objects."""
    folder = Path(folder)
    rows = []
    with open(folder / "labels.csv", newline="", encoding="utf-8") as handle:
        for record in csv.DictReader(handle):
            email = parse_eml_file(folder / record["filename"])
            assessment = score_findings(run_all_detectors(email).findings)
            rows.append(
                EvalRow(
                    filename=record["filename"],
                    true_label=record["true_label"],
                    expected_level=record["expected_level"],
                    score=assessment.score,
                    level=assessment.level,
                )
            )
    return rows


def summarise(rows):
    """Counts that are easy to read and hard to over-claim."""
    malicious = [r for r in rows if r.true_label == "malicious"]
    legitimate = [r for r in rows if r.true_label == "legitimate"]
    return {
        "total": len(rows),
        "matched_expected": sum(r.matched for r in rows),
        "malicious_total": len(malicious),
        "malicious_rated_high": sum(r.level == "High" for r in malicious),
        "legitimate_total": len(legitimate),
        "legitimate_rated_low": sum(r.level == "Low" for r in legitimate),
    }


def main(folder=DEFAULT_FOLDER):
    rows = evaluate_dataset(folder)
    print(f"{'File':<34}{'True label':<14}{'Expected':<10}{'Score':<7}{'Result':<8}Match")
    for r in rows:
        print(f"{r.filename:<34}{r.true_label:<14}{r.expected_level:<10}{r.score:<7}{r.level:<8}{'yes' if r.matched else 'NO'}")
    s = summarise(rows)
    print()
    print(f"Matched the expected level: {s['matched_expected']} of {s['total']}")
    print(f"Malicious rated High:       {s['malicious_rated_high']} of {s['malicious_total']}")
    print(f"Legitimate rated Low:       {s['legitimate_rated_low']} of {s['legitimate_total']}")
    print()
    print("Small synthetic set written by the same author as the rules. This is a")
    print("sanity check, not an accuracy claim.")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_FOLDER)
    