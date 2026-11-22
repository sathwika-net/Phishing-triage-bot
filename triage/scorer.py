"""Turns detector findings into a transparent 0-100 risk score.

The scorer never looks at the email itself, only at the Finding objects. That
keeps scoring easy to test and easy to explain: same findings in, same score out.
"""

from dataclasses import dataclass, field

from triage import scoring_config as cfg
from triage.models import Finding


@dataclass
class Contribution:
    """One finding and what it added to the score."""

    rule_id: str
    category: str
    description: str
    evidence: str
    weight: int          # points the rule is worth on its own
    counted: int         # points actually added after caps
    group: str = ""      # group name, empty if the rule is not grouped
    note: str = ""       # why counted is lower than weight, if it is


@dataclass
class RiskAssessment:
    score: int
    level: str                       # "Low", "Medium" or "High"
    contributions: list = field(default_factory=list)
    group_totals: dict = field(default_factory=dict)  # group -> (counted, cap)
    disclaimer: str = cfg.DISCLAIMER

    def top_contributions(self, n=3):
        counted = [c for c in self.contributions if c.counted > 0]
        return sorted(counted, key=lambda c: c.counted, reverse=True)[:n]


def classify(score, medium_threshold=None, high_threshold=None):
    """Map a 0-100 score to Low, Medium or High."""
    medium = cfg.MEDIUM_THRESHOLD if medium_threshold is None else medium_threshold
    high = cfg.HIGH_THRESHOLD if high_threshold is None else high_threshold
    if score >= high:
        return "High"
    if score >= medium:
        return "Medium"
    return "Low"


def _group_of(rule_id, groups):
    for name, group in groups.items():
        if rule_id in group["rules"]:
            return name
    return ""


def score_findings(findings, weights=None, groups=None, max_score=None):
    """Score a list of findings. Optional arguments let tests supply their own config."""
    weights = cfg.RULE_WEIGHTS if weights is None else weights
    groups = cfg.RULE_GROUPS if groups is None else groups
    max_score = cfg.MAX_SCORE if max_score is None else max_score

    contributions = []
    for finding in findings:
        weight = weights.get(finding.rule_id, cfg.DEFAULT_WEIGHT)
        contributions.append(
            Contribution(
                rule_id=finding.rule_id,
                category=finding.category,
                description=finding.description,
                evidence=finding.evidence,
                weight=weight,
                counted=weight,
                group=_group_of(finding.rule_id, groups),
            )
        )

    # Apply each group's cap. Highest-weight rules get their points first, so
    # the most important evidence is the one that "uses" the budget.
    group_totals = {}
    for name, group in groups.items():
        members = [c for c in contributions if c.group == name]
        if not members:
            continue
        remaining = group["cap"]
        for item in sorted(members, key=lambda c: c.weight, reverse=True):
            item.counted = min(item.weight, remaining)
            remaining -= item.counted
            if item.counted < item.weight:
                item.note = f"Capped: '{group['label']}' is limited to {group['cap']} points in total."
        group_totals[name] = (sum(c.counted for c in members), group["cap"])

    total = min(sum(c.counted for c in contributions), max_score)
    return RiskAssessment(
        score=total,
        level=classify(total),
        contributions=contributions,
        group_totals=group_totals,
    )


if __name__ == "__main__":
    import sys

    from triage.engine import run_all_detectors
    from triage.parser import parse_eml_file

    if len(sys.argv) != 2:
        print("Usage: python -m triage.scorer <path-to-eml>")
        sys.exit(1)

    assessment = score_findings(run_all_detectors(parse_eml_file(sys.argv[1])).findings)
    print(f"Risk score: {assessment.score}/100  ->  {assessment.level}")
    print()
    for item in sorted(assessment.contributions, key=lambda c: c.counted, reverse=True):
        print(f"  +{item.counted:<3} (worth {item.weight:<3}) {item.rule_id}")
        if item.note:
            print(f"        {item.note}")
    print()
    print(assessment.disclaimer)
    