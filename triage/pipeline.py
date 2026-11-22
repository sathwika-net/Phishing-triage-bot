"""One call that runs the whole analysis: parse -> detect -> score.

The dashboard (and any future command-line tool) uses this so the steps are
wired together in exactly one place.
"""

from dataclasses import dataclass

from triage.engine import DetectionResult, run_all_detectors
from triage.models import ParsedEmail
from triage.parser import parse_eml
from triage.scorer import RiskAssessment, score_findings


@dataclass
class Analysis:
    email: ParsedEmail
    detection: DetectionResult
    assessment: RiskAssessment


def analyze_bytes(raw: bytes) -> Analysis:
    """Analyze raw .eml bytes. Raises EmailParseError for empty or oversized input."""
    email = parse_eml(raw)
    detection = run_all_detectors(email)
    assessment = score_findings(detection.findings)
    return Analysis(email=email, detection=detection, assessment=assessment)
