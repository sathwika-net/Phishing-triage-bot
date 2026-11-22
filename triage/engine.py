"""Detection engine: runs every detector on one parsed email and bundles the results.

This is the single entry point the scorer, dashboard and report generator will call.
It never calls an LLM and never touches the network.
"""

import sys
from dataclasses import dataclass

from triage.auth import AuthResults, parse_authentication_results
from triage.content_checks import check_attachments, check_language
from triage.detectors import check_authentication, check_sender, check_urls
from triage.extractors import IOCs, extract_iocs
from triage.models import Finding, ParsedEmail


@dataclass
class DetectionResult:
    """Everything the detectors learned about one email."""

    findings: list[Finding]
    iocs: IOCs
    auth: AuthResults


def run_all_detectors(email: ParsedEmail) -> DetectionResult:
    """Run every check and return findings plus the extracted indicators and auth results."""
    iocs = extract_iocs(email)
    auth = parse_authentication_results(email.headers)
    findings = (
        check_sender(email)
        + check_authentication(auth)
        + check_urls(email, iocs)
        + check_language(email)
        + check_attachments(email)
    )
    return DetectionResult(findings=findings, iocs=iocs, auth=auth)


if __name__ == "__main__":
    # Quick manual check:  python -m triage.engine samples\quick_test.eml
    from triage.parser import parse_eml_file

    if len(sys.argv) != 2:
        print("Usage: python -m triage.engine <path-to-.eml>")
        raise SystemExit(1)
    result = run_all_detectors(parse_eml_file(sys.argv[1]))
    print(f"{len(result.findings)} finding(s)")
    for finding in result.findings:
        print(f"[{finding.category}] {finding.rule_id}")
        print(f"    {finding.description}")
        print(f"    evidence: {finding.evidence}")
        