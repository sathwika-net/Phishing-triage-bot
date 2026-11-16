"""Email authentication parsing: SPF, DKIM and DMARC results from headers.

We do NOT perform any DNS lookups or cryptographic checks ourselves. We only read
the verdicts that the receiving mail server already wrote into the headers.
"""

import re
import sys
from dataclasses import dataclass, field

NOT_FOUND = "not_found"    # the header did not contain any verdict for this method
UNVERIFIED = "unverified"  # a DKIM signature exists but nobody recorded a verdict

_COMMENT = re.compile(r"\([^()]*\)")
_METHOD = re.compile(r"^\s*([a-z0-9\-]+)\s*=\s*([a-z]+)", re.IGNORECASE)
_PAIR = re.compile(r"([a-z0-9.\-]+)\s*=\s*([^\s;]+)", re.IGNORECASE)


@dataclass
class AuthResults:
    """SPF/DKIM/DMARC verdicts plus the domains each check was about."""

    spf: str = NOT_FOUND
    dkim: str = NOT_FOUND
    dmarc: str = NOT_FOUND
    spf_domain: str = ""    # domain SPF was checked against (the envelope sender)
    dkim_domain: str = ""   # domain that signed the message (header.d)
    dmarc_domain: str = ""  # the From-header domain DMARC evaluated (header.from)
    checked_by: str = ""    # which server wrote the verdicts (the authserv-id)
    raw_header: str = ""    # the Authentication-Results header used, for the report
    notes: list[str] = field(default_factory=list)  # caveats the analyst should see


def _values(headers: list[tuple[str, str]], name: str) -> list[str]:
    """All values of a header, in file order (top of the email first), case-insensitive."""
    return [value for header_name, value in headers if header_name.lower() == name.lower()]


def _strip_comments(value: str) -> str:
    """Remove (parenthesised comments). Attackers can put fake 'spf=pass' text in them."""
    for _ in range(5):  # handles nesting without looping forever
        stripped = _COMMENT.sub(" ", value)
        if stripped == value:
            break
        value = stripped
    return value


def _domain_of(value: str) -> str:
    """'user@Example.com' or 'Example.com' -> 'example.com'."""
    return value.strip("<>\"'").rsplit("@", 1)[-1].lower()


def _read_authentication_results(value: str, result: AuthResults) -> None:
    """Fill in `result` from one Authentication-Results header (RFC 8601 format)."""
    result.raw_header = " ".join(value.split())[:500]
    parts = [part.strip() for part in _strip_comments(value).split(";")]

    if parts and parts[0] and "=" not in parts[0]:
        result.checked_by = parts[0].split()[0]  # first item is the server's name

    dkim_results: list[tuple[str, str]] = []
    for part in parts:
        match = _METHOD.match(part)
        if not match:
            continue
        method, verdict = match.group(1).lower(), match.group(2).lower()
        props = {key.lower(): val for key, val in _PAIR.findall(part)}

        if method == "spf" and result.spf == NOT_FOUND:
            result.spf = verdict
            result.spf_domain = _domain_of(props.get("smtp.mailfrom") or props.get("smtp.helo") or "")
        elif method == "dkim":
            dkim_results.append((verdict, _domain_of(props.get("header.d", ""))))
        elif method == "dmarc" and result.dmarc == NOT_FOUND:
            result.dmarc = verdict
            result.dmarc_domain = _domain_of(props.get("header.from", ""))

    if dkim_results:
        # An email can carry several signatures. If any one passes, report the pass.
        result.dkim, result.dkim_domain = next(
            (item for item in dkim_results if item[0] == "pass"), dkim_results[0]
        )


def parse_authentication_results(headers: list[tuple[str, str]]) -> AuthResults:
    """Read SPF/DKIM/DMARC verdicts from a list of (header name, value) pairs."""
    result = AuthResults()

    auth_headers = _values(headers, "Authentication-Results")
    if len(auth_headers) > 1:
        result.notes.append(
            f"{len(auth_headers)} Authentication-Results headers found. Only the first (topmost) "
            "is used, because the receiving server adds its own at the top and an attacker "
            "can pre-insert fake ones lower down."
        )
    if auth_headers:
        _read_authentication_results(auth_headers[0], result)

    # Fallback 1: SPF verdict from the older Received-SPF header.
    if result.spf == NOT_FOUND:
        received_spf = _values(headers, "Received-SPF")
        if received_spf:
            match = re.match(r"\s*([a-z]+)", received_spf[0], re.IGNORECASE)
            if match:
                result.spf = match.group(1).lower()
                result.notes.append("SPF verdict taken from the Received-SPF header.")

    # Fallback 2: a DKIM signature exists, but no one recorded whether it is valid.
    if result.dkim == NOT_FOUND:
        signatures = _values(headers, "DKIM-Signature")
        if signatures:
            result.dkim = UNVERIFIED
            match = re.search(r"(?:^|;)\s*d\s*=\s*([^\s;]+)", signatures[0], re.IGNORECASE)
            if match:
                result.dkim_domain = _domain_of(match.group(1))
            result.notes.append(
                "A DKIM-Signature header is present, but no verification result was recorded."
            )

    return result


if __name__ == "__main__":
    # Quick manual check:  python -m triage.auth samples\auth_demo.eml
    from triage.parser import parse_eml_file

    if len(sys.argv) != 2:
        print("Usage: python -m triage.auth <path-to-.eml>")
        raise SystemExit(1)
    auth = parse_authentication_results(parse_eml_file(sys.argv[1]).headers)
    print("SPF   :", auth.spf, f"(domain: {auth.spf_domain or 'n/a'})")
    print("DKIM  :", auth.dkim, f"(domain: {auth.dkim_domain or 'n/a'})")
    print("DMARC :", auth.dmarc, f"(domain: {auth.dmarc_domain or 'n/a'})")
    print("Checked by:", auth.checked_by or "n/a")
    print("Notes :", auth.notes or "none")
    