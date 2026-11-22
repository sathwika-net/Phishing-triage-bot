"""Streamlit dashboard for the Phishing Email Triage Bot.

Run with:  streamlit run app.py

Safety rules this file follows:
- The uploaded file is read into memory and never written to disk.
- Email-derived text is shown with st.text, st.code and st.dataframe only. It is
  NEVER passed to st.markdown or st.write, because markdown could render a remote
  image or a clickable link taken from a hostile email.
- The only HTML used (the colored level badge) is built from fixed strings.
- Nothing in the email is opened, fetched or executed.
"""

from pathlib import Path

import pandas as pd
import streamlit as st

from triage.extractors import defang
from triage.parser import MAX_EMAIL_BYTES, EmailParseError
from triage.pipeline import analyze_bytes
from triage.report import ACTIONS, build_report

SAMPLE_DIR = Path(__file__).parent / "samples" / "dataset"
LEVEL_HEX = {"Low": "#2e7d32", "Medium": "#ef8f00", "High": "#c62828"}

st.set_page_config(page_title="Phishing Triage Bot", page_icon="🛡️", layout="wide")


def load_input():
    """Return (raw_bytes, label) from the upload box or a bundled sample, or (None, None)."""
    samples = sorted(SAMPLE_DIR.glob("*.eml")) if SAMPLE_DIR.is_dir() else []
    options = ["Upload a file"] + (["Use a bundled synthetic sample"] if samples else [])
    source = st.sidebar.radio("Email source", options)

    if source == "Upload a file":
        uploaded = st.sidebar.file_uploader("Choose a .eml file", type=["eml"])
        if uploaded is None:
            return None, None
        if uploaded.size > MAX_EMAIL_BYTES:
            st.error(f"File is larger than the {MAX_EMAIL_BYTES // (1024 * 1024)} MB limit.")
            return None, None
        return uploaded.getvalue(), "uploaded file"

    names = [path.name for path in samples]
    chosen = st.sidebar.selectbox("Sample", names)
    return (SAMPLE_DIR / chosen).read_bytes(), chosen


def show_summary(analysis):
    assessment = analysis.assessment
    left, right = st.columns([1, 3])
    left.metric("Risk score", f"{assessment.score} / 100")
    right.markdown(
        f"<div style='background:{LEVEL_HEX[assessment.level]};color:white;padding:14px 18px;"
        f"border-radius:6px;font-size:22px;font-weight:600'>{assessment.level} risk</div>",
        unsafe_allow_html=True,
    )
    st.caption(assessment.disclaimer)

    st.subheader("Main reasons")
    top = assessment.top_contributions(3)
    if top:
        for item in top:
            st.text(f"+{item.counted}  {item.description}")
    else:
        st.text("No detection rules fired.")

    st.subheader(f"Recommended actions ({assessment.level} risk)")
    for action in ACTIONS[assessment.level]:
        st.text(f"- {action}")

    email = analysis.email
    st.subheader("Email details")
    sender = f"{email.sender_display_name} <{email.sender_address}>" if email.sender_display_name else email.sender_address
    details = pd.DataFrame(
        [
            ("From", sender),
            ("Reply-To", email.reply_to_address or "(none)"),
            ("Return-Path", email.return_path or "(none)"),
            ("To", ", ".join(email.recipients) or "(none)"),
            ("Subject", email.subject or "(none)"),
            ("Date header", email.date_raw or "(none)"),
            ("Message-ID", email.message_id or "(none)"),
        ],
        columns=["Field", "Value"],
    )
    st.dataframe(details, hide_index=True)
    for warning in email.parse_warnings:
        st.warning(warning)


def show_evidence(analysis):
    contributions = sorted(analysis.assessment.contributions, key=lambda c: c.counted, reverse=True)
    if not contributions:
        st.info("No findings.")
        return
    frame = pd.DataFrame(
        [
            {
                "Rule": c.rule_id,
                "Category": c.category,
                "Counted": c.counted,
                "Full weight": c.weight,
                "What was found": c.description,
                "Evidence": c.evidence,
                "Note": c.note,
            }
            for c in contributions
        ]
    )
    st.dataframe(frame, hide_index=True)
    st.caption("Related rules share a cap so one problem is not counted twice.")


def show_iocs(analysis):
    iocs = analysis.detection.iocs
    st.caption("Indicators are defanged (hxxp, [.]) so they cannot be clicked by accident.")
    for label, values in [
        ("URLs", [defang(u) for u in iocs.urls]),
        ("Domains", [defang(d) for d in iocs.domains]),
        ("IP addresses", [defang(i) for i in iocs.ips]),
        ("Email addresses", list(iocs.email_addresses)),
    ]:
        st.subheader(f"{label} ({len(values)})")
        if values:
            st.code("\n".join(values), language=None)
        else:
            st.text("(none)")


def show_auth(analysis):
    auth = analysis.detection.auth
    st.caption("Read from the email headers. These results are not verified through DNS.")
    frame = pd.DataFrame(
        [
            ("SPF", auth.spf, auth.spf_domain or "-"),
            ("DKIM", auth.dkim, auth.dkim_domain or "-"),
            ("DMARC", auth.dmarc, auth.dmarc_domain or "-"),
        ],
        columns=["Check", "Result", "Domain"],
    )
    st.dataframe(frame, hide_index=True)
    for note in auth.notes:
        st.text(note)


def show_attachments(analysis):
    attachments = analysis.email.attachments
    st.caption("Attachments are hashed in memory. They are never saved, opened or executed.")
    if not attachments:
        st.info("No attachments.")
        return
    frame = pd.DataFrame(
        [{"File name": a.filename, "Type": a.content_type, "Size (bytes)": a.size_bytes, "SHA-256": a.sha256}
         for a in attachments]
    )
    st.dataframe(frame, hide_index=True)


def main():
    st.title("🛡️ Phishing Email Triage Bot")
    st.caption("A triage aid, not proof. Upload a suspicious .eml file to see a rule-based risk score and the evidence behind it.")
    st.sidebar.header("Input")
    st.sidebar.info("Use synthetic or authorized emails only. The file is analyzed in memory and not stored. Links and attachments are never opened.")

    raw, label = load_input()
    if raw is None:
        st.info("Choose an email in the sidebar to begin.")
        return

    try:
        analysis = analyze_bytes(raw)
    except EmailParseError as error:
        st.error(f"Could not analyze this file: {error}")
        return
    except Exception:  # last-resort guard so a hostile file never shows a stack trace
        st.error("Unexpected error while analyzing this file. It may be malformed.")
        return

    st.success(f"Analyzed: {label}")
    tabs = st.tabs(["Summary", "Evidence", "IOCs", "Authentication", "Attachments", "Report"])
    with tabs[0]:
        show_summary(analysis)
    with tabs[1]:
        show_evidence(analysis)
    with tabs[2]:
        show_iocs(analysis)
    with tabs[3]:
        show_auth(analysis)
    with tabs[4]:
        show_attachments(analysis)
    with tabs[5]:
        st.write("Download a PDF investigation report for this email.")
        pdf = build_report(analysis.email, analysis.detection, analysis.assessment)
        st.download_button("Download PDF report", data=pdf, file_name="phishing_triage_report.pdf", mime="application/pdf")
        st.caption("The report contains metadata and evidence only. It does not include the message body.")


main()
