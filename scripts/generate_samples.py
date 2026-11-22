"""Generates the synthetic evaluation dataset into samples/dataset/.

Everything here is invented. Domains use the reserved ".example" suffix and
IPs use the documentation range 192.0.2.0/24, so nothing points at a real
host. The "attachments" are harmless text bytes with dangerous-looking names.

Run from the project root:  python scripts/generate_samples.py
"""

import csv
from email.message import EmailMessage
from pathlib import Path

OUT = Path("samples") / "dataset"

PASS = ("Authentication-Results: mx.example.net; spf=pass smtp.mailfrom={d}; "
        "dkim=pass header.d={d}; dmarc=pass header.from={d}")


def build(name, headers, text, html=None, attachments=()):
    msg = EmailMessage()
    for key, value in headers:
        msg[key] = value
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    for filename, subtype, data in attachments:
        maintype = "application"
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    (OUT / name).write_bytes(msg.as_bytes())


def main():
    OUT.mkdir(parents=True, exist_ok=True)

    # ---- Clearly malicious -------------------------------------------------
    build("mal_01_bank_credentials.eml", [
        ("Authentication-Results", "mx.example.net; spf=fail smtp.mailfrom=examplebank-verify.example; dkim=none; dmarc=fail header.from=examplebank-verify.example"),
        ("From", '"ExampleBank Security" <alerts@examplebank-verify.example>'),
        ("To", "customer@example.com"),
        ("Subject", "Urgent: Your account will be suspended"),
        ("Date", "Mon, 16 Nov 2026 08:00:00 -0700"),
    ], "Dear customer, your account will be suspended. Please verify your account and confirm your password now.",
       html='<p>Dear customer, act now. <a href="http://192.0.2.45/examplebank/login">https://www.examplebank.example/login</a> to verify your account and confirm your password.</p>')

    build("mal_02_fake_invoice.eml", [
        ("Authentication-Results", "mx.example.net; spf=softfail smtp.mailfrom=billing-dept.example; dkim=fail header.d=billing-dept.example; dmarc=fail header.from=billing-dept.example"),
        ("From", '"Accounts Payable" <billing@billing-dept.example>'),
        ("To", "finance@example.com"),
        ("Reply-To", "payments@collect-funds.example"),
        ("Subject", "Final notice: overdue invoice"),
        ("Date", "Tue, 17 Nov 2026 10:30:00 -0700"),
    ], "Your invoice is overdue. This is your final notice, respond immediately. See the attached invoice.",
       attachments=[("Invoice_2291.xlsm", "octet-stream", b"synthetic harmless bytes"),
                    ("invoice_2291.pdf.exe", "octet-stream", b"synthetic harmless bytes")])

    build("mal_03_password_expiry.eml", [
        ("Authentication-Results", "mx.example.net; spf=fail smtp.mailfrom=micros0ft-alerts.example; dkim=none; dmarc=fail header.from=micros0ft-alerts.example"),
        ("From", '"Microsoft Support" <no-reply@micros0ft-alerts.example>'),
        ("To", "user@example.com"),
        ("Subject", "Your password expires today"),
        ("Date", "Wed, 18 Nov 2026 07:45:00 -0700"),
    ], "Your password expires today. Sign in at http://login-microsoft-secure.xyz/reset to keep your account active.",
       html='<p>Your password expires today. <a href="http://login-microsoft-secure.xyz/reset">https://microsoft.com/reset</a> to verify your account.</p>')

    # ---- Legitimate business -----------------------------------------------
    build("leg_01_meeting.eml", [
        ("Authentication-Results", PASS.format(d="company.example")),
        ("From", '"Alex Chen" <alex@company.example>'),
        ("To", "bob@company.example"),
        ("Subject", "Agenda for Thursday"),
        ("Date", "Mon, 16 Nov 2026 09:15:00 -0700"),
    ], "Hi Bob, here is the agenda for Thursday's meeting. Please send me any items you want added. Thanks, Alex")

    build("leg_02_newsletter.eml", [
        ("Authentication-Results", PASS.format(d="news.shop.example")),
        ("From", '"Example Shop" <newsletter@news.shop.example>'),
        ("To", "subscriber@example.com"),
        ("Subject", "Our autumn sale starts soon"),
        ("Date", "Thu, 19 Nov 2026 06:00:00 -0700"),
    ], "Dear customer, our autumn sale is on. Browse the collection at https://shop.example/autumn. To unsubscribe visit https://news.shop.example/unsubscribe")

    build("leg_03_vendor_report.eml", [
        ("Authentication-Results", PASS.format(d="vendor.example")),
        ("From", '"Priya Nair" <priya@vendor.example>'),
        ("To", "team@company.example"),
        ("Subject", "Monthly report attached"),
        ("Date", "Fri, 20 Nov 2026 14:00:00 -0700"),
    ], "Hello team, the monthly report is attached. The summary slides are also at https://bit.ly/monthly-slides. Regards, Priya",
       attachments=[("report.pdf", "pdf", b"synthetic harmless bytes")])

    # ---- Suspicious but inconclusive ----------------------------------------
    build("inc_01_hr_notice.eml", [
        ("From", '"HR Department" <hr.notifications@staff-portal.example>'),
        ("To", "employee@company.example"),
        ("Reply-To", "hr.team@hr-benefits-desk.example"),
        ("Subject", "Updated benefits information"),
        ("Date", "Mon, 16 Nov 2026 11:00:00 -0700"),
    ], "Please review your updated benefits summary at https://bit.ly/benefits-2027 when you can.")

    build("inc_02_parcel_notice.eml", [
        ("Authentication-Results", "mx.example.net; spf=softfail smtp.mailfrom=dhl-tracking.example; dkim=none; dmarc=none"),
        ("From", '"DHL Express" <notify@dhl-tracking.example>'),
        ("To", "customer@example.com"),
        ("Subject", "Delivery attempt failed"),
        ("Date", "Tue, 17 Nov 2026 16:20:00 -0700"),
    ], "Dear customer, we could not deliver your parcel. Reschedule at http://parcel-reschedule.xyz/track")

    build("inc_03_bank_details_change.eml", [
        ("Authentication-Results", PASS.format(d="partner.example")),
        ("From", '"Sam Lee" <sam@partner.example>'),
        ("To", "accounts@company.example"),
        ("Subject", "Updated payment details"),
        ("Date", "Wed, 18 Nov 2026 13:10:00 -0700"),
    ], "Hi, our bank details have changed. Please use the new details in the attached file for all future payments.",
       attachments=[("new_bank_details.zip", "zip", b"synthetic harmless bytes")])

    labels = [
        ("mal_01_bank_credentials.eml", "malicious", "High"),
        ("mal_02_fake_invoice.eml", "malicious", "High"),
        ("mal_03_password_expiry.eml", "malicious", "High"),
        ("leg_01_meeting.eml", "legitimate", "Low"),
        ("leg_02_newsletter.eml", "legitimate", "Low"),
        ("leg_03_vendor_report.eml", "legitimate", "Low"),
        ("inc_01_hr_notice.eml", "inconclusive", "Medium"),
        ("inc_02_parcel_notice.eml", "inconclusive", "Medium"),
        ("inc_03_bank_details_change.eml", "inconclusive", "Medium"),
    ]
    with open(OUT / "labels.csv", "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["filename", "true_label", "expected_level"])
        writer.writerows(labels)
    print(f"Wrote {len(labels)} emails and labels.csv to {OUT}")


if __name__ == "__main__":
    main()
    