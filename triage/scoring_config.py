"""Scoring configuration. This is the ONLY file you edit to tune the risk score.

Every number here is a judgement call, not a measured fact. They are starting
values chosen so that one weak signal stays Low and several strong,
independent signals reach High. Tune them against a documented test set.
"""

# Points each rule adds when it fires (before group caps are applied).
RULE_WEIGHTS = {
    # Sender
    "SENDER_DISPLAY_NAME_EMAIL_MISMATCH": 15,
    "SENDER_BRAND_IMPERSONATION": 25,
    "SENDER_LOOKALIKE_DOMAIN": 30,
    "REPLY_TO_MISMATCH": 15,
    # Authentication
    "SPF_FAIL": 15,
    "SPF_SOFTFAIL": 8,
    "DKIM_FAIL": 15,
    "DMARC_FAIL": 20,
    "AUTH_RESULTS_MISSING": 3,  # weak: many internal or forwarded emails lack it
    # URLs
    "URL_SHORTENER": 8,
    "URL_IP_ADDRESS": 20,
    "URL_TEXT_MISMATCH": 25,
    "URL_SUSPICIOUS_TLD": 10,
    "URL_EMBEDDED_CREDENTIALS": 25,
    "URL_PUNYCODE": 15,
    "URL_LOOKALIKE_DOMAIN": 30,
    # Language
    "LANG_CREDENTIAL_REQUEST": 15,
    "LANG_URGENCY": 10,
    "LANG_MONEY_OR_PRIZE_LURE": 12,
    "LANG_GENERIC_GREETING": 4,
    # Attachments
    "ATTACHMENT_EXECUTABLE": 35,
    "ATTACHMENT_DOUBLE_EXTENSION": 30,
    "ATTACHMENT_MACRO_DOCUMENT": 20,
    "ATTACHMENT_HTML": 15,
    "ATTACHMENT_ARCHIVE": 10,
    "ATTACHMENT_HIDDEN_CHARACTERS": 30,
}

# Used for any rule_id that is not listed above (for example a rule added later).
DEFAULT_WEIGHT = 5

# Groups of rules that describe the SAME underlying problem. Inside a group the
# points are added up but can never exceed the group's cap. This stops one
# problem from being counted several times (for example, a look-alike domain
# triggers both a sender rule and a URL rule).
RULE_GROUPS = {
    "lookalike_domain": {
        "cap": 40,
        "label": "Look-alike or impersonated domain",
        "rules": ["SENDER_LOOKALIKE_DOMAIN", "URL_LOOKALIKE_DOMAIN", "SENDER_BRAND_IMPERSONATION"],
    },
    "sender_spoofing": {
        "cap": 20,
        "label": "Sender identity does not add up",
        "rules": ["SENDER_DISPLAY_NAME_EMAIL_MISMATCH", "REPLY_TO_MISMATCH"],
    },
    "authentication": {
        "cap": 30,
        "label": "Email authentication problems",
        "rules": ["SPF_FAIL", "SPF_SOFTFAIL", "DKIM_FAIL", "DMARC_FAIL"],
    },
    "url_reputation": {
        "cap": 12,
        "label": "Weak link signals",
        "rules": ["URL_SHORTENER", "URL_SUSPICIOUS_TLD"],
    },
    "pressure_language": {
        "cap": 25,
        "label": "Pressure and lure language",
        "rules": [
            "LANG_CREDENTIAL_REQUEST",
            "LANG_URGENCY",
            "LANG_MONEY_OR_PRIZE_LURE",
            "LANG_GENERIC_GREETING",
        ],
    },
    "disguised_attachment": {
        "cap": 45,
        "label": "Dangerous or disguised attachment",
        "rules": [
            "ATTACHMENT_EXECUTABLE",
            "ATTACHMENT_DOUBLE_EXTENSION",
            "ATTACHMENT_HIDDEN_CHARACTERS",
        ],
    },
}

MAX_SCORE = 100

# Classification thresholds (inclusive lower bounds).
MEDIUM_THRESHOLD = 30
HIGH_THRESHOLD = 60

DISCLAIMER = (
    "This score is a triage aid, not proof. It is produced by simple rules and can be "
    "wrong in both directions. A human analyst should review the evidence before acting."
)
