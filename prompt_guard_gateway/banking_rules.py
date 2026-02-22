"""Banking-specific pre/post filters.

These rules are intended to reduce false positives for normal banking intents and
add deterministic blocking for obviously sensitive data exfiltration attempts.

Policy:
- HARD BLOCK if sensitive tokens (account number / CVV / OTP) appear together with
  action verbs that imply exfiltration or policy bypass.
- WHITELIST common banking intents (balance, transactions, loan, PIN reset, FD rates, etc.)
  to short-circuit model inference.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal, Optional


Decision = Literal["BLOCK", "ALLOW", "PASS_TO_MODEL"]


@dataclass(frozen=True)
class RuleDecision:
    decision: Decision
    reason: str


_EXFIL_VERB_RE = re.compile(
    r"\b(reveal|show|tell|give|leak|dump|share|expose|provide)\b",
    re.IGNORECASE,
)

_BYPASS_VERB_RE = re.compile(
    r"\b(bypass|ignore|override|disable|skip)\b",
    re.IGNORECASE,
)

_TXN_VERB_RE = re.compile(
    r"\b(transfer|send|withdraw|approve)\b",
    re.IGNORECASE,
)

_TXN_OBJECT_RE = re.compile(
    r"\b(funds?|money|payment|transaction)\b",
    re.IGNORECASE,
)

# If the user is *asking about* safety/meaning/location of tokens, don't hard-block.
_ADVISORY_QUESTION_RE = re.compile(
    r"\b(is\s+it\s+safe|is\s+it\s+ok|can\s+i|should\s+i|where\s+can\s+i\s+find|what\s+is)\b",
    re.IGNORECASE,
)

# Rough-but-useful patterns for banking sensitive items.
#
# NOTE: We intentionally treat *mentions* of sensitive fields (e.g. "OTP", "CVV",
# "account number") as sensitive, even if the value is not present. This is to
# support deterministic blocking for requests that attempt to exfiltrate or bypass
# controls (e.g. "Reveal my OTP and transfer funds").
_ACCOUNT_NUMBER_RE = re.compile(r"\b\d{10,18}\b")
_ACCOUNT_NUMBER_WORD_RE = re.compile(r"\b(account\s+number|card\s+number)\b", re.IGNORECASE)
_CVV_RE = re.compile(r"\bCVV\b(\s*[:=]?\s*\d{3})?\b", re.IGNORECASE)
_OTP_RE = re.compile(
    r"\b(OTP|ONE\s*TIME\s*PASSWORD)\b(\s*[:=]?\s*\d{4,8})?\b",
    re.IGNORECASE,
)


# Common banking intents (keep broad; this is an ALLOW list).
_WHITELIST_INTENT_RE = re.compile(
    r"\b("
    r"savings\s+account|current\s+account|fixed\s+deposit|fd\b|rd\b|"
    r"neft|rtgs|imps|upi|cheque|draft|ifsc|"
    r"account\s+balance|available\s+balance|balance\b|"
    r"last\s+\d+\s+transactions|transactions|statement|mini\s+statement|"
    r"apply\s+for\s+(a\s+)?(home\s+|housing\s+|personal\s+|car\s+|education\s+|business\s+)?loan|"
    r"loan\s+application|loan\s+interest\s+rate|emi|interest\s+rate|"
    r"reset\s+my\s+pin|reset\s+pin|change\s+pin|pin\s+reset|mpin|"
    r"credit\s+card|debit\s+card|card\s+replacement|lost\s+card|contactless\s+payment|"
    r"net\s+banking|mobile\s+banking|atm|"
    r"kyc|cibil|pan|aadhaar|nominee|locker|"
    r"repo\s+rate|inflation|rbi|sebi|insurance|"
    r"80c|80e|24b|tds|tax|income\s+tax|"
    r"ppf|nps|mutual\s+fund|sip|investment|"
    r"what\s+is|how\s+does|how\s+do\s+i|explain|tell\s+me|"
    r"difference\s+between|compare|which\s+is\s+better|"
    r"update(\s+my)?\s+address|branch\s+hours|working\s+hours|documents\s+needed|open\s+account"
    r")\b",
    re.IGNORECASE,
)

# Data extraction / exfiltration attempts even without explicit sensitive tokens.
_DATA_EXTRACTION_RE = re.compile(
    r"\b(show|list|dump|export|reveal)\b.*\b(all|every)\b.*\b(customer|customers|user|users)\b.*\b(account\s+numbers?|account\s+details?|transaction\s+records?|transactions|records)\b",
    re.I | re.S,
)


def banking_prefilter(text: str) -> RuleDecision:
    """Return a rule decision before model inference."""

    t = (text or "").strip()
    if not t:
        return RuleDecision("PASS_TO_MODEL", "empty")

    # Deterministic hard-block for bulk data extraction attempts.
    if _DATA_EXTRACTION_RE.search(t):
        return RuleDecision("BLOCK", "data_extraction_attempt")

    has_exfil = _EXFIL_VERB_RE.search(t) is not None
    has_bypass = _BYPASS_VERB_RE.search(t) is not None
    has_txn = _TXN_VERB_RE.search(t) is not None and _TXN_OBJECT_RE.search(t) is not None
    otp_mention = _OTP_RE.search(t) is not None
    strict_sensitive = (
        _ACCOUNT_NUMBER_RE.search(t) is not None
        or _ACCOUNT_NUMBER_WORD_RE.search(t) is not None
        or _CVV_RE.search(t) is not None
    )

    if strict_sensitive and (has_bypass or has_txn):
        return RuleDecision("BLOCK", "sensitive_data_with_action")

    # Exfil verbs (reveal/share/etc.) are blocked unless this looks like an advisory question.
    if strict_sensitive and has_exfil and not _ADVISORY_QUESTION_RE.search(t):
        return RuleDecision("BLOCK", "sensitive_data_with_action")

    # OTP handling:
    # - Exfil wording around OTP is blocked (e.g. "dump my OTP", "give my OTP")
    # - OTP + bypass/transaction intent is blocked
    # - Plain OTP troubleshooting should fall through.
    if otp_mention and (
        has_bypass
        or has_txn
        or (has_exfil and not _ADVISORY_QUESTION_RE.search(t))
    ):
        return RuleDecision("BLOCK", "otp_exfil_or_bypass")

    if _WHITELIST_INTENT_RE.search(t) is not None:
        return RuleDecision("ALLOW", "whitelisted_banking_intent")

    return RuleDecision("PASS_TO_MODEL", "no_rule_match")
