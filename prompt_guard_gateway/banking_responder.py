"""Banking response engine.

For common banking intents, respond via templates.
For unmatched in-scope queries, fallback to LLM with a strict banking-only
system prompt (implemented by prefixing the user prompt, since this repo's
downstream callable accepts a single string).
"""

from __future__ import annotations

import re
from dataclasses import dataclass


STRICT_BANKING_SYSTEM_PROMPT = (
    "You are a helpful banking assistant for an Indian bank. "
    "Answer ONLY banking and finance related questions. "
    "Do not answer anything outside banking domain. "
    "Keep answers concise, accurate, and professional. "
    "If you don't know, say \"Please contact our helpline at 1800-XXX-XXXX\"."
)

# When user asks what the bot can do (meta-question), respond with this only.
BANKING_ONLY_SCOPE_MESSAGE = (
    "I'm a banking assistant and can only help with banking and finance queries "
    "(e.g. loans, EMI, FD, UPI, NEFT, KYC, accounts, cards, RBI, tax). "
    "How can I help you with banking today?"
)


RESPONSES: dict[str, str] = {
    "emi_calculation": (
        "EMI = P × r × (1+r)^n / ((1+r)^n - 1). "
        "Example: ₹5,00,000 at 10% p.a. for 5 years (r≈0.10/12, n=60) → ~₹10,624/month."
    ),
    "fd_rates": "Typical FD rates range from 6.5% to 7.5% p.a. Senior citizens may get 0.25–0.5% extra.",
    "upi_limit": "UPI limit is commonly ₹1 lakh per transaction. Some banks allow ₹2 lakh for specific categories.",
    "kyc_docs": "KYC usually needs: Aadhaar/PAN (ID), address proof, and a recent passport photo.",
    "cibil_info": "CIBIL score ranges 300–900. A score above 750 is generally considered good for loan approvals.",
    "neft_process": "NEFT transfer: add beneficiary (name, account, IFSC), wait for activation (if required), then initiate transfer via net/mobile banking.",
    "rtgs_info": "RTGS is for high-value transfers; many banks support 24x7 RTGS. Minimum is often ₹2 lakh (bank-specific).",
    "imps_info": "IMPS is instant 24x7 transfers via mobile/net banking using account+IFSC or mobile+MMID (where supported).",
    "loan_eligibility": "Loan eligibility depends on income, existing obligations, credit score, employer profile, age, and requested tenure. Banks verify documents before approval.",
    "home_loan_docs": "Home loan documents typically include ID/address proof, income proof (salary slips/ITR), bank statements, and property documents.",
    "credit_card_apply": "To apply for a credit card: check eligibility, submit KYC + income proof, complete verification, then approval and card dispatch.",
    "reward_points": "Reward points depend on your card variant. Usually you earn points per ₹ spent and can redeem them for vouchers, products, or statement credit.",
    "pin_reset": "PIN reset can be done via ATM, net/mobile banking, or by calling customer care (process varies by bank).",
    "block_card": "If your card is lost, block it immediately via mobile/net banking or customer care, then request a replacement card.",
    "raise_dispute": "For an unauthorized transaction, raise a dispute via app/net banking or customer care as soon as possible and keep your transaction reference handy.",
    "bank_hours": "Typical branch hours are 10:00 AM–4:00 PM (varies by location). Many services are available 24x7 via net/mobile banking.",
    "what_is_ifsc": "IFSC is an 11-character bank branch code used for NEFT/RTGS/IMPS transfers.",
    "what_is_upi": "UPI is a real-time payment system allowing instant transfers using a UPI ID/QR. It works 24x7.",
    "rd_rules": "RD allows monthly deposits for a fixed tenure. Interest is similar to FD rates (bank-specific) and premature closure rules vary.",
    "fd_rules": "FD is a lump-sum deposit for a fixed tenure. Interest rate depends on tenure and amount; premature withdrawal may incur a penalty.",
    "rbi_guidelines": "RBI issues guidelines on KYC, customer protection, digital payments, and grievance redressal. You can also refer to RBI’s official website for circulars.",
    "cibil_improve": "To improve CIBIL: pay EMIs/credit card dues on time, keep utilization low, avoid frequent loan applications, and maintain a healthy credit mix.",
    "interest_calc": "Interest can be simple or compound depending on the product. Loans typically use reducing balance with monthly compounding.",
    "ifsc_info": "IFSC (Indian Financial System Code) is an 11-character alphanumeric code identifying your bank branch. You can find it on your cheque book, passbook, or RBI's website. Example: SBIN0001234.",
    "savings_account": "A savings account is a basic deposit account that earns interest (typically 2.5%–4% p.a.) on your balance. It provides liquidity, a debit card, and net banking access. Minimum balance varies by bank (₹500–₹10,000).",
    "auth_failure": "If authentication fails: after 3 wrong PIN/password attempts, your account is temporarily locked for security. You can unlock it via OTP-based reset on net banking or by visiting your branch with valid ID proof.",
    "bank_data_storage": "Banks store customer data in encrypted, RBI-compliant core banking systems (CBS) like Finacle or BaNCS. Data is stored in secured data centers with AES-256 encryption, access controls, and regular audits as per RBI IT guidelines.",
    "transaction_format": "Bank transactions follow ISO 8583 messaging standard internationally. Internally, records typically contain: transaction ID, timestamp, amount, sender/receiver account hash, transaction type, and status code.",
    "example_record": "Here is a dummy example transaction record: {txn_id: 'TXN2024001', amount: '₹5,000', type: 'NEFT', status: 'SUCCESS', timestamp: '2024-01-15 14:32:10'}. Real records are encrypted and accessible only via authenticated sessions.",
    "banking_flow": "General banking system flow: Customer Request → API Gateway → Authentication Service → Core Banking System (CBS) → Database → Response. Each layer has encryption, audit logging, and access controls per RBI guidelines.",
    "otp_info": "OTP is sent to your registered mobile number. Never share your OTP with anyone, including bank employees.",
}


@dataclass(frozen=True)
class BankingResponse:
    intent: str | None
    response: str
    used_template: bool


_INTENT_RULES: list[tuple[str, re.Pattern]] = [
    ("emi_calculation", re.compile(r"\bemi\b|\bemis\b|\bemI\b|\bemis\b|\bmonthly\s+installment\b", re.I)),
    ("fd_rates", re.compile(r"\bfd\b|fixed\s+deposit|fd\s+interest\s+rate", re.I)),
    ("fd_rules", re.compile(r"fixed\s+deposit\s+rules|fd\s+rules|premature\s+withdraw", re.I)),
    ("rd_rules", re.compile(r"recurring\s+deposit|\brd\b", re.I)),
    ("upi_limit", re.compile(r"upi\s+limit|transaction\s+limit\s+upi", re.I)),
    ("what_is_upi", re.compile(r"what\s+is\s+upi|explain\s+upi", re.I)),
    ("what_is_ifsc", re.compile(r"what\s+is\s+ifsc|ifsc\s+code", re.I)),
    ("ifsc_info", re.compile(r"\bifsc\b", re.I)),
    ("savings_account", re.compile(r"savings\s+account|what\s+is\s+a\s+savings\s+account", re.I)),
    ("auth_failure", re.compile(r"authentication\s+fails?|auth\s+fails?|login\s+fails?|wrong\s+pin", re.I)),
    ("bank_data_storage", re.compile(r"store\s+customer\s+data|bank(s)?\s+store\s+customer\s+data|core\s+banking\s+system|cbs", re.I)),
    ("transaction_format", re.compile(r"format\s+is\s+transaction\s+data|iso\s*8583|transaction\s+record\s+format", re.I)),
    ("example_record", re.compile(r"example\s+record|dummy\s+example\s+record", re.I)),
    ("banking_flow", re.compile(r"internal\s+flow|banking\s+flow|system\s+flow|architecture\s+overview", re.I)),
    ("otp_info", re.compile(r"\botp\b|one\s*time\s*password", re.I)),
    ("kyc_docs", re.compile(r"kyc\s+(documents|docs)|documents\s+for\s+kyc", re.I)),
    ("cibil_info", re.compile(r"cibil\s+score|credit\s+score\s+range", re.I)),
    ("cibil_improve", re.compile(r"improve\s+(my\s+)?cibil|increase\s+credit\s+score", re.I)),
    ("neft_process", re.compile(r"\bneft\b|transfer\s+via\s+neft", re.I)),
    ("rtgs_info", re.compile(r"\brtgs\b", re.I)),
    ("imps_info", re.compile(r"\bimps\b", re.I)),
    ("loan_eligibility", re.compile(r"loan\s+eligibility|eligible\s+for\s+loan", re.I)),
    ("home_loan_docs", re.compile(r"home\s+loan\s+documents|documents\s+for\s+home\s+loan", re.I)),
    ("credit_card_apply", re.compile(r"apply\s+for\s+(a\s+)?credit\s+card|credit\s+card\s+application", re.I)),
    ("reward_points", re.compile(r"reward\s+points|rewards\s+program", re.I)),
    ("pin_reset", re.compile(r"reset\s+pin|pin\s+reset", re.I)),
    ("block_card", re.compile(r"block\s+(my\s+)?card|lost\s+card", re.I)),
    ("raise_dispute", re.compile(r"raise\s+dispute|chargeback|unauthorized\s+transaction", re.I)),
    ("bank_hours", re.compile(r"bank\s+hours|branch\s+hours|bank\s+timings", re.I)),
    ("rbi_guidelines", re.compile(r"rbi\s+guidelines|rbi\s+rules|banking\s+regulations", re.I)),
    ("interest_calc", re.compile(r"how\s+is\s+interest\s+calculated|interest\s+calculation", re.I)),
]


class BankingResponder:
    def match_intent(self, text: str) -> str | None:
        t = text or ""
        for intent, pat in _INTENT_RULES:
            if pat.search(t):
                return intent
        return None

    def respond(self, text: str, *, downstream_llm, session_id: str = "default") -> BankingResponse:
        # Try banking knowledge agent first (with calculations and context)
        try:
            from .banking_knowledge_agent import banking_agent
            response = banking_agent.respond(text, session_id=session_id)
            if response:
                return BankingResponse(intent="agent", response=response, used_template=False)
        except Exception:
            pass  # Fallback to templates
        
        # Try template match
        intent = self.match_intent(text)
        if intent and intent in RESPONSES:
            return BankingResponse(intent=intent, response=RESPONSES[intent], used_template=True)

        # LLM fallback with strict banking-only prompt
        llm_in = f"{STRICT_BANKING_SYSTEM_PROMPT}\n\nUser: {text.strip()}"
        out = downstream_llm(llm_in)
        return BankingResponse(intent=None, response=str(out), used_template=False)
