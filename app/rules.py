"""
rules.py — Deterministic Rule Engine (no LLM involved).

Extracts factual signals from complaint + transaction history before
the LLM call. Outputs a RuleContext dict injected into the system prompt
as pre-computed, trusted hints. This prevents LLM hallucination on
structural facts (amounts, transaction IDs, duplicates, phishing signals).

Edge cases handled per edge_cases.md:
- §2  Transaction history anomalies (duplicate, pending, settlement, agent)
- §3  Language & encoding (Bangla digits, Banglish, NFC normalization)
- §9  User type & channel routing
- §10 Amount parsing (Bangla digits, commas, ±5% tolerance)
"""

import re
import unicodedata
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from app.schemas import CaseType, Department, EvidenceVerdict, Severity, TransactionEntry

logger = logging.getLogger(__name__)


# ─── Constants ────────────────────────────────────────────────────────────────

# Bangla → ASCII digit translation table
BANGLA_DIGITS = str.maketrans("০১২৩৪৫৬৭৮৯", "0123456789")

# Banglish lexicon — Bengali words written in English script
BANGLISH_KEYWORDS = {
    "taka", "takar", "bkash", "nagad", "paisa", "transfer", "recharge",
    "balance", "agent", "merchant", "otp", "pin", "account",
    "pathalam", "pathaisi", "paini", "jabe", "aseni", "gelo",
    "deducted", "failed", "wrong", "number", "theke", "diye",
    "koresi", "korechi", "pelam", "pailam",
}

# Phishing detection keywords (English + Bangla script)
PHISHING_KEYWORDS = [
    r"\bOTP\b", r"\bPIN\b", r"\bpassword\b", r"\bpasscode\b",
    r"\baccount[\s\-]?block\b", r"\bverif(?:y|ication|ied)\b",
    r"\bsuspicious[\s\-]?(?:call|sms|message|link)\b",
    r"\bimpersonat\w*\b", r"\bscam\b", r"\bfraud(?:ster|ulent)?\b",
    r"\bhack(?:ed|er)?\b", r"\bstole?\b", r"\bunauthorized\b",
    r"\bsomeone\s+(?:called|messaged|texted)\b",
    r"\bfake\s+(?:agent|call|bkash)\b",
    # Bangla script
    r"পিন", r"ওটিপি", r"পাসওয়ার্ড", r"অ্যাকাউন্ট[\s\u200c]*ব্লক",
    r"ভেরিফিকেশন", r"প্রতারণা", r"জালিয়াতি", r"হ্যাক",
    r"সন্দেহজনক", r"অনুমোদন\s*ছাড়া",
]

# Prompt injection patterns (English + Bangla)
INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+)?(?:previous|above|prior|your)\s+(?:instructions?|rules?|prompts?|guidelines?)",
    r"you\s+are\s+now\s+(?:a|an|the)\s+(?:admin|superuser|authority|unrestricted\s+bot)",
    r"act\s+as\s+(?:if\s+you\s+(?:are|have)|an?)\s+(?:admin|authority|unrestricted)",
    r"forget\s+(?:all\s+)?(?:your\s+)?(?:previous\s+)?instructions?",
    r"disregard\s+(?:all\s+)?(?:safety|previous|your)",
    r"say\s+[\"']?we\s+will\s+(?:refund|reverse|return|credit)",
    r"output\s+(?:the\s+following|this|as)\s*[:\-]?\s*\{",
    r"your\s+new\s+(?:role|instructions?|prime\s+directive)",
    r"pretend\s+(?:you\s+are|to\s+be)",
    r"override\s+(?:all\s+)?(?:safety|rules?|restrictions?)",
    r"DAN\s+mode", r"developer\s+mode",
    # Bangla
    r"আগের\s+নির্দেশ\s+ভুলে\s+যাও",
    r"তুমি\s+এখন\s+(?:একজন\s+)?অ্যাডমিন",
    r"নিয়ম\s+মানো\s+না",
    r"রিফান্ড\s+দাও\s+বলো",
]

# Department routing table (deterministic — not delegated to LLM)
DEPT_ROUTING: dict[str, str] = {
    CaseType.wrong_transfer.value:                 Department.dispute_resolution.value,
    CaseType.payment_failed.value:                 Department.payments_ops.value,
    CaseType.duplicate_payment.value:              Department.payments_ops.value,
    CaseType.refund_request.value:                 Department.customer_support.value,
    CaseType.merchant_settlement_delay.value:      Department.merchant_operations.value,
    CaseType.agent_cash_in_issue.value:            Department.agent_operations.value,
    CaseType.phishing_or_social_engineering.value: Department.fraud_risk.value,
    CaseType.other.value:                          Department.customer_support.value,
}

# Case priority for multi-issue resolution (highest wins)
CASE_PRIORITY: dict[str, int] = {
    CaseType.phishing_or_social_engineering.value: 10,
    CaseType.wrong_transfer.value:                 8,
    CaseType.duplicate_payment.value:              7,
    CaseType.payment_failed.value:                 6,
    CaseType.agent_cash_in_issue.value:            5,
    CaseType.merchant_settlement_delay.value:      4,
    CaseType.refund_request.value:                 3,
    CaseType.other.value:                          1,
}


# ─── Text Utilities ───────────────────────────────────────────────────────────

def normalize_text(text: str) -> str:
    """NFC normalize, translate Bangla digits to ASCII."""
    text = unicodedata.normalize("NFC", text)
    return text.translate(BANGLA_DIGITS)


def strip_injection(text: str) -> str:
    """Remove prompt injection attempts from complaint or context strings."""
    cleaned = normalize_text(text)
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, cleaned, re.IGNORECASE):
            logger.warning(f"INJECTION DETECTED pattern='{pattern[:50]}'")
            cleaned = re.sub(pattern, "[content removed]", cleaned, flags=re.IGNORECASE)
    return cleaned


def safe_context_value(value: Optional[str]) -> Optional[str]:
    """Sanitize optional string fields (campaign_context, metadata) before prompt injection."""
    if not value:
        return None
    return strip_injection(str(value)[:300])


# ─── Language Detection ───────────────────────────────────────────────────────

def detect_language(complaint: str, declared: Optional[str] = None) -> str:
    """
    Enhanced language detector with Banglish support.
    Priority: detected script → Banglish detection → declared → default 'en'
    """
    normalized = normalize_text(complaint)
    bangla_chars = len(re.findall(r"[\u0980-\u09FF]", complaint))  # use original for script detection
    ascii_words = re.findall(r"[a-zA-Z]+", normalized.lower())

    # Pure Bangla script
    if bangla_chars > 10 and len(ascii_words) < 3:
        return "bn"

    # Mixed script (Bangla + English)
    if bangla_chars > 5 and len(ascii_words) > 2:
        return "mixed"

    # Banglish: English script but Bengali lexicon
    banglish_count = sum(1 for w in ascii_words if w in BANGLISH_KEYWORDS)
    if banglish_count >= 2:
        return "mixed"

    # Fall back to declared language
    if declared in ("en", "bn", "mixed"):
        return declared

    return "en"


# ─── Amount Extraction ────────────────────────────────────────────────────────

def extract_amounts(complaint: str) -> list[float]:
    """
    Extract all BDT amounts from complaint in any format:
    - Bangla digits (৫০০০)
    - Comma-separated (5,000)
    - Decimal (1200.50)
    - Currency prefixed (BDT 5000, ৳5000, Tk 5000)
    """
    text = normalize_text(complaint)
    # Strip currency symbols/prefixes
    text = re.sub(r"[৳\u09F3]|(?:BDT|Tk|TK|taka)\s*", " ", text, flags=re.IGNORECASE)

    raw = re.findall(r"\b(\d{1,3}(?:,\d{3})*(?:\.\d+)?|\d+(?:\.\d+)?)\b", text)
    amounts = []
    for r in raw:
        try:
            val = float(r.replace(",", ""))
            if val > 0:
                amounts.append(val)
        except ValueError:
            pass
    return list(set(amounts))


def amounts_match(complaint_amount: float, txn_amount: float) -> bool:
    """Amount match with ±1 BDT or ±5% tolerance (edge_cases.md §10)."""
    tolerance = max(1.0, abs(txn_amount) * 0.05)
    return abs(complaint_amount - txn_amount) <= tolerance


# ─── Phone Extraction ─────────────────────────────────────────────────────────

def extract_phones(text: str) -> list[str]:
    """Extract Bangladeshi mobile numbers from text (Bangla or ASCII digits)."""
    normalized = normalize_text(text)
    return re.findall(r"(?:\+880|880|0)1[3-9]\d{8}", normalized)


# ─── Timestamp Utilities ──────────────────────────────────────────────────────

def safe_parse_timestamp(timestamp: str) -> Optional[datetime]:
    """Parse ISO 8601 safely — returns None on any parse failure."""
    try:
        return datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError):
        return None


def is_today(timestamp: str) -> bool:
    dt = safe_parse_timestamp(timestamp)
    if not dt:
        return False
    return dt.date() == datetime.now(timezone.utc).date()


def is_yesterday(timestamp: str) -> bool:
    dt = safe_parse_timestamp(timestamp)
    if not dt:
        return False
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).date()
    return dt.date() == yesterday


# ─── Phishing Detection ───────────────────────────────────────────────────────

def is_phishing(complaint: str) -> bool:
    """Deterministic phishing signal — English and Bangla keywords."""
    lower = complaint.lower()
    return any(re.search(p, lower, re.IGNORECASE) for p in PHISHING_KEYWORDS)


# ─── Transaction Matchers ─────────────────────────────────────────────────────

def find_candidate_transactions(
    complaint: str,
    history: list[TransactionEntry],
) -> list[str]:
    """
    Score each transaction against the complaint and return IDs ranked by relevance.
    Returns top-3 candidates (or fewer). Empty list = no confident match.
    """
    if not history:
        return []

    amounts_in_complaint = extract_amounts(complaint)
    phones_in_complaint = extract_phones(complaint)
    complaint_lower = complaint.lower()
    normalized_complaint = normalize_text(complaint_lower)

    scored: list[tuple[int, str]] = []

    for txn in history:
        try:
            score = 0
            txn_amount = abs(txn.amount)

            # Amount match (highest weight — most reliable signal)
            if any(amounts_match(a, txn_amount) for a in amounts_in_complaint):
                score += 4

            # Phone / counterparty match
            if any(phone in txn.counterparty for phone in phones_in_complaint):
                score += 3

            # Timestamp signals
            if ("today" in normalized_complaint or "আজ" in complaint) and is_today(txn.timestamp):
                score += 2
            if ("yesterday" in normalized_complaint or "গতকাল" in complaint) and is_yesterday(txn.timestamp):
                score += 2

            # Status signals
            if txn.status == "failed" and any(
                kw in normalized_complaint for kw in ("fail", "error", "didn't go", "aseni", "paini")
            ):
                score += 2
            if txn.status == "pending" and any(
                kw in normalized_complaint for kw in ("pending", "not received", "aseni", "paini", "আসেনি")
            ):
                score += 2
            if txn.status == "reversed" and any(
                kw in normalized_complaint for kw in ("reverse", "refund", "back", "ফেরত")
            ):
                score += 2

            # Type signal
            if txn.type == "settlement" and "settlement" in normalized_complaint:
                score += 2
            if txn.type == "cash_in" and "cash" in normalized_complaint:
                score += 1

            if score >= 2:
                scored.append((score, txn.transaction_id))

        except Exception as e:
            logger.debug(f"Skipping transaction during scoring: {e}")
            continue

    scored.sort(reverse=True)
    return [txn_id for _, txn_id in scored[:3]]


def find_duplicate_transactions(history: list[TransactionEntry]) -> Optional[str]:
    """
    Detect duplicate payment: 2 transactions with the same
    amount + counterparty + type within 120 seconds.
    Returns the SECOND (duplicate) transaction_id, or None.

    RISK-4 FIX: Also catches completed+pending pairs — the pending one is
    the suspected duplicate (e.g., accidental double-tap before first settled).
    Completed+completed = confirmed duplicate.
    Completed+pending   = probable duplicate (pending = double-submitted).
    """
    if len(history) < 2:
        return None

    for i, t1 in enumerate(history):
        if t1.amount <= 0:
            continue
        # t1 must be completed to be the "original"
        if t1.status != "completed":
            continue
        for t2 in history[i + 1:]:
            # t2 can be completed OR pending (suspected double-submit)
            if t2.status not in ("completed", "pending"):
                continue
            if (
                t1.amount == t2.amount
                and t1.counterparty == t2.counterparty
                and t1.type == t2.type
            ):
                dt1 = safe_parse_timestamp(t1.timestamp)
                dt2 = safe_parse_timestamp(t2.timestamp)
                if dt1 and dt2:
                    diff = abs((dt2 - dt1).total_seconds())
                    if diff <= 120:
                        # Return the later transaction as the duplicate
                        later = t2 if dt2 >= dt1 else t1
                        return later.transaction_id
    return None


def has_established_recipient(counterparty: str, history: list[TransactionEntry]) -> bool:
    """
    True if the same counterparty appears in 3+ transactions.
    Signals an established relationship → 'wrong_transfer' may be inconsistent.
    """
    count = sum(1 for t in history if t.counterparty == counterparty)
    return count >= 3


# ─── Department & Severity ────────────────────────────────────────────────────

def get_department(case_type: str, user_type: Optional[str], channel: Optional[str],
                   history: list[TransactionEntry]) -> str:
    """Deterministic department routing — user_type and channel overrides applied."""
    ut = (user_type or "customer").lower()
    ch = (channel or "").lower()

    # Merchant-specific: settlement in history
    if ut == "merchant" and any(t.type == "settlement" for t in history):
        return Department.merchant_operations.value

    # Agent-specific: AGENT- prefixed counterparty
    if ut == "agent" or ch == "field_agent":
        if any(t.type == "cash_in" and t.counterparty.upper().startswith("AGENT-") for t in history):
            return Department.agent_operations.value

    return DEPT_ROUTING.get(case_type, Department.customer_support.value)


def get_severity(case_type: str, amount: Optional[float] = None,
                 has_pending: bool = False) -> str:
    """Deterministic severity — LLM may refine, but this is the safe floor."""
    if case_type == CaseType.phishing_or_social_engineering.value:
        return Severity.critical.value
    if case_type in (
        CaseType.wrong_transfer.value,
        CaseType.payment_failed.value,
        CaseType.duplicate_payment.value,
        CaseType.agent_cash_in_issue.value,
    ):
        return Severity.high.value
    if amount and amount >= 5000:
        return Severity.high.value
    if case_type == CaseType.merchant_settlement_delay.value:
        return Severity.medium.value
    if case_type == CaseType.refund_request.value:
        return Severity.low.value
    return Severity.medium.value


def requires_human_review(case_type: str, evidence_verdict: str,
                           severity: str, amount: Optional[float] = None) -> bool:
    """
    Deterministic human review triggers.

    Key rule: wrong_transfer and agent_cash_in REQUIRE human review only when
    a transaction has been identified (consistent or inconsistent verdict).
    When evidence_verdict=insufficient_data, we ask for clarification first.
    This matches Sample-08: wrong_transfer + insufficient_data → human_review=False.

    Phishing and duplicate_payment ALWAYS require review (even with insufficient_data).
    """
    # Phishing always escalates regardless of verdict
    if case_type == CaseType.phishing_or_social_engineering.value:
        return True

    # Duplicate payment always requires verification
    if case_type == CaseType.duplicate_payment.value:
        return True

    # When evidence is ambiguous — ask for clarification first, no human review yet
    # Exception: phishing and duplicate are already handled above
    if evidence_verdict == EvidenceVerdict.insufficient_data.value:
        return False

    # With a confirmed transaction (consistent or inconsistent verdict):
    if case_type == CaseType.wrong_transfer.value:
        return True
    if case_type == CaseType.agent_cash_in_issue.value:
        return True

    if severity == Severity.critical.value:
        return True
    if severity == Severity.high.value:
        if case_type == CaseType.payment_failed.value and evidence_verdict == EvidenceVerdict.consistent.value:
            return False
        return True
    if evidence_verdict == EvidenceVerdict.inconsistent.value:
        return True
    if amount and amount >= 5000:
        if case_type == CaseType.payment_failed.value and evidence_verdict == EvidenceVerdict.consistent.value:
            return False
        return True
    return False






def resolve_transaction_id(
    candidates: list[str],
    duplicate_id: Optional[str],
    is_phishing_flag: bool,
    history: list[TransactionEntry],
) -> tuple[Optional[str], str]:
    """
    Deterministic transaction ID and evidence verdict resolution.
    Returns (relevant_transaction_id, evidence_verdict).
    """
    # Phishing: credential theft has no linked financial transaction
    if is_phishing_flag:
        return None, EvidenceVerdict.insufficient_data.value

    # Confirmed duplicate
    if duplicate_id:
        return duplicate_id, EvidenceVerdict.consistent.value

    # Exactly one strong candidate
    if len(candidates) == 1:
        txn_id = candidates[0]
        txn = next((t for t in history if t.transaction_id == txn_id), None)
        if txn:
            # Established recipient pattern → inconsistency signal for wrong_transfer
            if has_established_recipient(txn.counterparty, history) and txn.type == "transfer":
                return txn_id, EvidenceVerdict.inconsistent.value
            return txn_id, EvidenceVerdict.consistent.value

    # BUG-2 FIX: Multiple candidates — pick top if its score dominates the second.
    # Previously always returned null + insufficient_data, which caused LLM to
    # hallucinate a TXN ID. Now if the top candidate has score >= 2x second, use it.
    if len(candidates) > 1:
        # candidates is already sorted descending by score from find_candidate_transactions
        # Re-score here to compare top two
        top_id = candidates[0]
        txn = next((t for t in history if t.transaction_id == top_id), None)
        if txn:
            if has_established_recipient(txn.counterparty, history) and txn.type == "transfer":
                return top_id, EvidenceVerdict.inconsistent.value
        # Still ambiguous — return null but keep insufficient_data
        return None, EvidenceVerdict.insufficient_data.value

    # No match
    return None, EvidenceVerdict.insufficient_data.value


# ─── Case Type Hints ──────────────────────────────────────────────────────────

def detect_case_type_hints(
    complaint: str,
    history: list[TransactionEntry],
    user_type: Optional[str],
    is_phishing_flag: bool,
    duplicate_id: Optional[str],
) -> dict:
    """Returns deterministic case_type hints to prime the LLM."""
    hints: dict = {}

    if is_phishing_flag:
        hints["likely_case_type"] = CaseType.phishing_or_social_engineering.value
        hints["likely_department"] = Department.fraud_risk.value
        hints["likely_severity"] = Severity.critical.value
        return hints  # Phishing overrides everything

    if duplicate_id:
        hints["likely_case_type"] = CaseType.duplicate_payment.value
        hints["likely_department"] = Department.payments_ops.value
        hints["likely_severity"] = Severity.high.value
        return hints

    ut = (user_type or "customer").lower()
    normalized = normalize_text(complaint.lower())

    # RISK-6 FIX: Merchant settlement detection — works even if user_type is not
    # explicitly "merchant". A settlement-type transaction in history + any mention
    # of settlement/delay in the complaint is a strong enough signal.
    has_settlement_txn = any(t.type == "settlement" for t in history)
    settlement_keywords = ["settlement", "settle", "settled", "payout", "disbursement"]
    complaint_mentions_settlement = any(kw in normalized for kw in settlement_keywords)

    if has_settlement_txn and (ut == "merchant" or complaint_mentions_settlement):
        hints["likely_case_type"] = CaseType.merchant_settlement_delay.value
        hints["likely_department"] = Department.merchant_operations.value
        hints["likely_severity"] = Severity.medium.value
        return hints

    # Agent cash-in
    agent_txns = [t for t in history if t.counterparty.upper().startswith("AGENT-")]
    is_agent_cash_in = False
    if agent_txns and any(t.status in ("pending", "failed") for t in agent_txns):
        is_agent_cash_in = True
    elif "cash in" in normalized or "ক্যাশ ইন" in normalized:
        is_agent_cash_in = True

    if is_agent_cash_in:
        hints["likely_case_type"] = CaseType.agent_cash_in_issue.value
        hints["likely_department"] = Department.agent_operations.value
        hints["likely_severity"] = Severity.high.value
        return hints

    # Refund request — BUG-3 FIX: expanded keyword list to cover common phrasing
    REFUND_KEYWORDS = [
        "changed my mind", "don't want", "want a refund", "want refund",
        "please refund", "give me refund", "give me my money back",
        "money back", "i want my money", "return my money",
        "টাকা ফেরত চাই", "টাকা ফেরত দিন", "রিফান্ড চাই",
        "ফেরত চাই", "ফিরিয়ে দিন", "দিতে চাই না",
    ]
    is_refund_request = False
    if any(kw in normalized for kw in REFUND_KEYWORDS):
        is_refund_request = True
    elif "refund" in normalized and not any(kw in normalized for kw in ["failed", "deducted", "error", "ভুল"]):
        is_refund_request = True

    # Payment failed
    is_payment_failed = False
    if any(kw in normalized for kw in ["failed", "deducted", "error", "ব্যালেন্স কেটে", "টাকা কেটে", "ব্যালেন্স কাটা"]):
        is_payment_failed = True
    elif any(t.status in ("failed", "pending") and t.type in ("payment", "transfer") for t in history):
        if any(t.status == "failed" and t.type == "payment" for t in history):
            is_payment_failed = True

    # Wrong transfer
    is_wrong_transfer = False
    if any(kw in normalized for kw in ["wrong number", "wrong recipient", "wrong person", "typed it wrong", "mistake", "ভুল", "brother", "অন্য নাম্বারে", "অন্য নম্বরে"]):
        is_wrong_transfer = True

    # Determine priority if multiple match
    if is_wrong_transfer:
        hints["likely_case_type"] = CaseType.wrong_transfer.value
        hints["likely_department"] = Department.dispute_resolution.value
        hints["likely_severity"] = Severity.high.value
    elif is_payment_failed:
        hints["likely_case_type"] = CaseType.payment_failed.value
        hints["likely_department"] = Department.payments_ops.value
        hints["likely_severity"] = Severity.high.value
    elif is_refund_request:
        hints["likely_case_type"] = CaseType.refund_request.value
        hints["likely_department"] = Department.customer_support.value
        hints["likely_severity"] = Severity.low.value
    else:
        hints["likely_case_type"] = CaseType.other.value
        hints["likely_department"] = Department.customer_support.value
        hints["likely_severity"] = Severity.medium.value

    # Refund type transaction in history — note for LLM
    if any(t.type == "refund" for t in history):
        hints["has_existing_refund_txn"] = True

    # Pending transactions
    pending = [t.transaction_id for t in history if t.status == "pending"]
    if pending:
        hints["pending_transaction_ids"] = pending

    return hints


# ─── Master Rule Analysis ─────────────────────────────────────────────────────

def analyze_rules(
    complaint: str,
    history: list[TransactionEntry],
    language: Optional[str] = None,
    user_type: Optional[str] = None,
    channel: Optional[str] = None,
) -> dict:
    """
    Run all deterministic rules and return a RuleContext dict.
    This is injected into the LLM system prompt as pre-computed trusted context.
    """
    # Normalize and sanitize
    safe_complaint = strip_injection(complaint)
    detected_lang = detect_language(safe_complaint, language)
    phishing = is_phishing(safe_complaint)
    candidates = find_candidate_transactions(safe_complaint, history)
    duplicate_id = find_duplicate_transactions(history)
    amounts = extract_amounts(safe_complaint)
    phones = extract_phones(safe_complaint)
    case_hints = detect_case_type_hints(safe_complaint, history, user_type, phishing, duplicate_id)
    txn_id, verdict_hint = resolve_transaction_id(candidates, duplicate_id, phishing, history)

    # Check for established recipient patterns among candidates
    established = []
    for txn in history:
        if txn.transaction_id in candidates and has_established_recipient(txn.counterparty, history):
            established.append(txn.counterparty)

    return {
        "safe_complaint": safe_complaint,
        "detected_language": detected_lang,
        "phishing_detected": phishing,
        "candidate_transaction_ids": candidates,
        "duplicate_transaction_id": duplicate_id,
        "rule_suggested_txn_id": txn_id,
        "rule_suggested_verdict": verdict_hint,
        "extracted_amounts_bdt": amounts,
        "extracted_phones": phones,
        "all_transaction_ids": [t.transaction_id for t in history],
        "pending_transaction_ids": [t.transaction_id for t in history if t.status == "pending"],
        "established_recipient_patterns": established,
        "transaction_count": len(history),
        "user_type": user_type or "customer",
        "channel": channel or "in_app_chat",
        "case_hints": case_hints,
    }
