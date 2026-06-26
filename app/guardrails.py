"""
guardrails.py — Double-lock Safety Guardrail System.

This layer runs AFTER LLM output and is fully DETERMINISTIC.
It cannot be fooled by LLM hallucination or adversarial prompts.

Blocks (per edge_cases.md §5):
  - Credential requests: PIN, OTP, password (−15 pts penalty)
  - Unauthorized financial commitments: refund promises (−10 pts penalty)
  - Third-party redirects: external URLs, phone numbers (−10 pts penalty)

Always appends the safety reminder phrase to every customer_reply.
"""

import logging
import re

logger = logging.getLogger(__name__)

# ─── Safe canonical replacements ──────────────────────────────────────────────
SAFE_REFUND_PHRASE = "any eligible amount will be returned through official channels if applicable"
SAFE_UNBLOCK_PHRASE = "our team will review your account status through official channels"
SAFETY_REMINDER_EN = "Please do not share your PIN, OTP, or password with anyone."
SAFETY_REMINDER_BN = "অনুগ্রহ করে কারো সাথে আপনার পিন, ওটিপি বা পাসওয়ার্ড শেয়ার করবেন না।"

# ─── Guard 1: Credential Request Patterns (−15 pts) ──────────────────────────
CREDENTIAL_REQUEST_PATTERNS = [
    # English — affirmative credential requests only (not "do not share")
    r"\b(?<!not\s)(?<!don't\s)(?<!never\s)share\s+(?:your\s+)?(?:PIN|OTP|password|passcode|credentials?|security\s+code)\b(?!\s+with\s+anyone)",
    r"\bplease\s+(?:share|provide|send|give|enter|type)\s+(?:your\s+)?(?:PIN|OTP|password)\b",
    r"\bprovide\s+(?:your\s+)?(?:PIN|OTP|password|passcode)\b",
    r"\benter\s+(?:your\s+)?(?:PIN|OTP|password)\s+(?:to|for|in)\b",
    r"\bsend\s+(?:us\s+)?(?:your\s+)?(?:PIN|OTP|password)\b",
    r"\bgive\s+(?:us\s+)?(?:your\s+)?(?:PIN|OTP|password)\b",
    r"\bconfirm\s+(?:your\s+)?(?:PIN|OTP)\s+(?:to|for|by)\b",
    r"\bverify\s+(?:your\s+)?(?:account|PIN|OTP)\s+(?:by\s+)?(?:sharing|providing|sending|entering)\b",
    r"\bwhat\s+is\s+(?:your\s+)?(?:PIN|OTP|password)\b",
    r"\btell\s+(?:us|me)\s+(?:your\s+)?(?:PIN|OTP|password)\b",
    r"(?:4|6)[\s-]?digit\s+(?:PIN|OTP|code)\s+(?:to|for|please)\b",
    # Bangla script — affirmative requests
    r"পিন\s*(?:নম্বর|কোড)?\s*(?:দিন|পাঠান|শেয়ার করুন|জানান|বলুন)",
    r"ওটিপি\s*(?:দিন|পাঠান|শেয়ার করুন|জানান|বলুন)",
    r"পাসওয়ার্ড\s*(?:দিন|পাঠান|শেয়ার করুন|জানান|বলুন)",
]

# ─── Guard 2: Unauthorized Financial Commitment Patterns (−10 pts) ────────────
UNAUTHORIZED_COMMITMENT_PATTERNS = [
    (r"\bwe\s+will\s+(?:refund|return|reverse|credit)\s+(?:your\s+)?(?:money|amount|funds|taka|BDT|balance)\b",
     SAFE_REFUND_PHRASE),
    (r"\byou\s+will\s+(?:get|receive)\s+(?:your\s+)?(?:money|amount|refund|funds|taka)\s+back\b",
     SAFE_REFUND_PHRASE),
    (r"\bwe\s+are\s+(?:reversing|processing\s+(?:a\s+)?refund\s+for|refunding)\b",
     SAFE_REFUND_PHRASE),
    (r"\brefund\s+(?:has\s+been|will\s+be)\s+(?:processed|initiated|completed|issued|done|sent)\b",
     SAFE_REFUND_PHRASE),
    (r"\bmoney\s+has\s+been\s+(?:returned|credited|sent\s+back|refunded)\b",
     SAFE_REFUND_PHRASE),
    (r"\byour\s+(?:money|funds|balance|amount)\s+(?:has\s+been|will\s+be)\s+(?:restored|returned|credited|refunded)\b",
     SAFE_REFUND_PHRASE),
    (r"\bwe\s+guarantee\s+(?:a\s+)?(?:refund|return|reversal)\b",
     SAFE_REFUND_PHRASE),
    (r"\bwe\s+will\s+unblock\s+(?:your\s+)?account\b",
     SAFE_UNBLOCK_PHRASE),
    (r"\byour\s+account\s+(?:has\s+been|will\s+be)\s+(?:unblocked|restored|reactivated)\b",
     SAFE_UNBLOCK_PHRASE),
    # Bangla
    (r"আপনার\s+টাকা\s+(?:ফেরত\s+দেওয়া\s+হবে|ফিরিয়ে\s+দেব|ফেরত\s+পাবেন)",
     SAFE_REFUND_PHRASE),
    (r"রিফান্ড\s+(?:করা\s+হবে|দেওয়া\s+হবে|প্রসেস\s+হবে|হয়ে\s+গেছে)",
     SAFE_REFUND_PHRASE),
    (r"টাকা\s+ফেরত\s+(?:যাবে|দেওয়া\s+হবে)",
     SAFE_REFUND_PHRASE),
]

# ─── Guard 3: Third-Party Redirect Patterns (−10 pts) ────────────────────────
THIRD_PARTY_PATTERNS = [
    r"https?://\S+",                              # external URLs
    r"www\.\S+\.\S+",                             # www links
    r"\bvisit\s+\S+\.(?:com|net|org|io|bd)\b",   # domain references
    r"\bcall\s+(?:us\s+at\s+)?\+?\d{8,}",        # external phone numbers
    r"\bcontact\s+(?:us\s+at\s+)?\+?\d{8,}",
    r"\bwhatsapp\s+\+?\d{8,}",
]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _detect_language(text: str) -> str:
    """Quick language detection for choosing safety reminder language."""
    bangla_chars = len(re.findall(r"[\u0980-\u09FF]", text))
    return "bn" if bangla_chars > 5 else "en"


def _scrub_sentence_containing(text: str, pattern: str) -> str:
    """
    Remove the entire sentence(s) containing a match of pattern.
    Uses multiple sentence boundary patterns for English and Bangla.
    """
    # Split on English and Bangla sentence terminators
    sentences = re.split(r"(?<=[.!?।\u0964\u0965])\s+", text)
    cleaned = []
    removed = False
    for sentence in sentences:
        if re.search(pattern, sentence, re.IGNORECASE):
            logger.warning(
                f"GUARDRAIL SCRUBBED sentence. Pattern='{pattern[:50]}' | "
                f"Sentence='{sentence[:80]}'"
            )
            removed = True
        else:
            cleaned.append(sentence)
    result = " ".join(cleaned).strip()
    return result if result else ""


def _has_safety_reminder(text: str) -> bool:
    """Check if the safety reminder is already present (English or Bangla)."""
    # Check for key phrases in either language
    en_check = bool(re.search(r"(?:PIN|OTP|password).{0,30}(?:share|anyone)", text, re.IGNORECASE))
    bn_check = "পিন" in text and ("শেয়ার" in text or "কারো" in text)
    return en_check or bn_check


# ─── Main Guardrail Function ──────────────────────────────────────────────────

def apply_guardrails(response: dict) -> dict:
    """
    Apply all safety guardrails to the response dict.
    Modifies customer_reply, recommended_next_action, and agent_summary in-place.
    This function is deterministic and cannot be bypassed by LLM output.

    Returns the sanitized response dict.
    """
    customer_reply = str(response.get("customer_reply", "")).strip()
    recommended_action = str(response.get("recommended_next_action", "")).strip()
    agent_summary = str(response.get("agent_summary", "")).strip()
    lang = _detect_language(customer_reply)

    # ── Guard 1: Remove credential request patterns ───────────────────────────
    for pattern in CREDENTIAL_REQUEST_PATTERNS:
        if re.search(pattern, customer_reply, re.IGNORECASE):
            logger.warning(
                f"SAFETY VIOLATION BLOCKED [credential request]: pattern='{pattern[:50]}'"
            )
            customer_reply = _scrub_sentence_containing(customer_reply, pattern)

    # Also check recommended_action for credential patterns
    for pattern in CREDENTIAL_REQUEST_PATTERNS:
        if re.search(pattern, recommended_action, re.IGNORECASE):
            logger.warning(
                f"SAFETY VIOLATION BLOCKED [credential in action]: pattern='{pattern[:50]}'"
            )
            recommended_action = _scrub_sentence_containing(recommended_action, pattern)

    # ── Guard 2: Replace unauthorized financial commitments ───────────────────
    for pattern, safe_replacement in UNAUTHORIZED_COMMITMENT_PATTERNS:
        if re.search(pattern, customer_reply, re.IGNORECASE):
            logger.warning(
                f"SAFETY VIOLATION BLOCKED [unauthorized commitment]: pattern='{pattern[:50]}'"
            )
            customer_reply = re.sub(
                pattern, safe_replacement, customer_reply, flags=re.IGNORECASE
            )
        if re.search(pattern, recommended_action, re.IGNORECASE):
            recommended_action = re.sub(
                pattern, safe_replacement, recommended_action, flags=re.IGNORECASE
            )

    # ── Guard 3: Remove third-party redirect patterns ─────────────────────────
    for pattern in THIRD_PARTY_PATTERNS:
        if re.search(pattern, customer_reply, re.IGNORECASE):
            logger.warning(
                f"SAFETY VIOLATION BLOCKED [third-party redirect]: pattern='{pattern[:50]}'"
            )
            customer_reply = _scrub_sentence_containing(customer_reply, pattern)

    # ── Guard 4: Ensure safety reminder is present ────────────────────────────
    if not _has_safety_reminder(customer_reply):
        reminder = SAFETY_REMINDER_BN if lang == "bn" else SAFETY_REMINDER_EN
        customer_reply = customer_reply.rstrip() + " " + reminder

    # ── Guard 5: Emergency fallback — if customer_reply is empty after scrubbing ─
    if not customer_reply.strip():
        logger.warning("GUARDRAIL: customer_reply was emptied by scrubbing — using safe fallback")
        customer_reply = (
            "Thank you for contacting us. Our team will review your case through official "
            "support channels. " + SAFETY_REMINDER_EN
        )

    # ── Guard 6: Scrub third-party URLs/phones from agent_summary (HALL-2) ──────
    # The LLM occasionally embeds raw phone numbers or URLs in the agent_summary
    # that could mislead agents into contacting external parties.
    for pattern in THIRD_PARTY_PATTERNS:
        if re.search(pattern, agent_summary, re.IGNORECASE):
            logger.warning(
                f"GUARDRAIL: third-party link/phone in agent_summary — pattern='{pattern[:50]}'"
            )
            agent_summary = _scrub_sentence_containing(agent_summary, pattern)

    response["customer_reply"] = customer_reply.strip()
    response["recommended_next_action"] = recommended_action.strip() or \
        "Assign to available support agent for manual review."
    response["agent_summary"] = agent_summary.strip() or \
        "Ticket requires manual review by a support agent."

    return response
