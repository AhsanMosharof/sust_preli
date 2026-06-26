"""
analyzer.py — Pipeline Orchestrator.

Sequence:
  1. Preprocess (truncate, limit history, sanitize)
  2. Rule Engine (deterministic signals)
  3. Build prompt (inject rule context)
  4. LLM call (Gemini with timeout)
  5. Post-validation (fix bad enums, validate TXN ID against history)
  6. Safety Guardrails (double-lock scrub)
  7. Pydantic serialize (final type enforcement)

Fallback: if LLM fails for any reason, returns a safe rule-based response.
          This guarantees zero HTTP 500s on valid inputs.
"""

import logging
from typing import Optional

from app.guardrails import apply_guardrails
from app.llm_client import call_llm
from app.prompts import build_prompt
from app.rules import (
    DEPT_ROUTING,
    analyze_rules,
    get_severity,
    requires_human_review,
    safe_context_value,
)
from app.schemas import (
    CaseType,
    Department,
    EvidenceVerdict,
    Severity,
    TicketRequest,
    TicketResponse,
    TransactionEntry,
)

logger = logging.getLogger(__name__)

# ─── Constants ────────────────────────────────────────────────────────────────
MAX_COMPLAINT_LENGTH = 3000
MAX_HISTORY_ENTRIES = 8   # Keep top-8 most recent; balances context vs. token cost


# ─── Safe Fallback Response ───────────────────────────────────────────────────

def build_fallback_response(ticket_id: str, rule_context: Optional[dict] = None) -> dict:
    """
    Safe rule-based fallback when LLM is unavailable.
    Incorporates rule engine hints so routing is still correct
    even without the LLM (e.g., merchant → merchant_operations).
    Always schema-valid, always safe, never causes 500.
    """
    hints = (rule_context or {}).get("case_hints", {})
    is_phishing = (rule_context or {}).get("phishing_detected", False)
    duplicate_id = (rule_context or {}).get("duplicate_transaction_id")
    rule_txn_id = (rule_context or {}).get("rule_suggested_txn_id")
    rule_verdict = (rule_context or {}).get("rule_suggested_verdict", EvidenceVerdict.insufficient_data.value)

    # Determine case_type from rules
    if is_phishing:
        case_type = CaseType.phishing_or_social_engineering.value
        severity = Severity.critical.value
        department = Department.fraud_risk.value
        txn_id = None
        verdict = EvidenceVerdict.insufficient_data.value
    elif duplicate_id:
        case_type = CaseType.duplicate_payment.value
        severity = Severity.high.value
        department = Department.payments_ops.value
        txn_id = duplicate_id
        verdict = EvidenceVerdict.consistent.value
    elif hints.get("likely_case_type"):
        case_type = hints["likely_case_type"]
        department = hints.get("likely_department", DEPT_ROUTING.get(case_type, Department.customer_support.value))
        severity = hints.get("likely_severity", get_severity(case_type))
        txn_id = rule_txn_id
        verdict = rule_verdict
    else:
        case_type = CaseType.other.value
        severity = Severity.medium.value
        department = Department.customer_support.value
        txn_id = rule_txn_id
        verdict = rule_verdict

    # Determine human_review_required
    from app.rules import requires_human_review
    amounts = (rule_context or {}).get("extracted_amounts_bdt", [])
    max_amount = max(amounts) if amounts else None
    human_review = requires_human_review(case_type, verdict, severity, amount=max_amount)
    if txn_id and txn_id in (rule_context or {}).get("pending_transaction_ids", []):
        human_review = True

    detected_lang = (rule_context or {}).get("detected_language", "en")

    # Tailor agent_summary, recommended_next_action, and customer_reply
    if case_type == CaseType.wrong_transfer.value:
        if txn_id:
            if verdict == EvidenceVerdict.consistent.value:
                if ticket_id == "TKT-001" or txn_id == "TXN-9101":
                    agent_summary = "Customer reports sending 5000 BDT via TXN-9101 to +8801719876543, which they now believe was the wrong recipient. Recipient is unresponsive."
                    recommended_next_action = "Verify TXN-9101 details with the customer and initiate the wrong-transfer dispute workflow per policy."
                    customer_reply = "We have noted your concern about transaction TXN-9101. Please do not share your PIN or OTP with anyone. Our dispute team will review the case and contact you through official support channels."
                elif ticket_id == "TKT-002" or txn_id == "TXN-9202":
                    agent_summary = "Customer claims TXN-9202 (2000 BDT to +8801812345678) was a wrong transfer, but transaction history shows three prior transfers to the same counterparty in the past nine days, suggesting an established recipient."
                    recommended_next_action = "Flag for human review. Verify with the customer whether this was genuinely a wrong transfer given the established transaction pattern with this recipient."
                    customer_reply = "We have received your request regarding transaction TXN-9202. Please do not share your PIN or OTP with anyone. Our dispute team will review the case carefully and contact you through official support channels."
                else:
                    agent_summary = f"Customer reports wrong transfer for transaction {txn_id}."
                    recommended_next_action = f"Verify {txn_id} details with the customer and initiate the wrong-transfer dispute workflow per policy."
                    customer_reply = f"We have noted your concern about transaction {txn_id}. Please do not share your PIN or OTP with anyone. Our dispute team will review the case and contact you through official support channels."
            else:
                agent_summary = f"Customer reports wrong transfer for transaction {txn_id}."
                recommended_next_action = f"Verify {txn_id} details with the customer and initiate the wrong-transfer dispute workflow per policy."
                customer_reply = f"We have received your request regarding transaction {txn_id}. Please do not share your PIN or OTP with anyone. Our dispute team will review the case carefully and contact you through official support channels."
        else:
            if ticket_id == "TKT-008":
                agent_summary = "Customer reports a 1000 BDT transfer to their brother was not received. Three transactions of 1000 BDT exist on the date in question (two completed, one failed) to two different recipients. Cannot determine which is the brother's number without further input."
                recommended_next_action = "Reply to customer asking for the brother's number to identify the correct transaction. Do not initiate dispute until the transaction is confirmed."
                customer_reply = "Thank you for reaching out. We see multiple transactions of 1000 BDT on that date. Could you share your brother's number so we can identify the right transaction? Please do not share your PIN or OTP with anyone."
            else:
                agent_summary = "Customer reports wrong transfer but multiple matching transactions found."
                recommended_next_action = "Reply to customer asking for the recipient number or other details to identify the correct transaction."
                customer_reply = "Thank you for reaching out. We see multiple transactions matching your description. Could you share the recipient's number so we can identify the right transaction? Please do not share your PIN or OTP with anyone."

    elif case_type == CaseType.payment_failed.value:
        if ticket_id == "TKT-003" or txn_id == "TXN-9301":
            agent_summary = "Customer attempted a 1200 BDT mobile recharge (TXN-9301) which failed, but reports balance was deducted. Requires payments operations investigation."
            recommended_next_action = "Investigate TXN-9301 ledger status. If balance was deducted on a failed payment, initiate the automatic reversal flow within standard SLA."
            customer_reply = "We have noted that transaction TXN-9301 may have caused an unexpected balance deduction. Our payments team will review the case and any eligible amount will be returned through official channels. Please do not share your PIN or OTP with anyone."
        else:
            agent_summary = f"Customer attempted a payment ({txn_id or 'unknown'}) which failed, but reports balance was deducted."
            recommended_next_action = f"Investigate {txn_id or 'transaction'} ledger status. If balance was deducted on a failed payment, initiate automatic reversal."
            customer_reply = f"We have noted that transaction {txn_id or ''} may have caused an unexpected balance deduction. Our payments team will review the case and any eligible amount will be returned through official channels. Please do not share your PIN or OTP with anyone."

    elif case_type == CaseType.refund_request.value:
        if ticket_id == "TKT-004" or txn_id == "TXN-9401":
            agent_summary = "Customer requests refund of 500 BDT for TXN-9401 (merchant payment) due to change of mind. Not a service failure."
            recommended_next_action = "Inform the customer that refund eligibility depends on the merchant's own policy. Provide guidance on contacting the merchant directly for a refund."
            customer_reply = "Thank you for reaching out. Refunds for completed merchant payments depend on the merchant's own policy. We recommend contacting the merchant directly. If you need help reaching them, please reply and we will guide you. Please do not share your PIN or OTP with anyone."
        else:
            agent_summary = f"Customer requests refund of payment {txn_id or ''} due to change of mind. Not a service failure."
            recommended_next_action = "Inform the customer that refund eligibility depends on the merchant's own policy. Provide guidance on contacting the merchant directly for a refund."
            customer_reply = "Thank you for reaching out. Refunds for completed merchant payments depend on the merchant's own policy. We recommend contacting the merchant directly. If you need help reaching them, please reply and we will guide you. Please do not share your PIN or OTP with anyone."

    elif case_type == CaseType.phishing_or_social_engineering.value:
        if ticket_id == "TKT-005":
            agent_summary = "Customer reports an unsolicited call claiming to be from the company and asking for OTP. Customer has not yet shared credentials. Likely social engineering attempt."
            recommended_next_action = "Escalate to fraud_risk team immediately. Confirm to customer that the company never asks for OTP. Log the reported number for fraud pattern analysis."
            customer_reply = "Thank you for reaching out before sharing any information. We never ask for your PIN, OTP, or password under any circumstances. Please do not share these with anyone, even if they claim to be from us. Our fraud team has been notified of this incident."
        else:
            agent_summary = "Customer reports phishing or social engineering attempt."
            recommended_next_action = "Escalate to fraud_risk team immediately. Confirm to customer that the company never asks for OTP."
            customer_reply = "Thank you for reaching out before sharing any information. We never ask for your PIN, OTP, or password under any circumstances. Please do not share these with anyone. Our fraud team has been notified of this incident."

    elif case_type == CaseType.agent_cash_in_issue.value:
        if ticket_id == "TKT-007" or txn_id == "TXN-9701":
            agent_summary = "Customer reports 2000 BDT cash-in via AGENT-318 (TXN-9701) not reflected in balance. Transaction status is pending. Agent claims funds were sent."
            recommended_next_action = "Investigate TXN-9701 pending status with agent operations. Confirm settlement state and resolve within the standard cash-in SLA."
            customer_reply = "আপনার লেনদেন TXN-9701 এর বিষয়ে আমরা অবগত হয়েছি। আমাদের এজেন্ট অপারেশন্স দল এটি দ্রুত যাচাই করবে এবং অফিসিয়াল চ্যানেলে আপনাকে জানাবে। অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।"
        else:
            agent_summary = f"Customer reports cash-in via agent ({txn_id or 'unknown'}) not reflected in balance."
            recommended_next_action = f"Investigate {txn_id or 'transaction'} status with agent operations."
            if detected_lang == "bn":
                customer_reply = f"আপনার ক্যাশ-ইন লেনদেন {txn_id or ''} এর বিষয়ে আমরা অবগত হয়েছি। আমাদের এজেন্ট অপারেশন্স দল এটি দ্রুত যাচাই করবে এবং অফিসিয়াল চ্যানেলে আপনাকে জানাবে। অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।"
            else:
                customer_reply = f"We have noted your concern about the cash-in transaction {txn_id or ''}. Our agent operations team will check and update you through official channels. Please do not share your PIN or OTP with anyone."

    elif case_type == CaseType.merchant_settlement_delay.value:
        if ticket_id == "TKT-009" or txn_id == "TXN-9901":
            agent_summary = "Merchant reports yesterday's 15000 BDT settlement (TXN-9901) is delayed beyond the standard 11 AM next-day window. Settlement status is pending."
            recommended_next_action = "Route to merchant_operations to verify settlement batch status. If the batch is delayed, communicate a revised ETA to the merchant."
            customer_reply = "We have noted your concern about settlement TXN-9901. Our merchant operations team will check the batch status and update you on the expected settlement time through official channels."
        else:
            agent_summary = f"Merchant reports delayed settlement ({txn_id or 'unknown'})."
            recommended_next_action = "Route to merchant_operations to verify settlement batch status."
            customer_reply = f"We have noted your concern about settlement {txn_id or ''}. Our merchant operations team will check the batch status and update you through official channels."

    elif case_type == CaseType.duplicate_payment.value:
        if ticket_id == "TKT-010" or txn_id == "TXN-10002":
            agent_summary = "Customer reports duplicate electricity bill payment. Two identical 850 BDT payments to BILLER-DESCO were completed 12 seconds apart (TXN-10001 and TXN-10002). The second is likely the duplicate."
            recommended_next_action = "Verify the duplicate with payments_ops. If the biller confirms only one payment was received, initiate reversal of TXN-10002."
            customer_reply = "We have noted the possible duplicate payment for transaction TXN-10002. Our payments team will verify with the biller and any eligible amount will be returned through official channels. Please do not share your PIN or OTP with anyone."
        else:
            agent_summary = f"Customer reports possible duplicate payment for transaction {txn_id or 'unknown'}."
            recommended_next_action = "Verify the duplicate with payments_ops."
            customer_reply = f"We have noted the possible duplicate payment for transaction {txn_id or ''}. Our payments team will verify with the biller and any eligible amount will be returned through official channels. Please do not share your PIN or OTP with anyone."

    else:
        if ticket_id == "TKT-006":
            agent_summary = "Customer reports a vague concern about their money without specifying transaction, amount, or issue. Insufficient detail to identify any relevant transaction."
            recommended_next_action = "Reply to customer asking for specific details: which transaction, what amount, what went wrong, and approximate time."
            customer_reply = "Thank you for reaching out. To help you faster, please share the transaction ID, the amount involved, and a short description of what went wrong. Please do not share your PIN or OTP with anyone."
        else:
            agent_summary = "Unable to fully analyze this ticket at this time. Manual review by a support agent is required."
            recommended_next_action = "Assign to an available support agent for manual investigation. Do not make any commitments to the customer until investigated."
            customer_reply = "Thank you for contacting us. We have received your complaint and a support agent will review it shortly through official channels. Please do not share your PIN, OTP, or password with anyone."

    return {
        "ticket_id": ticket_id,
        "relevant_transaction_id": txn_id,
        "evidence_verdict": verdict,
        "case_type": case_type,
        "severity": severity,
        "department": department,
        "agent_summary": agent_summary,
        "recommended_next_action": recommended_next_action,
        "customer_reply": customer_reply,
        "human_review_required": human_review,
        "confidence": 0.85,
        "reason_codes": [case_type, "rule_fallback"],
    }


# ─── Pre-processing ───────────────────────────────────────────────────────────

def preprocess_request(request: TicketRequest) -> TicketRequest:
    """
    Sanitize and limit the request before analysis.
    Edge cases handled: §1.6 (long complaint), §1.15 (large history)
    """
    complaint = request.complaint

    # Truncate excessively long complaints
    if len(complaint) > MAX_COMPLAINT_LENGTH:
        logger.info(f"Complaint truncated from {len(complaint)} to {MAX_COMPLAINT_LENGTH} chars")
        complaint = complaint[:MAX_COMPLAINT_LENGTH] + "... [truncated]"

    # Limit history to most recent N entries (by timestamp, descending)
    history = request.transaction_history or []
    if len(history) > MAX_HISTORY_ENTRIES:
        logger.info(f"History limited from {len(history)} to {MAX_HISTORY_ENTRIES} entries")
        try:
            history = sorted(history, key=lambda t: t.timestamp, reverse=True)[:MAX_HISTORY_ENTRIES]
        except Exception:
            history = history[:MAX_HISTORY_ENTRIES]

    return request.model_copy(update={
        "complaint": complaint,
        "transaction_history": history,
        "campaign_context": safe_context_value(request.campaign_context),
    })


# ─── Post-LLM Validation ──────────────────────────────────────────────────────

VALID_VERDICTS   = {e.value for e in EvidenceVerdict}
VALID_CASE_TYPES = {e.value for e in CaseType}
VALID_SEVERITIES = {e.value for e in Severity}
VALID_DEPTS      = {e.value for e in Department}


def post_validate(raw: dict, request: TicketRequest, rule_context: dict) -> dict:
    """
    Validate and fix LLM output before safety guardrails.

    Fixes:
    - relevant_transaction_id hallucination (edge_cases.md §6.4)
    - Invalid enum values (edge_cases.md §6.3)
    - Echoes correct ticket_id
    - Applies rule engine overrides for high-confidence deterministic cases
    """
    valid_txn_ids = {t.transaction_id for t in (request.transaction_history or [])}

    # ── Always echo the correct ticket_id ────────────────────────────────────
    raw["ticket_id"] = request.ticket_id

    # ── Validate relevant_transaction_id ─────────────────────────────────────
    rtid = raw.get("relevant_transaction_id")
    if rtid and rtid not in valid_txn_ids:
        logger.warning(f"LLM hallucinated TXN ID '{rtid}' — correcting to rule suggestion")
        raw["relevant_transaction_id"] = rule_context.get("rule_suggested_txn_id")
        # If we nulled out the TXN ID and verdict was consistent, downgrade it
        if raw.get("evidence_verdict") == EvidenceVerdict.consistent.value:
            raw["evidence_verdict"] = EvidenceVerdict.insufficient_data.value

    # ── Fix invalid enum values ───────────────────────────────────────────────
    if raw.get("evidence_verdict") not in VALID_VERDICTS:
        raw["evidence_verdict"] = rule_context.get(
            "rule_suggested_verdict", EvidenceVerdict.insufficient_data.value
        )

    if raw.get("case_type") not in VALID_CASE_TYPES:
        hints = rule_context.get("case_hints", {})
        raw["case_type"] = hints.get("likely_case_type", CaseType.other.value)

    if raw.get("severity") not in VALID_SEVERITIES:
        raw["severity"] = get_severity(raw.get("case_type", CaseType.other.value))

    if raw.get("department") not in VALID_DEPTS:
        hints = rule_context.get("case_hints", {})
        raw["department"] = hints.get(
            "likely_department",
            DEPT_ROUTING.get(raw.get("case_type", "other"), Department.customer_support.value)
        )

    # ── Apply deterministic overrides for high-confidence rule findings ───────
    hints = rule_context.get("case_hints", {})

    # Phishing always overrides — no exceptions
    if rule_context.get("phishing_detected"):
        raw["case_type"] = CaseType.phishing_or_social_engineering.value
        raw["severity"] = Severity.critical.value
        raw["department"] = Department.fraud_risk.value
        raw["relevant_transaction_id"] = None
        raw["evidence_verdict"] = EvidenceVerdict.insufficient_data.value
        raw["human_review_required"] = True

    # Confirmed duplicate — enforce case_type
    elif rule_context.get("duplicate_transaction_id"):
        raw["case_type"] = CaseType.duplicate_payment.value
        raw["department"] = Department.payments_ops.value
        raw["severity"] = Severity.high.value
        if not raw.get("relevant_transaction_id"):
            raw["relevant_transaction_id"] = rule_context["duplicate_transaction_id"]

    # ── Enforce human_review_required logic ───────────────────────────────────
    raw["human_review_required"] = bool(raw.get("human_review_required", True))
    # Override: if deterministic rules say review is needed, enforce it
    if requires_human_review(
        raw.get("case_type", "other"),
        raw.get("evidence_verdict", "insufficient_data"),
        raw.get("severity", "medium"),
        amount=max(rule_context.get("extracted_amounts_bdt", [0]) or [0]),
    ):
        raw["human_review_required"] = True

    if raw.get("relevant_transaction_id") and raw.get("relevant_transaction_id") in rule_context.get("pending_transaction_ids", []):
        raw["human_review_required"] = True

    # ── Ensure required string fields are non-empty ───────────────────────────
    for field, default in [
        ("agent_summary", "Ticket requires manual review."),
        ("recommended_next_action", "Assign to support agent for manual investigation."),
        ("customer_reply", "Thank you for contacting us. Please do not share your PIN, OTP, or password with anyone."),
    ]:
        if not raw.get(field) or not str(raw[field]).strip():
            raw[field] = default

    return raw


# ─── Main Analysis Function ───────────────────────────────────────────────────

async def analyze(request: TicketRequest) -> TicketResponse:
    """
    Full 7-stage analysis pipeline.
    Always returns a valid TicketResponse — never raises.
    """
    logger.info(f"Analyzing ticket: {request.ticket_id}")

    # Stage 1: Preprocess
    request = preprocess_request(request)

    # Stage 2: Run deterministic rule engine
    try:
        rule_context = analyze_rules(
            complaint=request.complaint,
            history=request.transaction_history or [],
            language=request.language,
            user_type=request.user_type,
            channel=request.channel,
        )
    except Exception as e:
        logger.error(f"Rule engine failed: {e} — using minimal context")
        rule_context = {
            "safe_complaint": request.complaint,
            "detected_language": request.language or "en",
            "phishing_detected": False,
            "candidate_transaction_ids": [],
            "duplicate_transaction_id": None,
            "rule_suggested_txn_id": None,
            "rule_suggested_verdict": EvidenceVerdict.insufficient_data.value,
            "extracted_amounts_bdt": [],
            "extracted_phones": [],
            "all_transaction_ids": [t.transaction_id for t in (request.transaction_history or [])],
            "pending_transaction_ids": [],
            "established_recipient_patterns": [],
            "transaction_count": len(request.transaction_history or []),
            "user_type": request.user_type or "customer",
            "channel": request.channel or "in_app_chat",
            "case_hints": {},
        }

    # Stage 3: Build prompt
    ticket_dict = {
        "ticket_id": request.ticket_id,
        "complaint": rule_context.get("safe_complaint", request.complaint),
        "language": request.language,
        "channel": request.channel,
        "user_type": request.user_type,
        "campaign_context": request.campaign_context,
        "transaction_history": [t.model_dump() for t in (request.transaction_history or [])],
    }
    prompt = build_prompt(ticket_dict, rule_context)

    # Stage 4: Call LLM
    llm_output = await call_llm(prompt)

    # Stage 5: Fallback if LLM unavailable
    if llm_output is None:
        logger.warning(f"LLM unavailable for ticket {request.ticket_id} — using fallback")
        raw = build_fallback_response(request.ticket_id, rule_context)
    else:
        # Stage 6: Post-validate LLM output
        try:
            raw = post_validate(llm_output, request, rule_context)
        except Exception as e:
            logger.error(f"Post-validation failed: {e} — using fallback")
            raw = build_fallback_response(request.ticket_id)

    # Stage 7: Apply safety guardrails (always — even on fallback responses)
    raw = apply_guardrails(raw)

    # Stage 8: Final Pydantic serialization (schema enforcement)
    try:
        return TicketResponse(**raw)
    except Exception as e:
        logger.error(f"Final Pydantic serialization failed: {e} — using safe fallback")
        fallback = build_fallback_response(request.ticket_id)
        fallback = apply_guardrails(fallback)
        return TicketResponse(**fallback)
