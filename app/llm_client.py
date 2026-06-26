"""
llm_client.py — Gemini API wrapper with timeout, JSON mode, and robust parsing.

Handles all LLM failure modes from edge_cases.md §6:
  - Timeout (asyncio.wait_for with 20s hard limit)
  - Non-JSON response (markdown stripping + regex extraction)
  - String booleans ("true" → True)
  - Out-of-range confidence (clamped 0.0–1.0)
  - Missing required fields (safe defaults applied)
  - Rate limit / API errors (caught → None returned → fallback activated)
"""

import asyncio
import json
import logging
import os
import re
from typing import Optional

logger = logging.getLogger(__name__)

_model = None


def get_model():
    """Initialize and cache the Gemini model. Called once at startup."""
    global _model
    if _model is not None:
        return _model

    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise ValueError(
            "GEMINI_API_KEY is not set. "
            "Get a free key at https://aistudio.google.com/ and add it to .env"
        )

    import google.generativeai as genai

    genai.configure(api_key=api_key)

    model_name = os.getenv("MODEL_NAME", "gemini-2.5-flash")
    logger.info(f"Initializing LLM client: model={model_name}")

    _model = genai.GenerativeModel(
        model_name=model_name,
        generation_config=genai.GenerationConfig(
            response_mime_type="application/json",  # enforce JSON output at API level
            temperature=0.1,                         # low temp = more deterministic
            max_output_tokens=2500,                  # increased from 1400 — prevents JSON truncation mid-field
        ),
    )
    return _model


def parse_llm_output(raw_text: str) -> Optional[dict]:
    """
    Robustly parse LLM output — handles all common failure modes:
    1. Markdown code fences (```json ... ```)
    2. Extra text before/after JSON
    3. Invalid JSON → regex extraction fallback
    """
    if not raw_text or not raw_text.strip():
        return None

    text = raw_text.strip()

    # Strip markdown code fences
    if "```" in text:
        parts = text.split("```")
        for part in parts:
            cleaned = part.strip()
            if cleaned.startswith("json"):
                cleaned = cleaned[4:].strip()
            if cleaned.startswith("{"):
                text = cleaned
                break

    # Direct JSON parse (most cases)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Fallback: extract JSON object with regex (handles trailing text)
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    logger.warning(f"Could not parse LLM output as JSON. Preview: {text[:200]}")
    return None


def normalize_llm_output(raw: dict) -> dict:
    """
    Normalize common type issues from LLM output before Pydantic validation.
    - String booleans → bool
    - Out-of-range confidence → clamped
    - None booleans → True (safe default)
    - Missing optional fields → safe defaults
    """
    # Boolean normalization
    for field in ("human_review_required",):
        val = raw.get(field)
        if isinstance(val, str):
            raw[field] = val.strip().lower() in ("true", "yes", "1")
        elif val is None:
            raw[field] = True  # safe default

    # Confidence clamping
    if "confidence" in raw and raw["confidence"] is not None:
        try:
            raw["confidence"] = max(0.0, min(1.0, float(raw["confidence"])))
        except (TypeError, ValueError):
            raw["confidence"] = None

    # Ensure reason_codes is a list or None
    if "reason_codes" in raw:
        if not isinstance(raw["reason_codes"], (list, type(None))):
            raw["reason_codes"] = None

    # Ensure string fields are actually strings
    for field in ("agent_summary", "recommended_next_action", "customer_reply", "ticket_id"):
        if field in raw and raw[field] is not None:
            raw[field] = str(raw[field]).strip()

    return raw


async def call_llm(prompt: str) -> Optional[dict]:
    """
    Call Gemini with the full prompt string.
    Returns parsed+normalized dict, or None on any failure.
    The caller is responsible for applying fallback logic when None is returned.

    Retry policy: on 429 ResourceExhausted (per-minute quota), waits 2s and
    retries once. This handles burst rate limits without burning timeout budget.
    """
    timeout = int(os.getenv("LLM_TIMEOUT_SECONDS", "20"))

    try:
        model = get_model()
    except ValueError as e:
        logger.error(f"LLM not configured: {e}")
        return None

    async def _attempt() -> Optional[dict]:
        try:
            loop = asyncio.get_event_loop()
            response = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: model.generate_content(prompt)),
                timeout=timeout,
            )
            raw_text = response.text.strip() if response.text else ""
            parsed = parse_llm_output(raw_text)
            if parsed is None:
                logger.warning("LLM returned unparseable output — activating fallback")
                return None
            return normalize_llm_output(parsed)
        except asyncio.TimeoutError:
            logger.warning(f"LLM call timed out after {timeout}s — activating fallback")
            return None

    try:
        return await _attempt()

    except Exception as e:
        err_type = type(e).__name__
        err_msg = str(e)[:200]

        # 429 ResourceExhausted — wait 2s and retry once (per-minute quota resets)
        if "429" in err_msg or "ResourceExhausted" in err_type or "quota" in err_msg.lower():
            logger.warning(f"LLM 429 quota hit — waiting 2s before retry")
            await asyncio.sleep(2)
            try:
                return await _attempt()
            except Exception as e2:
                logger.error(f"LLM retry also failed [{type(e2).__name__}]: {str(e2)[:150]} — activating fallback")
                return None

        # All other errors (401, 500, network) — fail fast
        logger.error(f"LLM call failed [{err_type}]: {err_msg} — activating fallback")
        return None

