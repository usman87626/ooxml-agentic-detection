"""
intent_analyzer.py — Deterministic text extraction and LLM-based intent classification.
"""
from __future__ import annotations
import logging
import time
import re

import config
from agents.guardrails import sanitize_for_prompt, strip_xml_tags_and_normalize
from analysis.instructions.loader import load_instruction

from pydantic import BaseModel, field_validator

class IntentResponse(BaseModel):
    intent: str
    intent_confidence: float
    risk_keywords: list[str]
    explanation: str

    @field_validator("intent_confidence")
    def normalize_confidence(cls, v: float) -> float:
        if v > 1.0:
            return v / 100.0
        return v

_SYSTEM_PROMPT = load_instruction("intent_analyzer")

logger = logging.getLogger(__name__)

def get_text_stats(manifest: dict) -> dict:
    """
    Extract visible text and calculate density/length.
    
    Output:
        visible_text: str
        visible_text_length: int
        text_density_score: float
        intent_candidates: list[str] | None
    """
    # Use existing extractor if it already provided visible_text_extract
    # Otherwise, fallback to scanning entries
    visible_ext = manifest.get("visible_text_extract", {})
    full_parts = []
    
    if visible_ext:
        for part, text in visible_ext.items():
            full_parts.append(text)
    else:
        # Fallback manual extraction
        for entry in manifest.get("entries", []):
            kind = (entry.get("classification") or {}).get("kind", "")
            if "xml" in kind or "text" in kind:
                decoded = entry.get("decoded") or {}
                text = decoded.get("decoded_text_utf8", "")
                if text.strip():
                    clean = strip_xml_tags_and_normalize(text)
                    if clean:
                        full_parts.append(clean)

    full_text = "\n".join(full_parts)
    
    # Clean boilerplate / repeated whitespace / strip
    # We apply sanitization and length capping later in classify_intent
    cleaned_text = re.sub(r'\s+', ' ', full_text).strip()
    text_len = len(cleaned_text)
    
    return {
        "visible_text": cleaned_text,
        "visible_text_length": text_len,
        "intent_candidates": None,
    }

async def classify_intent(visible_text: str, doc_type: str = "Unknown") -> IntentResponse:
    """
    LLM Task 1: Classify intent from visible text.
    """
    if not visible_text.strip():
        return IntentResponse(intent="unknown", intent_confidence=0.0, risk_keywords=[], explanation="No visible text found.")

    try:
        client = config.get_openai_client()
    except RuntimeError:
        return IntentResponse(intent="unknown", intent_confidence=0.0, risk_keywords=[], explanation="Internal error: OpenAI client untrusted.")

    safe_text = sanitize_for_prompt(visible_text, max_chars=config.MAX_SAFE_TEXT_CHARS, label="document text")
    
    user_message = (
        "Classify the intent of this document based on its visible text contents.\n"
        f"Document Type: {doc_type}\n\n"
        f"{safe_text}"
    )

    try:
        response = client.beta.chat.completions.parse(
            model=config.OPENAI_MODEL_ANALYSIS,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_message}
            ],
            response_format=IntentResponse,
            max_completion_tokens=config.LLM_MAX_COMPLETION_TOKENS_ANALYSIS,
            temperature=config.LLM_TEMPERATURE,
        )
        return response.choices[0].message.parsed
    except Exception as e:
        logger.error(f"Intent classification failed: {e}")
        return IntentResponse(intent="unknown", intent_confidence=0.0, risk_keywords=[], explanation=f"Error during classification: {e}")
