"""
macro_behavior_analyzer.py — LLM Task 2: Analyze macro code for behavioral risk.
"""
from __future__ import annotations
import logging
import config
from agents.guardrails import sanitize_for_prompt
from analysis.instructions.loader import load_instruction
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class MacroBehaviorResponse(BaseModel):
    macro_behavior: str
    macro_risk_score: int
    macro_indicators: list[str]

_SYSTEM_PROMPT = load_instruction("macro_analyzer") # We can reuse or refine this

async def analyze_behavior(macro_code: str, vba_indicators: list[str], doc_type: str = "Unknown") -> MacroBehaviorResponse:
    """
    LLM Task 2: Analyze macro code for behavioral risk.
    """
    if not macro_code.strip():
        return MacroBehaviorResponse(
            macro_behavior="No macro code present for analysis.",
            macro_risk_score=0,
            macro_indicators=[]
        )

    try:
        client = config.get_openai_client()
    except RuntimeError:
        return MacroBehaviorResponse(
            macro_behavior="Analysis unavailable.",
            macro_risk_score=0,
            macro_indicators=[]
        )

    safe_code = sanitize_for_prompt(macro_code, max_chars=15000, label="vba macro code")
    
    user_message = (
        "Analyze the following extracted VBA macro code for malicious behavior.\n"
        f"Document Type: {doc_type}\n"
        f"Static OLEVBA Indicators: {vba_indicators}\n\n"
        f"{safe_code}"
    )

    try:
        response = client.beta.chat.completions.parse(
            model=config.OPENAI_MODEL_ANALYSIS,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_message}
            ],
            response_format=MacroBehaviorResponse,
            max_completion_tokens=config.LLM_MAX_COMPLETION_TOKENS_ANALYSIS,
            temperature=config.LLM_TEMPERATURE,
        )
        return response.choices[0].message.parsed
    except Exception as e:
        logger.error(f"Macro behavior analysis failed: {e}")
        return MacroBehaviorResponse(
            macro_behavior=f"Analysis failed: {str(e)}",
            macro_risk_score=0,
            macro_indicators=[]
        )
