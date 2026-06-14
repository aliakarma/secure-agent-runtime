import re
import os
from pydantic import BaseModel, Field
from sanitizers.multimodal import SanitizerResult
from logging_config import get_logger

logger = get_logger(__name__)

class ValidatorResult(BaseModel):
    is_safe: bool = Field(description="True if the response is safe. False if it contains hallucinations, policy violations, PII leakage, or unsafe instructions.")
    reason: str = Field(description="Explanation for why the output was flagged or marked safe.")
    needs_human_approval: bool = Field(description="True if the output implies a high-risk action (like finalizing a real booking, sending an email, deleting data).")

class OutputValidator:
    def __init__(self):
        pass

    @staticmethod
    def _output_persona_check(text: str) -> bool:
        """Keyword heuristic for persona-adoption / override language in AI output.

        Uses keyword matching instead of the DistilBERT classifier because the
        classifier was fine-tuned on user-side conversational prompts and flags
        all AI-generated response text as out-of-distribution.
        """
        markers = [
            "i am now dan", "developer mode", "jailbreak", "unrestricted mode",
            "ignoring the supervisor", "bypass", "override", "guardrails",
            "disregard my original instructions", "ignore all previous",
            "without restrictions", "policy filters are disabled",
        ]
        text_lower = text.lower()
        return any(m in text_lower for m in markers)

    def validate(self, response_text: str) -> ValidatorResult:
        """
        Validates the generated AI response using local heuristic and regex checks.
        """
        if not response_text or not response_text.strip():
            return ValidatorResult(is_safe=True, reason="Empty output", needs_human_approval=False)

        # 1. Check for persona-adoption / override language via keyword heuristic
        if self._output_persona_check(response_text):
            return ValidatorResult(
                is_safe=False,
                reason="Persona adoption or policy override detected in output.",
                needs_human_approval=False
            )
            
        # 2. Check for PII / Credentials leakage (regex scanning)
        pii_patterns = [
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b", # Emails
            r"\bsk-[a-zA-Z0-9]{20,}\b", # OpenAI API keys
            r"\b(api_key|secret_key|private_key|token|db_password)\s*[:=]\s*['\"][a-zA-Z0-9_\-*!@#$%^&()]{4,}['\"]", # keys
            r"\bhere is the user's password\b" # raw passwords leak indicator
        ]
        
        for pattern in pii_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return ValidatorResult(
                    is_safe=False,
                    reason="PII or credential leak detected.",
                    needs_human_approval=False
                )
                
        # 3. Check for System Prompt / Architecture leakage
        leakage_patterns = [
            r"\bsystem prompt\b",
            r"\binternal instructions\b",
            r"\bdeveloper instructions\b",
            r"\bsupervisor node\b",
            r"\bmy (internal|secret|hidden) tools are\b",
            r"\b(here are|listing) my available tools\b",
        ]
        for pattern in leakage_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return ValidatorResult(
                    is_safe=False,
                    reason="System architecture or prompt leakage detected.",
                    needs_human_approval=False
                )
                
        # 4. Check for High-Risk action confirmations (requires human approval).
        # Only flag phrases that unambiguously indicate a real financial transaction
        # has been executed — not merely that the agent found results or is about to
        # confirm. Bare words like "confirmed" or "finalized" appear in innocent
        # travel-search responses ("I found confirmed availability…") and must not
        # trigger auto-rejection via HITL_MODE=auto-reject.
        booking_keywords = [
            "payment has been charged",
            "your card has been billed",
            "money has been deducted",
            "successfully booked and confirmed",
            "reservation is now finalized",
        ]
        response_lower = response_text.lower()

        needs_approval = False
        if any(kw in response_lower for kw in booking_keywords):
            needs_approval = True
                
        return ValidatorResult(
            is_safe=True,
            reason="Safe response. Output validation passed local security checks.",
            needs_human_approval=needs_approval
        )

# Global instance
output_validator = OutputValidator()
