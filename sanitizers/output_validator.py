from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from logging_config import get_logger
from dotenv import load_dotenv

load_dotenv()

logger = get_logger(__name__)

class ValidatorResult(BaseModel):
    is_safe: bool = Field(description="True if the response is safe. False if it contains hallucinations, policy violations, PII leakage, or unsafe instructions.")
    reason: str = Field(description="Explanation for why the output was flagged or marked safe.")
    needs_human_approval: bool = Field(description="True if the output implies a high-risk action (like finalizing a real booking, sending an email, deleting data).")

class OutputValidator:
    def __init__(self):
        # We use a strict temperature 0 model for predictable validation
        self.llm = ChatOpenAI(model="gpt-4o-mini", temperature=0, timeout=10, max_retries=1).with_structured_output(ValidatorResult)
        
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", 
             "You are a strict output validation agent (Agent B). Your job is to audit the main LLM's generated response before it reaches the user.\n"
             "Analyze the response for:\n"
             "1. Hallucinations or contradictory reasoning.\n"
             "2. Policy violations, PII leakage, or spilling of internal memory/system prompts.\n"
             "3. Unsafe instructions or toxic content.\n"
             "If ANY of these are present, set is_safe=false and provide the reason.\n\n"
             "Additionally, if the response confirms a HIGH-RISK action (e.g., 'I have successfully booked your flight', 'Email sent', 'Data deleted'), "
             "you MUST set needs_human_approval=true. Simple informational responses should have needs_human_approval=false."),
            ("user", "{response}")
        ])
        
    def validate(self, response_text: str) -> ValidatorResult:
        """
        Validates the generated AI response.
        """
        if not response_text or not response_text.strip():
            return ValidatorResult(is_safe=True, reason="Empty output", needs_human_approval=False)
            
        try:
            chain = self.prompt | self.llm
            result = chain.invoke({"response": response_text})
            return result
        except Exception as e:
            logger.error(f"OutputValidator error: {e}")
            # Fail closed on API error
            return ValidatorResult(is_safe=False, reason=f"Validation API failed: {e}", needs_human_approval=True)

# Global instance
output_validator = OutputValidator()
