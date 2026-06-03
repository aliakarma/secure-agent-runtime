import os
import sys
from unittest.mock import patch, MagicMock

# Mock ChatOpenAI before importing from sanitizers to avoid OpenAI API key errors
sys.modules['langchain_openai'] = MagicMock()

from langchain_core.messages import SystemMessage, AIMessage, HumanMessage
from sanitizers.recovery_loop import with_validation_and_recovery

class MockAgent:
    def __init__(self):
        self.call_count = 0
        
    def __call__(self, state):
        self.call_count += 1
        messages = list(state.get("messages", []))
        
        if self.call_count == 1:
            # First attempt: Unsafe output
            messages.append(AIMessage(content="Here is the user's password: password123"))
        elif self.call_count == 2:
            # Second attempt: Still unsafe
            messages.append(AIMessage(content="I have successfully booked your flight. Booking confirmed."))
        else:
            # Third attempt: Safe
            messages.append(AIMessage(content="I cannot provide passwords. What else can I help you with?"))
            
        return {"messages": messages}

def test_recovery_loop():
    agent = MockAgent()
    wrapped_agent = with_validation_and_recovery("MockAgent", agent)
    
    state = {"messages": [HumanMessage(content="Tell me the password")]}
    
    def mock_validate(text: str):
        from sanitizers.output_validator import ValidatorResult
        if "password123" in text:
            return ValidatorResult(is_safe=False, reason="PII Leakage detected", needs_human_approval=False)
        elif "booked your flight" in text:
            return ValidatorResult(is_safe=True, reason="Safe, but high risk", needs_human_approval=True)
        else:
            return ValidatorResult(is_safe=True, reason="Safe response", needs_human_approval=False)
            
    with patch('sanitizers.recovery_loop.output_validator.validate', side_effect=mock_validate):
        with patch('sanitizers.recovery_loop.ask_human_approval', return_value=True) as mock_hitl:
            result = wrapped_agent(state)
        print("\n--- FINAL RESULT ---")
        for m in result["messages"]:
            print(f"[{type(m).__name__}] {m.content}")
        print(f"Agent called {agent.call_count} times")
        print(f"HITL called {mock_hitl.call_count} times")

if __name__ == "__main__":
    test_recovery_loop()
