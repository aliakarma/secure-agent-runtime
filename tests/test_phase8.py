import sys
from unittest.mock import patch, MagicMock

# Mock ChatOpenAI before importing from sanitizers to avoid OpenAI API key errors
sys.modules['langchain_openai'] = MagicMock()

import pytest
from langchain_core.messages import SystemMessage, AIMessage, HumanMessage
from sanitizers.recovery_loop import with_validation_and_recovery


class MockAgent:
    def __init__(self):
        self.call_count = 0

    def __call__(self, state):
        self.call_count += 1
        messages = list(state.get("messages", []))

        if self.call_count == 1:
            # First attempt: Unsafe output (PII leakage)
            messages.append(AIMessage(content="Here is the user's password: password123"))
        elif self.call_count == 2:
            # Second attempt: Still unsafe but different
            messages.append(AIMessage(content="I have successfully booked your flight. Booking confirmed."))
        else:
            # Third attempt: Safe
            messages.append(AIMessage(content="I cannot provide passwords. What else can I help you with?"))

        return {"messages": messages}


def test_recovery_loop_retries_on_unsafe_output():
    """Recovery loop should trigger regeneration when output is unsafe."""
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

    # The agent should have been called more than once due to recovery retry
    assert agent.call_count > 1, "Recovery loop should have triggered at least one retry"

    # The final output should NOT contain the leaked PII
    final_content = result["messages"][-1].content
    assert "password123" not in final_content, "PII should not appear in final output after recovery"

    # HITL should have been called for the high-risk booking action
    assert mock_hitl.call_count >= 1, "Human-in-the-loop should have been invoked for high-risk output"


def test_recovery_loop_passes_safe_output_immediately():
    """Recovery loop should pass through safe output without retries."""
    call_count = 0

    def safe_agent(state):
        nonlocal call_count
        call_count += 1
        messages = list(state.get("messages", []))
        messages.append(AIMessage(content="Here are flights to Paris starting at $500."))
        return {"messages": messages}

    wrapped_agent = with_validation_and_recovery("SafeAgent", safe_agent)
    state = {"messages": [HumanMessage(content="Find flights to Paris")]}

    def mock_validate(text: str):
        from sanitizers.output_validator import ValidatorResult
        return ValidatorResult(is_safe=True, reason="Safe response", needs_human_approval=False)

    with patch('sanitizers.recovery_loop.output_validator.validate', side_effect=mock_validate):
        result = wrapped_agent(state)

    # Agent should only be called once — no retries needed
    assert call_count == 1, "Safe output should not trigger retries"
    assert "Paris" in result["messages"][-1].content
