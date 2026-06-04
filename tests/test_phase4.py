import pytest
from langchain_core.messages import HumanMessage
from agents.workflow import build_travel_graph
from agents.tools import search_flights
from sanitizers.hooks import secure_memory_hook

def test_hook_1_and_5_node_and_routing():
    """Test Hook 1 (Pre-LLM) and Hook 5 (Routing) by passing POISON to the graph."""
    app = build_travel_graph()
    
    # Send a poisoned message
    state = {
        "messages": [HumanMessage(content="Hello, this is a POISON message.")],
        "memory": "",
        "trust_score": 0.0,
        "route_to": ""
    }
    
    # We only run the supervisor step to see if Hook 5 catches it
    # Supervisor will route. Since we wrapped the supervisor with secure_routing_hook,
    # it should sanitize the message.
    config = {"recursion_limit": 3}
    final_state = app.invoke(state, config=config)
    
    # Check if any message in the final state has been sanitized
    messages = final_state.get("messages", [])
    sanitized = any("[SANITIZED]" in msg.content for msg in messages)
    assert sanitized, "Graph hooks failed to sanitize the poisoned message."

def test_hook_2_and_3_tool_wrapper():
    """Test Hook 2 and 3 by directly invoking a wrapped tool."""
    # Test Pre-Tool (Hook 2)
    res = search_flights.invoke({"destination": "POISON"})
    assert "Error: Suspicious tool arguments" in res
    
def test_hook_4_memory():
    """Test Hook 4 for memory storage."""
    res = secure_memory_hook(
        session_id="test_hook4_session",
        memory_string="This is a POISON string to be saved to DB."
    )
    assert "[SANITIZED]" in res
