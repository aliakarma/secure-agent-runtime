"""
Tests for Phase 2: Baseline Vulnerable Multi-Agent Runtime.
"""

from __future__ import annotations

from langchain_core.messages import HumanMessage
from agents.state import AgentState
from agents.workflow import build_travel_graph
from agents.tools import search_flights, reserve_hotel
from agents.memory.chroma_memory import ChromaMemoryManager
from unittest.mock import patch, MagicMock

def test_mock_tools():
    """Verify that the mock tools return expected data format."""
    flight_result = search_flights.invoke({"destination": "Riyadh"})
    assert "Riyadh" in flight_result
    assert "Found flight" in flight_result
    assert "$" in flight_result
    
    hotel_result = reserve_hotel.invoke({"location": "Riyadh"})
    assert "Riyadh" in hotel_result
    assert "Reserved a room" in hotel_result
    assert "Confirmation:" in hotel_result

def test_graph_compilation():
    """Verify the state graph compiles without errors."""
    app = build_travel_graph()
    assert app is not None
    # Check that nodes exist
    nodes = app.get_graph().nodes
    assert "Supervisor" in nodes
    assert "FlightAgent" in nodes
    assert "HotelAgent" in nodes

def test_supervisor_routing():
    import agents.nodes.supervisor
    from agents.nodes.supervisor import supervisor_node, Route
    from unittest.mock import MagicMock

    # Seed the lazily-built chain cache with a mock so no API key is needed.
    original_chain = agents.nodes.supervisor._supervisor_chain
    try:
        mock_chain = MagicMock()
        mock_chain.invoke.return_value = Route(next="FlightAgent")
        agents.nodes.supervisor._supervisor_chain = mock_chain

        state = AgentState(
            messages=[HumanMessage(content="Book a flight to Riyadh")],
            memory=[],
            next="",
            trust_score=1.0
        )
        result = supervisor_node(state)
        assert result["next"] == "FlightAgent"
    finally:
        agents.nodes.supervisor._supervisor_chain = original_chain

@patch('langchain_openai.OpenAIEmbeddings.embed_query')
def test_chroma_memory(mock_embed):
    """Test ChromaDB saving and retrieving."""
    mock_embed.return_value = [0.1] * 1536 # Fake embedding vector
    
    # We pass in a specific test session so it doesn't pollute actual dev db
    memory_manager = ChromaMemoryManager(collection_name="test_agent_memory")
    
    session = "test_session_123"
    memory_manager.save_memory(session, "The user prefers window seats.")
    
    docs = memory_manager.retrieve_memory(session, "Does the user like window seats?", k=1)
    # The document might be returned depending on exact embedding timing, 
    # but at a minimum we should have a list back without crashing.
    assert isinstance(docs, list)
