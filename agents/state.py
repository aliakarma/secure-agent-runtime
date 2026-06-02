"""
Agent State Definition for Phase 2.

This defines the shared brain for our multi-agent system.
"""

from typing import Annotated, Sequence, TypedDict, Union

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages

class AgentState(TypedDict):
    """The state dictionary representing the shared context across agents."""
    messages: Annotated[Sequence[BaseMessage], add_messages]
    
    # Memory retrieved from ChromaDB
    memory: list[str]
    
    # The next node to route to
    next: str
    
    # Trust score for Phase 6 Provenance & Trust Engine
    trust_score: float
    
    # Trust tier: HIGH, MEDIUM, LOW
    trust_tier: str
    
    # Session ID for state tracking
    session_id: str
