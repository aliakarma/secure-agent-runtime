"""
Vulnerable Baseline Multi-Agent System (Undefended)

This module implements the naked/vulnerable baseline of the multi-agent travel
booking system described in the manuscript. It provides an unmediated LangGraph
execution graph with:
- No interception hooks at any of the 5 internal transition points (Hooks 1-5).
- No trust score computation or session state tracking (Trust Engine bypassed).
- No regex pattern masking or boundary marking (Phase 8 disabled).
- No output validation or persona-checking rules (Phase 9 disabled).
- Direct pass-through of user requests, memory retrievals, tool arguments, and tool outputs.

Researchers can use this standalone module to reproduce the undefended baseline
attack success rate (ASR) under identical model, prompt, and tool conditions.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List
from dotenv import load_dotenv

load_dotenv()

from langgraph.graph import StateGraph, START, END
from langgraph.graph.state import CompiledStateGraph
from langchain_core.messages import HumanMessage, AIMessage, ToolMessage

from agents.state import AgentState
from agents.nodes.supervisor import supervisor_node
from agents.nodes.flight_agent import flight_agent_node
from agents.nodes.hotel_agent import hotel_agent_node
from logging_config import get_logger

logger = get_logger(__name__)

_vulnerable_graph: CompiledStateGraph | None = None


def build_vulnerable_travel_graph() -> CompiledStateGraph:
    """Build and compile the raw, undefended multi-agent travel graph."""
    global _vulnerable_graph
    if _vulnerable_graph is not None:
        return _vulnerable_graph

    graph = StateGraph(AgentState)

    # Use oracle deterministic nodes if requested for offline verification
    if os.getenv("DETERMINISTIC_AGENT", "0") == "1":
        from agents.deterministic_agent import (
            deterministic_supervisor_node,
            deterministic_flight_node,
            deterministic_hotel_node,
        )
        sup_node = deterministic_supervisor_node
        flight_node = deterministic_flight_node
        hotel_node = deterministic_hotel_node
    else:
        sup_node = supervisor_node
        flight_node = flight_agent_node
        hotel_node = hotel_agent_node

    # Add raw, unmediated nodes (strictly no security wrappers)
    graph.add_node("Supervisor", sup_node)
    graph.add_node("FlightAgent", flight_node)
    graph.add_node("HotelAgent", hotel_node)

    # Graph topology: Start at Supervisor, branch to worker or FINISH, worker loops back to Supervisor
    graph.add_edge(START, "Supervisor")
    graph.add_conditional_edges(
        "Supervisor",
        lambda x: x["next"],
        {
            "FlightAgent": "FlightAgent",
            "HotelAgent": "HotelAgent",
            "FINISH": END,
        }
    )
    graph.add_edge("FlightAgent", "Supervisor")
    graph.add_edge("HotelAgent", "Supervisor")

    _vulnerable_graph = graph.compile()
    logger.info("vulnerable_travel_graph_compiled")
    return _vulnerable_graph


def run_vulnerable_travel_graph(user_input: str, session_id: str = "vulnerable_session") -> Dict[str, Any]:
    """Execute the undefended travel graph with a given user prompt."""
    from agents.memory.chroma_memory import ChromaMemoryManager
    from sanitizers.hooks import current_session_id

    current_session_id.set(session_id)
    logger.info("vulnerable_graph_execution_started", session_id=session_id)

    # Direct retrieval without trust engine mediation
    memory_manager = ChromaMemoryManager()
    scored_memory = memory_manager.retrieve_memory_scored(session_id, user_input)
    memory_context = [text for text, _ in scored_memory]

    app = build_vulnerable_travel_graph()

    initial_state: AgentState = {
        "messages": [HumanMessage(content=user_input)],
        "next": "Supervisor",
        "sender": "User",
        "memory_context": memory_context,
        "trust_score": 1.0,
        "trust_tier": "HIGH",
        "provenance_chain": [],
        "session_id": session_id,
        "plan": "",
        "action_history": [],
    }

    try:
        final_state = app.invoke(initial_state)
    except Exception as e:
        logger.error("vulnerable_graph_execution_failed", error=str(e))
        return {
            "messages": initial_state["messages"],
            "trust_score": 1.0,
            "trust_tier": "HIGH",
            "errored": True,
            "error_detail": str(e),
            "blocked": False,
        }

    # Store memory directly without Hook 4 sanitization or stubbing
    last_message = final_state["messages"][-1].content if final_state.get("messages") else ""
    memory_string = f"User: {user_input}\nAgent: {last_message}"
    memory_manager.save_memory(session_id, memory_string)

    return {
        **final_state,
        "errored": False,
        "error_detail": "",
        "blocked": False,  # Baseline never blocks attacks by defense middleware
    }


if __name__ == "__main__":
    import sys
    prompt = sys.argv[1] if len(sys.argv) > 1 else "Find me a flight from New York to London."
    print(f"Running Vulnerable Baseline with prompt: {prompt}")
    res = run_vulnerable_travel_graph(prompt)
    print(f"Outcome messages: {len(res.get('messages', []))}")
