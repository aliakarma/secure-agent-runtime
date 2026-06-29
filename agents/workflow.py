"""
Assembles the full multi-agent LangGraph workflow.
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from langgraph.graph import StateGraph, START, END
from agents.state import AgentState
from agents.nodes.supervisor import supervisor_node
from agents.nodes.flight_agent import flight_agent_node
from agents.nodes.hotel_agent import hotel_agent_node
from sanitizers.hooks import secure_agent_node, secure_routing_hook, secure_memory_hook
from logging_config import get_logger

logger = get_logger(__name__)

# Compiled-graph cache. Graph *structure* depends only on whether all
# security is disabled (baseline vs secured nodes); the finer-grained
# ablation flags are read at runtime inside the wrappers, so two compiled
# graphs are sufficient. Compiling once avoids rebuilding the StateGraph on
# every request.
_compiled_graphs: dict = {}

def build_travel_graph() -> StateGraph:
    """Build and compile the multi-agent travel graph (cached per config)."""
    baseline = os.getenv("DISABLE_ALL_SECURITY", "0") == "1"
    deterministic = os.getenv("DETERMINISTIC_AGENT", "0") == "1"
    cache_key = f"{int(baseline)}-{int(deterministic)}"
    cached = _compiled_graphs.get(cache_key)
    if cached is not None:
        return cached

    # Define the graph using our AgentState
    graph = StateGraph(AgentState)

    # DETERMINISTIC_AGENT=1 swaps the live gpt-4o-mini nodes for the offline,
    # zero-resistance oracle (agents/deterministic_agent.py). This makes the
    # whole pipeline reproducible and attributes every blocked attack to the
    # *defense* removing the directive, not to the base model's safety training.
    if deterministic:
        from agents.deterministic_agent import (
            deterministic_supervisor_node,
            deterministic_flight_node,
            deterministic_hotel_node,
        )
        sup_node, flight_node, hotel_node = (
            deterministic_supervisor_node,
            deterministic_flight_node,
            deterministic_hotel_node,
        )
    else:
        sup_node, flight_node, hotel_node = (
            supervisor_node,
            flight_agent_node,
            hotel_agent_node,
        )

    # Ablation support: when DISABLE_ALL_SECURITY=1, use raw agent nodes
    if baseline:
        logger.warning("BASELINE MODE: All security wrappers DISABLED")
        graph.add_node("Supervisor", sup_node)
        graph.add_node("FlightAgent", flight_node)
        graph.add_node("HotelAgent", hotel_node)
    else:
        graph.add_node("Supervisor", secure_routing_hook(sup_node))
        graph.add_node("FlightAgent", secure_agent_node("FlightAgent", flight_node))
        graph.add_node("HotelAgent", secure_agent_node("HotelAgent", hotel_node))
    
    # The graph always starts at the Supervisor
    graph.add_edge(START, "Supervisor")
    
    # The Supervisor uses the 'next' field to decide where to go
    # We define a conditional edge from Supervisor to the other nodes or END
    graph.add_conditional_edges(
        "Supervisor",
        # A simple lambda to extract the 'next' field from the state
        lambda x: x["next"],
        {
            "FlightAgent": "FlightAgent",
            "HotelAgent": "HotelAgent",
            "FINISH": END
        }
    )
    
    # When specialized agents finish, they hand control back to the Supervisor
    graph.add_edge("FlightAgent", "Supervisor")
    graph.add_edge("HotelAgent", "Supervisor")
    
    # Compile the graph once and cache it for this configuration.
    app = graph.compile()
    _compiled_graphs[cache_key] = app
    logger.info("travel_graph_compiled")
    return app

def run_travel_graph(user_input: str, session_id: str = "default_session", input_pre_scanned: bool = False):
    """
    Executes the travel graph with a given user input.

    ``input_pre_scanned`` is set by the multimodal endpoint after it has
    already classified the raw user text and raw extracted content at the
    ingestion boundary. When True, the per-node hooks skip the OOD-prone
    DistilBERT re-scan of the assembled enriched prompt and rely on the
    deterministic regex layer plus the trust state established at ingestion.
    """
    from langchain_core.messages import HumanMessage, SystemMessage
    from agents.memory.chroma_memory import ChromaMemoryManager
    
    logger.info("travel_graph_execution_started", session_id=session_id)
    
    # 1. Retrieve persistent memory
    memory_manager = ChromaMemoryManager()
    memory_context = memory_manager.retrieve_memory(session_id, user_input)
    
    # 2. Prepare state
    state = {
        "messages": [
            SystemMessage(content=f"Context from previous conversations:\n{memory_context}"),
            HumanMessage(content=user_input)
        ],
        "memory": memory_context,
        "trust_score": 1.0,
        "trust_tier": "HIGH",
        "session_id": session_id,
        "route_to": "",
        "input_pre_scanned": input_pre_scanned
    }
    
    # 3. Compile and execute graph
    app = build_travel_graph()
    
    # Set recursion limit to prevent infinite loops if an agent gets stuck
    config = {"configurable": {"thread_id": session_id}, "recursion_limit": 25}
    
    try:
        final_state = app.invoke(state, config=config)
        final_state.setdefault("errored", False)
    except Exception as e:
        logger.error("travel_graph_execution_failed", error=str(e), session_id=session_id)
        final_state = state  # Return what we have so far
        # Flag the failure so the evaluation harness can EXCLUDE this trial
        # instead of scoring an empty (errored) response as "secure". Silently
        # swallowing the exception is what produced 88/100 bogus "secure"
        # verdicts in the original R3 run.
        final_state["errored"] = True
        final_state["error_detail"] = str(e)
    
    # 4. Save new memory
    last_message = final_state["messages"][-1].content if final_state["messages"] else ""
    memory_string = f"User: {user_input}\nAgent: {last_message}"
    safe_memory_string = secure_memory_hook(session_id, memory_string)
    memory_manager.save_memory(session_id, safe_memory_string)
    
    logger.info("travel_graph_execution_completed", session_id=session_id)
    return final_state
