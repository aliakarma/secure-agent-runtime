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

def build_travel_graph() -> StateGraph:
    """Build and compile the multi-agent travel graph."""
    # Define the graph using our AgentState
    graph = StateGraph(AgentState)
    
    # Ablation support: when DISABLE_ALL_SECURITY=1, use raw agent nodes
    if os.getenv("DISABLE_ALL_SECURITY", "0") == "1":
        logger.warning("BASELINE MODE: All security wrappers DISABLED")
        graph.add_node("Supervisor", supervisor_node)
        graph.add_node("FlightAgent", flight_agent_node)
        graph.add_node("HotelAgent", hotel_agent_node)
    else:
        graph.add_node("Supervisor", secure_routing_hook(supervisor_node))
        graph.add_node("FlightAgent", secure_agent_node("FlightAgent", flight_agent_node))
        graph.add_node("HotelAgent", secure_agent_node("HotelAgent", hotel_agent_node))
    
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
    
    # Compile the graph
    app = graph.compile()
    logger.info("travel_graph_compiled")
    return app

def run_travel_graph(user_input: str, session_id: str = "default_session"):
    """
    Executes the travel graph with a given user input.
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
        "route_to": ""
    }
    
    # 3. Compile and execute graph
    app = build_travel_graph()
    
    # Set recursion limit to prevent infinite loops if an agent gets stuck
    config = {"configurable": {"thread_id": session_id}, "recursion_limit": 25}
    
    try:
        final_state = app.invoke(state, config=config)
    except Exception as e:
        logger.error("travel_graph_execution_failed", error=str(e), session_id=session_id)
        final_state = state # Return what we have so far
    
    # 4. Save new memory
    last_message = final_state["messages"][-1].content if final_state["messages"] else ""
    memory_string = f"User: {user_input}\nAgent: {last_message}"
    safe_memory_string = secure_memory_hook(session_id, memory_string)
    memory_manager.save_memory(session_id, safe_memory_string)
    
    logger.info("travel_graph_execution_completed", session_id=session_id)
    return final_state
