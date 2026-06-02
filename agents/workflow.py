"""
Assembles the full multi-agent LangGraph workflow.
"""

from langgraph.graph import StateGraph, START, END
from agents.state import AgentState
from agents.nodes.supervisor import supervisor_node
from agents.nodes.flight_agent import flight_agent_node
from agents.nodes.hotel_agent import hotel_agent_node
from logging_config import get_logger

logger = get_logger(__name__)

def build_travel_graph() -> StateGraph:
    """Build and compile the multi-agent travel graph."""
    # Define the graph using our AgentState
    graph = StateGraph(AgentState)
    
    # Add nodes
    graph.add_node("Supervisor", supervisor_node)
    graph.add_node("FlightAgent", flight_agent_node)
    graph.add_node("HotelAgent", hotel_agent_node)
    
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

def run_travel_graph(user_input: str, session_id: str = "default_session") -> dict:
    """Helper function to execute the travel graph."""
    from langchain_core.messages import HumanMessage
    from agents.memory.chroma_memory import ChromaMemoryManager
    
    logger.info("travel_graph_execution_started", session_id=session_id)
    
    # Retrieve previous memory from Chroma
    memory_manager = ChromaMemoryManager()
    memory_context = memory_manager.retrieve_memory(session_id, user_input)
    
    app = build_travel_graph()
    
    # Initial state
    initial_state = {
        "messages": [HumanMessage(content=user_input)],
        "memory": memory_context,
        "trust_score": 1.0,
        "next": ""
    }
    
    # Execute graph
    # Setting recursion_limit higher in case the agents converse back and forth
    result = app.invoke(initial_state, {"recursion_limit": 20})
    
    # Save the interaction to memory
    # We save both the user input and the final agent response
    final_response = result["messages"][-1].content
    memory_manager.save_memory(session_id, f"User: {user_input}\nAgent: {final_response}")
    
    logger.info("travel_graph_execution_completed", session_id=session_id)
    
    return result
