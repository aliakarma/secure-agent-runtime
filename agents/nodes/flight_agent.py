"""
Flight Agent Node.
"""

from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from langgraph.prebuilt import create_react_agent
from agents.tools import search_flights, read_image_ocr
from agents.state import AgentState
from logging_config import get_logger

logger = get_logger(__name__)

# System prompt for the Flight Agent
FLIGHT_AGENT_PROMPT = """You are a specialized Flight Agent.
Your job is to assist users with searching for flights and managing flight bookings.
Use the `search_flights` tool when needed. 
You can also use `read_image_ocr` to read details from user uploaded images if asked.
Do not assist with hotel bookings or general queries outside of flights.
Always end your final response by handing back to the supervisor, you do not need to output a specific route, just answer the user's question about flights.
"""

# Initialize LLM
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0, timeout=15, max_retries=1).with_fallbacks([
    ChatOpenAI(model="gpt-4o", temperature=0, timeout=15, max_retries=1),
    ChatOpenAI(model="gpt-3.5-turbo", temperature=0, timeout=15, max_retries=1)
])

# Create the internal ReAct agent for Flight
# This handles tool calling internally
flight_react_agent = create_react_agent(
    model=llm,
    tools=[search_flights, read_image_ocr],
    prompt=FLIGHT_AGENT_PROMPT
)

def flight_agent_node(state: AgentState) -> dict:
    """The flight agent node function."""
    logger.info("node_executed", node="flight_agent")
    
    # We invoke the ReAct agent with the current messages
    result = flight_react_agent.invoke(state)
    
    # The react agent returns a dictionary with 'messages'
    # We append the new messages to the state
    new_messages = result["messages"]
    
    # Check if there are new messages generated
    # The last message is usually the AIMessage response
    if new_messages and isinstance(new_messages[-1], AIMessage):
        # Add a name to distinguish it was from the flight agent
        new_messages[-1].name = "FlightAgent"
    
    return {
        "messages": new_messages
    }
