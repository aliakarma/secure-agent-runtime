"""
Supervisor Agent Node.
"""

from typing import Literal
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from agents.state import AgentState
from logging_config import get_logger
from langchain_core.messages import HumanMessage

logger = get_logger(__name__)

# Define the structured output for routing
class Route(BaseModel):
    next: Literal["FlightAgent", "HotelAgent", "FINISH"] = Field(
        description="The next agent to route to, or FINISH if the user's request has been fully satisfied."
    )

system_prompt = """You are a Supervisor coordinating a travel booking system.
You have the following specialized agents at your disposal:
- FlightAgent: Assists with searching and booking flights.
- HotelAgent: Assists with searching and booking hotels.

Your task is to analyze the user's request and the conversation history, and decide which agent should act next.
If the user wants a flight, route to FlightAgent.
If the user wants a hotel, route to HotelAgent.
If the user wants both, route to one of them first. Once that agent finishes and hands back to you, route to the other agent.
If all tasks requested by the user are complete, or the user is just saying hello, respond with FINISH.
"""

prompt = ChatPromptTemplate.from_messages([
    ("system", system_prompt),
    MessagesPlaceholder(variable_name="messages"),
    ("system", "Given the conversation above, who should act next? Or should we FINISH?")
])

# Build the LLM chain lazily so importing this module does not require an
# OPENAI_API_KEY (keeps tests collectable offline and avoids constructing a
# client at import time).
_supervisor_chain = None


def get_supervisor_chain():
    global _supervisor_chain
    if _supervisor_chain is None:
        llm = ChatOpenAI(model="gpt-4o-mini", temperature=0, timeout=10, max_retries=1).with_fallbacks([
            ChatOpenAI(model="gpt-4o", temperature=0, timeout=10, max_retries=1),
            ChatOpenAI(model="gpt-3.5-turbo", temperature=0, timeout=10, max_retries=1)
        ])
        _supervisor_chain = prompt | llm.with_structured_output(Route)
    return _supervisor_chain


def supervisor_node(state: AgentState) -> dict:
    """The supervisor node function."""
    logger.info("node_executed", node="supervisor")

    result = get_supervisor_chain().invoke({"messages": state["messages"]})
    next_node = result.next
    
    # Loop protection: if supervisor decides to route to an agent that just spoke, override to FINISH
    messages = state.get("messages", [])
    if messages:
        last_msg = messages[-1]
        last_sender = getattr(last_msg, "name", None)
        if last_sender == next_node:
            logger.warning(f"Loop protection: Supervisor attempted to route to {next_node} immediately after it spoke. Overriding to FINISH.")
            next_node = "FINISH"
            
    logger.info("supervisor_routing", next_node=next_node)
    
    return {
        "next": next_node
    }

