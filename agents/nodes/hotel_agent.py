"""
Hotel Agent Node.
"""

from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from langgraph.prebuilt import create_react_agent
from agents.tools import reserve_hotel, read_image_ocr
from agents.state import AgentState
from logging_config import get_logger

logger = get_logger(__name__)

# System prompt for the Hotel Agent
HOTEL_AGENT_PROMPT = """You are a specialized Hotel Agent.
Your job is to assist users with searching for and booking hotels.
Use the `reserve_hotel` tool when needed.
You can also use `read_image_ocr` to read details from user uploaded images if asked.
Do not assist with flights or general queries outside of hotels.
Always end your final response by answering the user's hotel question clearly.
"""

# Initialize LLM
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0, timeout=10, max_retries=1).with_fallbacks([
    ChatOpenAI(model="gpt-4o", temperature=0, timeout=10, max_retries=1),
    ChatOpenAI(model="gpt-3.5-turbo", temperature=0, timeout=10, max_retries=1)
])

# Create the internal ReAct agent for Hotel
hotel_react_agent = create_react_agent(
    model=llm,
    tools=[reserve_hotel, read_image_ocr],
    prompt=HOTEL_AGENT_PROMPT
)

def hotel_agent_node(state: AgentState) -> dict:
    """The hotel agent node function."""
    logger.info("node_executed", node="hotel_agent")

    result = hotel_react_agent.invoke(state)
    new_messages = result["messages"]
    if new_messages and isinstance(new_messages[-1], AIMessage):
        new_messages[-1].name = "HotelAgent"
    
    return {
        "messages": new_messages
    }
