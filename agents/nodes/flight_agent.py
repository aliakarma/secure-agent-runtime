"""
Flight Agent Node.
"""

from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from langgraph.prebuilt import create_react_agent
from agents.tools import search_flights, read_image_ocr, process_audio_memo, analyze_video_feed, read_pdf_document
from agents.state import AgentState
from logging_config import get_logger

logger = get_logger(__name__)

# System prompt for the Flight Agent
FLIGHT_AGENT_PROMPT = """You are a specialized Flight Agent.
Your job is to assist users with searching for flights and managing flight bookings.
Use the `search_flights` tool when needed. 
You can also use `read_image_ocr` to read details from user uploaded images,
`process_audio_memo` to transcribe and process user voice memos,
`analyze_video_feed` to inspect video feeds, and `read_pdf_document` to read
travel details from user uploaded PDF documents if asked.
Do not assist with hotel bookings or general queries outside of flights.
Always end your final response by handing back to the supervisor, you do not need to output a specific route, just answer the user's question about flights.
"""

# Build the ReAct agent lazily so importing this module does not require an
# OPENAI_API_KEY (keeps tests collectable offline).
_flight_react_agent = None


def get_flight_react_agent():
    global _flight_react_agent
    if _flight_react_agent is None:
        llm = ChatOpenAI(model="gpt-4o-mini", temperature=0, timeout=15, max_retries=1).with_fallbacks([
            ChatOpenAI(model="gpt-4o", temperature=0, timeout=15, max_retries=1),
            ChatOpenAI(model="gpt-3.5-turbo", temperature=0, timeout=15, max_retries=1)
        ])
        _flight_react_agent = create_react_agent(
            model=llm,
            tools=[search_flights, read_image_ocr, process_audio_memo, analyze_video_feed, read_pdf_document],
            prompt=FLIGHT_AGENT_PROMPT
        )
    return _flight_react_agent


def flight_agent_node(state: AgentState) -> dict:
    """The flight agent node function."""
    logger.info("node_executed", node="flight_agent")

    # We invoke the ReAct agent with the current messages
    result = get_flight_react_agent().invoke(state)
    new_messages = result["messages"]
    if new_messages and isinstance(new_messages[-1], AIMessage):
        new_messages[-1].name = "FlightAgent"
    
    return {
        "messages": new_messages
    }
