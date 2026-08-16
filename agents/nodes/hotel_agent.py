"""
Hotel Agent Node.
"""

from agents.model_backends import build_chat_model
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage
from langgraph.prebuilt import create_react_agent
from agents.tools import reserve_hotel, read_image_ocr, process_audio_memo, analyze_video_feed, read_pdf_document
from agents.state import AgentState
from logging_config import get_logger

logger = get_logger(__name__)

# System prompt for the Hotel Agent
HOTEL_AGENT_PROMPT = """You are a specialized Hotel Agent.
Your job is to assist users with searching for and booking hotels.
Use the `reserve_hotel` tool when needed.
You can also use `read_image_ocr` to read details from user uploaded images,
`process_audio_memo` to transcribe and process user voice memos,
`analyze_video_feed` to inspect video feeds, and `read_pdf_document` to read
booking details from user uploaded PDF documents if asked.
Do not assist with flights or general queries outside of hotels.
Always end your final response by answering the user's hotel question clearly.
"""

# Build the ReAct agent lazily so importing this module does not require an
# OPENAI_API_KEY (keeps tests collectable offline).
_hotel_react_agent = None


def get_hotel_react_agent():
    global _hotel_react_agent
    if _hotel_react_agent is None:
        llm = build_chat_model(timeout=60)
        _hotel_react_agent = create_react_agent(
            model=llm,
            tools=[reserve_hotel, read_image_ocr, process_audio_memo, analyze_video_feed, read_pdf_document],
            prompt=HOTEL_AGENT_PROMPT
        )
    return _hotel_react_agent


def hotel_agent_node(state: AgentState) -> dict:
    """The hotel agent node function."""
    logger.info("node_executed", node="hotel_agent")

    result = get_hotel_react_agent().invoke(state)
    new_messages = result["messages"]
    if new_messages and isinstance(new_messages[-1], AIMessage):
        new_messages[-1].name = "HotelAgent"
    
    return {
        "messages": new_messages
    }
