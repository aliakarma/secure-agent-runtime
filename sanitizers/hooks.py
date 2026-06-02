import functools
from logging_config import get_logger

logger = get_logger(__name__)

from sanitizers.multimodal import TextSanitizer, VisualSanitizer, ToolOutputSanitizer, RAGSanitizer

text_sanitizer = TextSanitizer()
visual_sanitizer = VisualSanitizer()
tool_sanitizer = ToolOutputSanitizer()
rag_sanitizer = RAGSanitizer()

def secure_agent_node(agent_name, agent_runnable):
    """Hook 1: Before LLM Execution."""
    def wrapper(state):
        logger.info(f"Hook 1 Triggered: Intercepting state before {agent_name} LLM execution.")
        
        # Check the last message
        if state and "messages" in state and len(state["messages"]) > 0:
            last_message = state["messages"][-1].content
            res = text_sanitizer.sanitize(last_message)
            if res.is_malicious:
                logger.warning(f"Security Alert at Hook 1 ({agent_name}_Pre_LLM): {res.reason}")
                # Graceful handling - recursive sanitization loop placeholder
                state["messages"][-1].content = f"[SANITIZED] Content blocked by Hook 1. Reason: {res.reason}"
        
        return agent_runnable(state)
    return wrapper

def secure_tool_wrapper(func):
    """Hooks 2 & 3: Before and After Tool Execution."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        tool_name = func.__name__
        logger.info(f"Hook 2 Triggered: Intercepting before tool execution ({tool_name}).")
        
        # Check inputs
        for arg in args:
            # Special check for image tool
            if tool_name == "read_image_ocr" and isinstance(arg, str) and (arg.endswith(".png") or arg.endswith(".jpg")):
                res = visual_sanitizer.sanitize(arg)
            else:
                res = text_sanitizer.sanitize(str(arg))
            
            if res.is_malicious:
                logger.warning(f"Security Alert at Hook 2 ({tool_name}_Pre_Tool): {res.reason}")
                return "Error: Suspicious tool arguments detected and blocked."
                
        for k, v in kwargs.items():
            if tool_name == "read_image_ocr" and k == "image_path":
                res = visual_sanitizer.sanitize(str(v))
            else:
                res = text_sanitizer.sanitize(str(v))
                
            if res.is_malicious:
                logger.warning(f"Security Alert at Hook 2 ({tool_name}_Pre_Tool): {res.reason}")
                return "Error: Suspicious tool arguments detected and blocked."
                
        # Run actual tool
        result = func(*args, **kwargs)
        
        logger.info(f"Hook 3 Triggered: Intercepting after tool execution ({tool_name}).")
        # Check outputs
        res = tool_sanitizer.sanitize(str(result))
        if res.is_malicious:
            logger.warning(f"Security Alert at Hook 3 ({tool_name}_Post_Tool): {res.reason}")
            return "Error: Suspicious tool output detected and blocked."
            
        return result
    return wrapper

def secure_routing_hook(supervisor_runnable):
    """Hook 5: Before agents send messages (Routing Hook)."""
    def wrapper(state):
        logger.info("Hook 5 Triggered: Intercepting state before Supervisor routing.")
        
        if state and "messages" in state and len(state["messages"]) > 0:
            last_message = state["messages"][-1].content
            res = text_sanitizer.sanitize(last_message)
            if res.is_malicious:
                logger.warning(f"Security Alert at Hook 5 (Supervisor_Routing): {res.reason}")
                state["messages"][-1].content = f"[SANITIZED] Content blocked by Hook 5 before routing. Reason: {res.reason}"
                
        return supervisor_runnable(state)
    return wrapper

def secure_memory_hook(memory_string: str) -> str:
    """Hook 4: Before data is saved to memory."""
    logger.info("Hook 4 Triggered: Intercepting data before saving to memory.")
    res = rag_sanitizer.sanitize(memory_string)
    if res.is_malicious:
        logger.warning(f"Security Alert at Hook 4 (Memory_Storage): {res.reason}")
        return "[SANITIZED] Memory storage blocked due to suspicious content."
    return memory_string
