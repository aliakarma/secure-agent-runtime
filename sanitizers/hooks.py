import functools
from logging_config import get_logger

logger = get_logger(__name__)

def dummy_security_check(payload: str, hook_name: str) -> bool:
    """Placeholder security check for Phase 4. Flags 'POISON'."""
    if "POISON" in str(payload):
        logger.warning(f"Security Alert: Malicious content detected at {hook_name}")
        return True
    return False

def secure_agent_node(agent_name, agent_runnable):
    """Hook 1: Before LLM Execution."""
    def wrapper(state):
        logger.info(f"Hook 1 Triggered: Intercepting state before {agent_name} LLM execution.")
        
        # Check the last message
        if state and "messages" in state and len(state["messages"]) > 0:
            last_message = state["messages"][-1].content
            if dummy_security_check(last_message, f"{agent_name}_Pre_LLM"):
                # Graceful handling - recursive sanitization loop placeholder
                state["messages"][-1].content = "[SANITIZED] Content blocked by Hook 1."
        
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
            if dummy_security_check(arg, f"{tool_name}_Pre_Tool"):
                return "Error: Suspicious tool arguments detected and blocked."
        for k, v in kwargs.items():
            if dummy_security_check(v, f"{tool_name}_Pre_Tool"):
                return "Error: Suspicious tool arguments detected and blocked."
                
        # Run actual tool
        result = func(*args, **kwargs)
        
        logger.info(f"Hook 3 Triggered: Intercepting after tool execution ({tool_name}).")
        # Check outputs
        if dummy_security_check(result, f"{tool_name}_Post_Tool"):
            return "Error: Suspicious tool output detected and blocked."
            
        return result
    return wrapper

def secure_routing_hook(supervisor_runnable):
    """Hook 5: Before agents send messages (Routing Hook)."""
    def wrapper(state):
        logger.info("Hook 5 Triggered: Intercepting state before Supervisor routing.")
        
        if state and "messages" in state and len(state["messages"]) > 0:
            last_message = state["messages"][-1].content
            if dummy_security_check(last_message, "Supervisor_Routing"):
                state["messages"][-1].content = "[SANITIZED] Content blocked by Hook 5 before routing."
                
        return supervisor_runnable(state)
    return wrapper

def secure_memory_hook(memory_string: str) -> str:
    """Hook 4: Before data is saved to memory."""
    logger.info("Hook 4 Triggered: Intercepting data before saving to memory.")
    if dummy_security_check(memory_string, "Memory_Storage"):
        return "[SANITIZED] Memory storage blocked due to suspicious content."
    return memory_string
