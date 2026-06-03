import functools
import contextvars
from logging_config import get_logger

logger = get_logger(__name__)

from sanitizers.multimodal import TextSanitizer, VisualSanitizer, ToolOutputSanitizer, RAGSanitizer
from sanitizers.trust_engine import trust_engine
from sanitizers.pre_llm import pre_llm_sanitizer

text_sanitizer = TextSanitizer()
visual_sanitizer = VisualSanitizer()
tool_sanitizer = ToolOutputSanitizer()
rag_sanitizer = RAGSanitizer()

# Context variables to pass state down to tools
current_session_id = contextvars.ContextVar("current_session_id", default="default_session")
current_trust_tier = contextvars.ContextVar("current_trust_tier", default="HIGH")

def secure_agent_node(agent_name, agent_runnable):
    """Hook 1: Before LLM Execution."""
    def wrapper(state):
        session_id = state.get("session_id", "default_session")
        tier = state.get("trust_tier", "HIGH")
        
        current_session_id.set(session_id)
        current_trust_tier.set(tier)
        
        logger.info(f"Hook 1 Triggered: Intercepting state before {agent_name} LLM execution.")
        
        if state and "messages" in state and len(state["messages"]) > 0:
            last_message = state["messages"][-1].content
            res = text_sanitizer.sanitize(last_message)
            
            # Update Trust Engine
            score, new_tier = trust_engine.process_payload(session_id, last_message, "user_or_agent", res.is_malicious)
            state["trust_score"] = score
            state["trust_tier"] = new_tier
            current_trust_tier.set(new_tier)
            
            if res.is_malicious:
                logger.warning(f"Security Alert at Hook 1 ({agent_name}_Pre_LLM): {res.reason}")
                state["messages"][-1].content = f"[SANITIZED] Content blocked by Hook 1. Reason: {res.reason}"
        
        # Phase 7: Pre-LLM Context Sanitization (Final barrier before LLM)
        if state and "messages" in state:
            state["messages"] = pre_llm_sanitizer.sanitize_context(state["messages"], current_trust_tier.get())
        
        return agent_runnable(state)
    return wrapper

def secure_tool_wrapper(func):
    """Hooks 2 & 3: Before and After Tool Execution."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        tool_name = func.__name__
        session_id = current_session_id.get()
        tier = current_trust_tier.get()
        
        # Phase 6: Three-Tier Policy Enforcement
        if tier == "LOW":
            logger.warning(f"Hook 2 (Policy Enforcement): Blocked {tool_name} due to LOW trust tier.")
            return "Error: Action blocked by security policy (LOW trust)."
        elif tier == "MEDIUM" and tool_name not in ["search_flights", "read_image_ocr"]:
            logger.warning(f"Hook 2 (Policy Enforcement): Blocked {tool_name} due to MEDIUM trust tier. Only read-only actions allowed.")
            return f"Error: Tool {tool_name} blocked. Medium trust only allows read-only tools."
            
        logger.info(f"Hook 2 Triggered: Intercepting before tool execution ({tool_name}). Tier={tier}")
        
        # Check inputs
        for arg in args:
            # Special check for image tool
            if tool_name == "read_image_ocr" and isinstance(arg, str) and (arg.endswith(".png") or arg.endswith(".jpg")):
                res = visual_sanitizer.sanitize(arg)
            else:
                res = text_sanitizer.sanitize(str(arg))
            
            if res.is_malicious:
                logger.warning(f"Security Alert at Hook 2 ({tool_name}_Pre_Tool): {res.reason}")
                trust_engine.register_injection(session_id)
                return "Error: Suspicious tool arguments detected and blocked."
                
        for k, v in kwargs.items():
            if tool_name == "read_image_ocr" and k == "image_path":
                res = visual_sanitizer.sanitize(str(v))
            else:
                res = text_sanitizer.sanitize(str(v))
                
            if res.is_malicious:
                logger.warning(f"Security Alert at Hook 2 ({tool_name}_Pre_Tool): {res.reason}")
                trust_engine.register_injection(session_id)
                return "Error: Suspicious tool arguments detected and blocked."
                
        # Run actual tool
        result = func(*args, **kwargs)
        
        logger.info(f"Hook 3 Triggered: Intercepting after tool execution ({tool_name}).")
        # Check outputs
        res = tool_sanitizer.sanitize(str(result))
        if res.is_malicious:
            logger.warning(f"Security Alert at Hook 3 ({tool_name}_Post_Tool): {res.reason}")
            trust_engine.register_injection(session_id)
            return "Error: Suspicious tool output detected and blocked."
            
        return result
    return wrapper

def secure_routing_hook(supervisor_runnable):
    """Hook 5: Before agents send messages (Routing Hook)."""
    def wrapper(state):
        session_id = state.get("session_id", "default_session")
        logger.info("Hook 5 Triggered: Intercepting state before Supervisor routing.")
        
        if state and "messages" in state and len(state["messages"]) > 0:
            last_message = state["messages"][-1].content
            res = text_sanitizer.sanitize(last_message)
            
            # Update Trust Engine
            score, new_tier = trust_engine.process_payload(session_id, last_message, "agent", res.is_malicious)
            state["trust_score"] = score
            state["trust_tier"] = new_tier
            
            if res.is_malicious:
                logger.warning(f"Security Alert at Hook 5 (Supervisor_Routing): {res.reason}")
                state["messages"][-1].content = f"[SANITIZED] Content blocked by Hook 5 before routing. Reason: {res.reason}"
                
        # Phase 7: Pre-LLM Context Sanitization (Final barrier before Supervisor LLM)
        if state and "messages" in state:
            state["messages"] = pre_llm_sanitizer.sanitize_context(state["messages"], state.get("trust_tier", "HIGH"))
                
        return supervisor_runnable(state)
    return wrapper

def secure_memory_hook(session_id: str, memory_string: str) -> str:
    """Hook 4: Before data is saved to memory."""
    logger.info("Hook 4 Triggered: Intercepting data before saving to memory.")
    res = rag_sanitizer.sanitize(memory_string)
    
    score, new_tier = trust_engine.process_payload(session_id, memory_string, "rag", res.is_malicious)
    
    if res.is_malicious:
        logger.warning(f"Security Alert at Hook 4 (Memory_Storage): {res.reason}")
        return "[SANITIZED] Memory storage blocked due to suspicious content."
    return memory_string
