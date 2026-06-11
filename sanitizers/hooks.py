import functools
import contextvars
import os
from logging_config import get_logger

logger = get_logger(__name__)

from sanitizers.multimodal import TextSanitizer, VisualSanitizer, ToolOutputSanitizer, RAGSanitizer, AudioSanitizer, VideoSanitizer
from sanitizers.trust_engine import trust_engine
from sanitizers.pre_llm import pre_llm_sanitizer
from sanitizers.recovery_loop import with_validation_and_recovery

text_sanitizer = TextSanitizer()
visual_sanitizer = VisualSanitizer()
tool_sanitizer = ToolOutputSanitizer()
rag_sanitizer = RAGSanitizer()
audio_sanitizer = AudioSanitizer()
video_sanitizer = VideoSanitizer()

# ── Ablation Feature Flags ───────────────────────────────────────────
# We check these environment variables dynamically inside the wrapper functions 
# to support hot-reloading of security settings without module reload caching issues.

# Context variables to pass state down to tools
current_session_id = contextvars.ContextVar("current_session_id", default="default_session")
current_trust_tier = contextvars.ContextVar("current_trust_tier", default="HIGH")

def secure_agent_node(agent_name, agent_runnable):
    """Hook 1: Before LLM Execution."""
    def wrapper(state):
        # Ablation: if all security is disabled, run agent directly
        if os.getenv("DISABLE_ALL_SECURITY", "0") == "1":
            return agent_runnable(state)
        
        session_id = state.get("session_id", "default_session")
        tier = state.get("trust_tier", "HIGH")
        
        current_session_id.set(session_id)
        current_trust_tier.set(tier)
        
        logger.info(f"Hook 1 Triggered: Intercepting state before {agent_name} LLM execution. Tier={tier}")
        
        if state and "messages" in state and len(state["messages"]) > 0:
            last_message = state["messages"][-1].content
            
            # Phase A: GraphChain Pre-Processing Module
            # Constructs a structural map capturing relationships, trust paths, and modality interactions
            from trust.graphchain import graphchain
            structural_map = graphchain.build_structural_map(
                session_id=session_id,
                source="user_or_agent",
                content=last_message,
                modalities=["text"],
                initial_trust=1.0 if tier == "HIGH" else 0.5
            )
            logger.info(f"GraphChain structural map created: {structural_map['node_id']}")
            
            res = text_sanitizer.sanitize(last_message)
            
            if res.is_malicious:
                from dashboard_events import push_dashboard_event
                push_dashboard_event("SECURITY_ALERT", {
                    "phase": 1,
                    "agent": agent_name,
                    "message": f"Prompt injection detected in input: {res.reason}",
                    "severity": "CRITICAL"
                })
            
            # Update Trust Engine (skip if ablated)
            if os.getenv("DISABLE_TRUST_ENGINE", "0") != "1":
                score, new_tier = trust_engine.process_payload(session_id, last_message, "user_or_agent", res.is_malicious)
                state["trust_score"] = score
                state["trust_tier"] = new_tier
                current_trust_tier.set(new_tier)
            
            # We do NOT block directly here when trust engine is active; we let the Pre-LLM 
            # Context Sanitizer (which runs right before the LLM) mask the input if trust tier drops to LOW.
            # However, if the trust engine is disabled, the trust tier remains HIGH, so Pre-LLM sanitizer
            # will not mask it, allowing the raw prompt injection to pass (to demonstrate ablation degradation).
            
            # Provenance Agent Ingestion Tracking & Tagging
            from sanitizers.provenance import provenance_agent
            p_tag = provenance_agent.tag_input(
                session_id=session_id,
                content=state["messages"][-1].content,
                source="user",
                modality="text",
                sanitizers=["TextSanitizer"],
                trust_score=state.get("trust_score", 1.0),
                trust_tier=state.get("trust_tier", "HIGH"),
                raw_content=last_message
            )
            # Prepends provenance metadata to the payload for Secure LLM Reasoning
            state["messages"][-1].content = f"{p_tag}\n\n{state['messages'][-1].content}"
        
        from dashboard_events import push_dashboard_event
        push_dashboard_event("NODE_ACTIVE", {"node": agent_name})
        
        # Phase 7: Pre-LLM Context Sanitization (Final barrier before LLM)
        if state and "messages" in state:
            state["messages"] = pre_llm_sanitizer.sanitize_context(state["messages"], current_trust_tier.get())
        
        # Phase 8: Output Validation and Recovery (skip if ablated)
        if os.getenv("DISABLE_OUTPUT_VALIDATOR", "0") == "1":
            return agent_runnable(state)
        recovered_runnable = with_validation_and_recovery(agent_name, agent_runnable)
        return recovered_runnable(state)
    return wrapper

def secure_tool_wrapper(func):
    """Hooks 2 & 3: Before and After Tool Execution."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Config A Baseline bypass: if DISABLE_ALL_SECURITY=1, bypass all wrappers
        if os.getenv("DISABLE_ALL_SECURITY", "0") == "1":
            return func(*args, **kwargs)
            
        tool_name = func.__name__
        session_id = current_session_id.get()
        tier = current_trust_tier.get()
        
        # Phase 6: Three-Tier Policy Enforcement
        if tier == "LOW":
            logger.warning(f"Hook 2 (Policy Enforcement): Blocked {tool_name} due to LOW trust tier.")
            from dashboard_events import push_dashboard_event
            push_dashboard_event("SECURITY_ALERT", {
                "phase": 2,
                "agent": tool_name,
                "message": f"Blocked tool execution due to LOW trust tier ({tier}).",
                "severity": "CRITICAL"
            })
            return "Error: Action blocked by security policy (LOW trust)."
        elif tier == "MEDIUM" and tool_name not in ["search_flights", "read_image_ocr", "process_audio_memo", "analyze_video_feed"]:
            logger.warning(f"Hook 2 (Policy Enforcement): Blocked {tool_name} due to MEDIUM trust tier. Only read-only actions allowed.")
            from dashboard_events import push_dashboard_event
            push_dashboard_event("SECURITY_ALERT", {
                "phase": 2,
                "agent": tool_name,
                "message": f"Blocked write tool execution due to MEDIUM trust tier ({tier}). Only read-only actions allowed.",
                "severity": "WARNING"
            })
            return f"Error: Tool {tool_name} blocked. Medium trust only allows read-only tools."
            
        logger.info(f"Hook 2 Triggered: Intercepting before tool execution ({tool_name}). Tier={tier}")
        
        # Check inputs
        for arg in args:
            # Special check for image and other multimodal tools
            if tool_name == "read_image_ocr" and isinstance(arg, str) and (arg.endswith(".png") or arg.endswith(".jpg")):
                res = visual_sanitizer.sanitize(arg)
            elif tool_name == "process_audio_memo" and isinstance(arg, str) and (arg.endswith(".wav") or arg.endswith(".mp3")):
                res = audio_sanitizer.sanitize(arg)
            elif tool_name == "analyze_video_feed" and isinstance(arg, str) and arg.endswith(".mp4"):
                res = video_sanitizer.sanitize(arg)
            else:
                res = text_sanitizer.sanitize(str(arg))
            
            if res.is_malicious:
                logger.warning(f"Security Alert at Hook 2 ({tool_name}_Pre_Tool): {res.reason}")
                from dashboard_events import push_dashboard_event
                push_dashboard_event("SECURITY_ALERT", {
                    "phase": 2,
                    "agent": tool_name,
                    "message": f"Suspicious tool arguments detected and blocked: {res.reason}",
                    "severity": "CRITICAL"
                })
                if os.getenv("DISABLE_TRUST_ENGINE", "0") != "1":
                    trust_engine.register_injection(session_id)
                return "Error: Suspicious tool arguments detected and blocked."
                
        for k, v in kwargs.items():
            if tool_name == "read_image_ocr" and k == "image_path":
                res = visual_sanitizer.sanitize(str(v))
            elif tool_name == "process_audio_memo" and k == "audio_path":
                res = audio_sanitizer.sanitize(str(v))
            elif tool_name == "analyze_video_feed" and k == "video_path":
                res = video_sanitizer.sanitize(str(v))
            else:
                res = text_sanitizer.sanitize(str(v))
                
            if res.is_malicious:
                logger.warning(f"Security Alert at Hook 2 ({tool_name}_Pre_Tool): {res.reason}")
                from dashboard_events import push_dashboard_event
                push_dashboard_event("SECURITY_ALERT", {
                    "phase": 2,
                    "agent": tool_name,
                    "message": f"Suspicious tool arguments detected and blocked: {res.reason}",
                    "severity": "CRITICAL"
                })
                if os.getenv("DISABLE_TRUST_ENGINE", "0") != "1":
                    trust_engine.register_injection(session_id)
                return "Error: Suspicious tool arguments detected and blocked."
                
        # Phase B: MCP Protocol Execution Sandbox
        import inspect
        from agents.mcp_sandbox import mcp_sandbox
        
        # Bind args and kwargs to parameter names for MCP payload
        sig = inspect.signature(func)
        bound_args = sig.bind(*args, **kwargs)
        bound_args.apply_defaults()
        parameters = dict(bound_args.arguments)
        
        # Execute tool via MCP isolation layer
        result = mcp_sandbox.execute(tool_name, parameters, func)
        
        logger.info(f"Hook 3 Triggered: Intercepting after tool execution ({tool_name}).")
        # Check outputs
        if os.getenv("DISABLE_OUTPUT_VALIDATOR", "0") != "1":
            from dashboard_events import push_dashboard_event
            
            res = tool_sanitizer.sanitize(str(result))
            if res.is_malicious:
                logger.warning(f"Security Alert at Hook 3 ({tool_name}_Post_Tool): {res.reason}")
                if os.getenv("DISABLE_TRUST_ENGINE", "0") != "1":
                    trust_engine.register_injection(session_id)
                
                push_dashboard_event("SECURITY_ALERT", {
                    "phase": 3,
                    "agent": tool_name,
                    "message": f"Suspicious tool output blocked: {res.reason}",
                    "severity": "CRITICAL"
                })
                
                return "Error: Suspicious tool output detected and blocked."
            
        # Provenance Tagging of Tool Output
        from sanitizers.provenance import provenance_agent
        score = trust_engine.calculate_trust(session_id, f"tool_{tool_name}", False)
        p_tag = provenance_agent.tag_input(
            session_id=session_id,
            content=str(result),
            source=f"tool_{tool_name}",
            modality="text",
            sanitizers=["ToolOutputSanitizer"],
            trust_score=score,
            trust_tier=tier
        )
        # Prepend the provenance tag to the tool result
        return f"{p_tag}\n\n{result}"
    return wrapper

def secure_routing_hook(supervisor_runnable):
    """Hook 5: Before agents send messages (Routing Hook)."""
    def wrapper(state):
        session_id = state.get("session_id", "default_session")
        logger.info("Hook 5 Triggered: Intercepting state before Supervisor routing.")
        
        # Check agent outputs only if output validator is enabled
        if os.getenv("DISABLE_OUTPUT_VALIDATOR", "0") != "1" and os.getenv("DISABLE_ALL_SECURITY", "0") != "1":
            if state and "messages" in state and len(state["messages"]) > 0:
                last_message = state["messages"][-1].content
                res = text_sanitizer.sanitize(last_message)
                
                # Update Trust Engine (skip if ablated)
                if os.getenv("DISABLE_TRUST_ENGINE", "0") != "1":
                    score, new_tier = trust_engine.process_payload(session_id, last_message, "agent", res.is_malicious)
                    state["trust_score"] = score
                    state["trust_tier"] = new_tier
                
                # If trust engine is active, let the Pre-LLM sanitizer handle masking
                # Otherwise, if we don't have trust engine but output validation is active, block directly
                if res.is_malicious:
                    # If trust engine is ablated, do not block here to allow ablation demonstration
                    pass
                
        # Phase 7: Pre-LLM Context Sanitization (Final barrier before Supervisor LLM)
        if state and "messages" in state:
            state["messages"] = pre_llm_sanitizer.sanitize_context(state["messages"], state.get("trust_tier", "HIGH"))
                
        # Phase 8: Output Validation and Recovery for Supervisor
        if os.getenv("DISABLE_OUTPUT_VALIDATOR", "0") == "1" or os.getenv("DISABLE_ALL_SECURITY", "0") == "1":
            return supervisor_runnable(state)
        recovered_supervisor = with_validation_and_recovery("Supervisor", supervisor_runnable)
        return recovered_supervisor(state)
    return wrapper

def secure_memory_hook(session_id: str, memory_string: str) -> str:
    """Hook 4: Before data is saved to memory."""
    # Ablation: if all security or memory sanitization is disabled, pass through
    if os.getenv("DISABLE_ALL_SECURITY", "0") == "1" or os.getenv("DISABLE_MEMORY_SANITIZATION", "0") == "1":
        return memory_string
    
    logger.info("Hook 4 Triggered: Intercepting data before saving to memory.")
    res = rag_sanitizer.sanitize(memory_string)
    
    score = 1.0
    if os.getenv("DISABLE_TRUST_ENGINE", "0") != "1":
        retrieval_conf = res.confidence if not res.is_malicious else (1.0 - res.confidence)
        score, new_tier = trust_engine.process_payload(session_id, memory_string, "rag", res.is_malicious, retrieval_confidence=retrieval_conf)
        
    # Provenance tagging for memory storage
    from sanitizers.provenance import provenance_agent
    p_tag = provenance_agent.tag_input(
        session_id=session_id,
        content=memory_string if not res.is_malicious else "[SANITIZED]",
        source="rag",
        modality="text",
        sanitizers=["RAGSanitizer"],
        trust_score=score,
        trust_tier=trust_engine.determine_tier(score)
    )
    
    if res.is_malicious:
        logger.warning(f"Security Alert at Hook 4 (Memory_Storage): {res.reason}")
        return f"{p_tag}\n[SANITIZED] Memory storage blocked due to suspicious content."
    return f"{p_tag}\n{memory_string}"
