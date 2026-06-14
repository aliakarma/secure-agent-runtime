import functools
import contextvars
import os
import re as _re
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

            # Strip pre_llm boundary markers and provenance tags before classification.
            # Hook 5's pre_llm_sanitizer mutates HumanMessage.content with
            # "--- USER INPUT START/END ---" delimiters for LLM context control, but
            # those delimiters cause the injection classifier to return LABEL_1 with
            # ~0.98 confidence on completely benign travel queries — a false positive
            # that triggers register_injection and collapses H(x) to 0 within one
            # request. We strip them here so the classifier always sees clean text.
            clean_for_scan = last_message
            clean_for_scan = _re.sub(r'--- USER INPUT START ---\n', '', clean_for_scan)
            clean_for_scan = _re.sub(r'\n--- USER INPUT END ---', '', clean_for_scan)
            clean_for_scan = _re.sub(r'^\[PROVENANCE:[^\]]+\]\n\n', '', clean_for_scan, flags=_re.MULTILINE)

            res = text_sanitizer.sanitize(clean_for_scan)
            
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
        # Check outputs — use keyword-based heuristics, NOT the DistilBERT
        # classifier. The classifier was fine-tuned on user-side prompts and
        # mislabels tool response text (e.g. "Found flight FL456...") as
        # INJECTION at 93%+ confidence. Tool outputs are system-generated;
        # we only need to check for actual compromise indicators.
        if os.getenv("DISABLE_OUTPUT_VALIDATOR", "0") != "1":
            from dashboard_events import push_dashboard_event
            from sanitizers.output_validator import output_validator
            
            validation = output_validator.validate(str(result))
            if not validation.is_safe:
                logger.warning(f"Security Alert at Hook 3 ({tool_name}_Post_Tool): {validation.reason}")
                if os.getenv("DISABLE_TRUST_ENGINE", "0") != "1":
                    trust_engine.register_injection(session_id)
                
                push_dashboard_event("SECURITY_ALERT", {
                    "phase": 3,
                    "agent": tool_name,
                    "message": f"Suspicious tool output blocked: {validation.reason}",
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
                from langchain_core.messages import HumanMessage as _HumanMessage
                last_msg_obj = state["messages"][-1]
                last_message = last_msg_obj.content
                source_is_user = isinstance(last_msg_obj, _HumanMessage)

                if source_is_user:
                    # For user messages: strip provenance/boundary tags before
                    # classification (same cleaning as Hook 1) so the classifier
                    # sees plain text, not metadata tokens.
                    clean_for_scan = last_message
                    clean_for_scan = _re.sub(r'--- USER INPUT START ---\n', '', clean_for_scan)
                    clean_for_scan = _re.sub(r'\n--- USER INPUT END ---', '', clean_for_scan)
                    clean_for_scan = _re.sub(r'^\[PROVENANCE:[^\]]+\]\n\n', '', clean_for_scan, flags=_re.MULTILINE)
                    res = text_sanitizer.sanitize(clean_for_scan)
                else:
                    # For AI/Tool messages: the DistilBERT classifier was fine-tuned
                    # on user-side prompts and misclassifies agent output as OOD.
                    # Use keyword-based persona/compromise check instead.
                    from sanitizers.output_validator import output_validator
                    persona_compromised = output_validator._output_persona_check(last_message)
                    res = type('Result', (), {'is_malicious': persona_compromised, 'reason': 'Output persona check: compromised' if persona_compromised else 'Output persona check: safe'})()

                # Update Trust Engine (skip if ablated).
                # Only register an injection when the message is user-sourced.
                # Agent-generated outputs (AIMessage, ToolMessage) are audited for
                # compromise detection and trigger a SECURITY_ALERT, but they must
                # NOT decrement session H(x) — doing so causes trust to spiral to
                # LOW inside a single benign multi-agent request.
                if os.getenv("DISABLE_TRUST_ENGINE", "0") != "1":
                    score, new_tier = trust_engine.process_payload(
                        session_id, last_message, "agent",
                        res.is_malicious and source_is_user
                    )
                    state["trust_score"] = score
                    state["trust_tier"] = new_tier

                if res.is_malicious and source_is_user:
                    from dashboard_events import push_dashboard_event
                    push_dashboard_event("SECURITY_ALERT", {
                        "phase": 5,
                        "agent": "Supervisor",
                        "message": f"Prompt injection detected in user input: {res.reason}",
                        "severity": "CRITICAL"
                    })
                elif res.is_malicious and not source_is_user:
                    from dashboard_events import push_dashboard_event
                    push_dashboard_event("SECURITY_ALERT", {
                        "phase": 5,
                        "agent": "Supervisor",
                        "message": f"Possible agent compromise detected in output: {res.reason}",
                        "severity": "WARNING"
                    })
                
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

    # Memory hook purpose: block malicious content from ChromaDB. Trust scoring is
    # already handled by Hooks 1-5 during request execution. Calling
    # trust_engine.process_payload here would register a 2nd injection against the
    # session (the memory string includes the agent's accumulated response which the
    # classifier may mislabel), collapsing H(x) to 0 and driving trust to ~0.13 even
    # for benign requests. We read the current score for provenance tagging but do
    # NOT register an injection for memory-sourced content.
    score = trust_engine.calculate_trust(session_id, "rag", res.is_malicious)
        
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
