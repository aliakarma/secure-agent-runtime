"""
The five interception hooks and the phases that act at them (paper §3.1, Table phases).

    Phase  Hook  Where                              Check                         On a flag
    1      H1    worker input, before inference     detector                      strip span, mark, register
    2      H2    every tool call, before dispatch   detector (text) / modality    refuse the call, register
    3      --    tool execution                     JSON-RPC sandbox              refuse a malformed call
    4      H3    tool response, before the model    detector after JSON unrolling strip span, mark, register
    5      H4    memory write, after the graph      memory-adapted detector       sanitized stub, no registration
    6      H5    supervisor entry, worker returns   detector                      strip span, mark, register
    7      --    before every tool dispatch         enforcement tier              writes refused at MEDIUM
                                                                                  (or step-up), all at LOW
    8      --    before every inference             tier masking, 17 regexes,     mask or strip spans
                                                    boundary markers
    9      --    model response                     persona and leakage rules     regenerate (<= 3), then review

A flag at H1, H3, or H5 does not end the turn: the flagged span is replaced by
``[SANITIZED]``, an injection is registered with the trust engine, and control
returns to the graph. This action does not depend on the trust engine, so a
configuration with the trust engine disabled still removes what the detector
flags; it only loses the tier consequences.

Which hooks run is set by ``HOOKS`` (comma list, default all five);
``INTERCEPTION_MODE=perimeter`` runs H1 only. The detector is the fine-tuned
classifier in ``full-research``/``secure`` mode and the keyword heuristic in
``fast`` mode; the heuristic is not OR-ed with the classifier.
"""

import contextvars
import functools
import json
import os
import re as _re

from config import settings
from logging_config import get_logger

logger = get_logger(__name__)

from sanitizers.multimodal import (AudioSanitizer, PdfSanitizer, RAGSanitizer, SanitizerResult,
                                   TextSanitizer, ToolOutputSanitizer, VideoSanitizer,
                                   VisualSanitizer, _unroll_structured_text)
from sanitizers.pre_llm import pre_llm_sanitizer
from sanitizers.recovery_loop import with_validation_and_recovery
from sanitizers.trust_engine import TIER_ORDER, trust_engine

text_sanitizer = TextSanitizer()
visual_sanitizer = VisualSanitizer()
tool_sanitizer = ToolOutputSanitizer()
rag_sanitizer = RAGSanitizer()
audio_sanitizer = AudioSanitizer()
video_sanitizer = VideoSanitizer()
pdf_sanitizer = PdfSanitizer()

SANITIZED = "[SANITIZED]"

current_session_id = contextvars.ContextVar("current_session_id", default="default_session")
current_trust_tier = contextvars.ContextVar("current_trust_tier", default="HIGH")


# ── Switches ─────────────────────────────────────────────────────────

def security_off() -> bool:
    return os.getenv("DISABLE_ALL_SECURITY", "0") == "1"


def trust_on() -> bool:
    return os.getenv("DISABLE_TRUST_ENGINE", "0") != "1"


def hook_on(n: int) -> bool:
    if security_off():
        return False
    if n == 4 and os.getenv("DISABLE_MEMORY_SANITIZATION", "0") == "1":
        return False
    return n in settings.hooks_enabled


def perimeter_only() -> bool:
    """True when only Hook 1 runs (the perimeter baseline)."""
    return settings.hooks_enabled == {1}


def phase8_on() -> bool:
    return not security_off() and not settings.disable_pre_llm


def phase9_on() -> bool:
    return not security_off() and os.getenv("DISABLE_OUTPUT_VALIDATOR", "0") != "1"


# ── Detection and span stripping ─────────────────────────────────────

_INSTRUMENTATION = [
    (r"--- USER INPUT START ---\n?", ""),
    (r"\n?--- USER INPUT END ---", ""),
    (r"\[PROVENANCE:[^\]]+\]\n*", ""),
    (r'\b[a-zA-Z]:[\\/][^:\*\?"<>\|]+?\.[a-zA-Z0-9]{3,4}\b', "[FILEPATH]"),
    (r"\bdatasets[\\/][A-Za-z0-9_.\-\\/]+", "[FILEPATH]"),
]


def clean_for_scan(text: str) -> str:
    """Remove the runtime's own instrumentation before classification."""
    out = str(text)
    for pattern, repl in _INSTRUMENTATION:
        out = _re.sub(pattern, repl, out, flags=_re.MULTILINE)
    return out.strip()


def detect(text: str) -> SanitizerResult:
    """The hook detector: classifier (secure modes) or keyword heuristic (fast mode)."""
    return text_sanitizer.sanitize(text)


_SENTENCE = _re.compile(r"(?<=[.!?])\s+|\n+")


def strip_flagged_spans(text: str) -> tuple:
    """Replace the flagged spans of ``text`` with ``[SANITIZED]``.

    JSON is handled leaf by leaf, so only the offending string values are
    replaced and the structure survives. Other text is split into sentences and
    each is classified. If no single span is flagged although the whole text was,
    the whole text is replaced. Returns ``(sanitized_text, n_spans_replaced)``.
    """
    try:
        obj = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        obj = None

    if isinstance(obj, (dict, list)):
        count = 0

        def walk(node, depth=0):
            nonlocal count
            if isinstance(node, str):
                s = node.strip()
                if depth < 4 and s[:1] in ("{", "["):
                    try:
                        return json.dumps(walk(json.loads(s), depth + 1))
                    except (json.JSONDecodeError, TypeError):
                        pass
                if s and detect(node).is_malicious:
                    count += 1
                    return SANITIZED
                return node
            if isinstance(node, dict):
                return {k: (v if k in ("jsonrpc", "id") else walk(v, depth)) for k, v in node.items()}
            if isinstance(node, list):
                return [walk(v, depth) for v in node]
            return node

        cleaned = walk(obj)
        if count:
            return json.dumps(cleaned), count
        return SANITIZED, 1

    spans = [s for s in _SENTENCE.split(str(text)) if s and s.strip()]
    kept, count = [], 0
    for span in spans:
        if detect(span).is_malicious:
            kept.append(SANITIZED)
            count += 1
        else:
            kept.append(span)
    if count == 0:
        return SANITIZED, 1
    return " ".join(kept), count


def _alert(session_id, phase, agent, message, severity="CRITICAL", **extra):
    try:
        from dashboard_events import push_dashboard_event
        push_dashboard_event("SECURITY_ALERT", {"session_id": session_id, "phase": phase,
                                                "agent": agent, "message": message,
                                                "severity": severity, **extra})
    except Exception:
        pass


def _screen_message(state, session_id: str, hook: int, source: str, agent: str) -> None:
    """H1/H5 action on the last message: detect; on a flag strip, mark, register."""
    msg = state["messages"][-1]
    raw = msg.content if isinstance(msg.content, str) else str(msg.content)
    clean = clean_for_scan(raw)
    res = detect(clean)
    if res.is_malicious:
        sanitized, n = strip_flagged_spans(clean)
        msg.content = f"{sanitized}\n{SANITIZED}"
        _alert(session_id, hook, agent, f"Injection detected at Hook {hook}: {res.reason}",
               detector=text_sanitizer.detector_name,
               confidence=round(float(getattr(res, "confidence", 0.0) or 0.0), 3))
        logger.warning(f"Hook {hook}: flagged {n} span(s) in {source} message ({res.reason})")
    if trust_on():
        score, tier = trust_engine.process_payload(session_id, clean, source, res.is_malicious)
        state["trust_score"] = score
        state["trust_tier"] = tier
        current_trust_tier.set(tier)


def _phase8_and_9(state, runnable, name, tier):
    if phase8_on() and state and "messages" in state:
        state["messages"] = pre_llm_sanitizer.sanitize_context(state["messages"], tier)
    if phase9_on():
        return with_validation_and_recovery(name, runnable)(state)
    return runnable(state)


# ═══════════════════════════════════════════════════════════════════
# Hook 1: worker input
# ═══════════════════════════════════════════════════════════════════

def secure_agent_node(agent_name, agent_runnable):
    def wrapper(state):
        if security_off():
            return agent_runnable(state)

        session_id = state.get("session_id", "default_session")
        current_session_id.set(session_id)
        current_trust_tier.set(trust_engine.session_tier(session_id) if trust_on()
                               else state.get("trust_tier", "HIGH"))

        if state and state.get("messages") and hook_on(1) and not state.get("input_pre_scanned"):
            logger.info(f"Hook 1: screening input to {agent_name}")
            last = state["messages"][-1].content
            from trust.graphchain import graphchain
            graphchain.build_structural_map(session_id=session_id, source="user_or_agent",
                                            content=str(last), modalities=["text"],
                                            initial_trust=1.0 if current_trust_tier.get() == "HIGH" else 0.5)
            _screen_message(state, session_id, 1, "user", agent_name)

            from sanitizers.provenance import provenance_agent
            tag = provenance_agent.tag_input(
                session_id=session_id, content=state["messages"][-1].content, source="user",
                modality="text", sanitizers=["TextSanitizer"],
                trust_score=state.get("trust_score", 1.0), trust_tier=state.get("trust_tier", "HIGH"),
                raw_content=str(last))
            state["messages"][-1].content = f"{tag}\n\n{state['messages'][-1].content}"

        try:
            from dashboard_events import push_dashboard_event
            push_dashboard_event("NODE_ACTIVE", {"node": agent_name})
        except Exception:
            pass

        tier = trust_engine.session_tier(session_id) if trust_on() else "HIGH"
        current_trust_tier.set(tier)
        res_dict = _phase8_and_9(state, agent_runnable, agent_name, tier)
        if isinstance(res_dict, dict):
            res_dict["trust_score"] = state.get("trust_score", 1.0)
            res_dict["trust_tier"] = trust_engine.session_tier(session_id) if trust_on() else "HIGH"
        return res_dict
    return wrapper


# ═══════════════════════════════════════════════════════════════════
# Phase 7, Hook 2, Phase 3, Hook 3: around every tool call
# ═══════════════════════════════════════════════════════════════════

def _arg_sanitizer(tool_name: str, key, value):
    v = str(value)
    if tool_name == "read_image_ocr" and (key == "image_path" or v.endswith((".png", ".jpg"))):
        return visual_sanitizer.sanitize(v)
    if tool_name == "process_audio_memo" and (key == "audio_path" or v.endswith((".wav", ".mp3"))):
        return audio_sanitizer.sanitize(v)
    if tool_name == "analyze_video_feed" and (key == "video_path" or v.endswith(".mp4")):
        return video_sanitizer.sanitize(v)
    if tool_name == "read_pdf_document" and (key == "pdf_path" or v.lower().endswith(".pdf")):
        return pdf_sanitizer.sanitize(v)
    return detect(v)


# Tool calls that actually dispatched, per session: [(tool, parameters)]. The
# evaluation harness reads this to decide whether a write executed, which does
# not depend on how a given agent formats its messages.
executed_calls: dict = {}


def _record_dispatch(session_id: str, tool_name: str, parameters: dict) -> None:
    executed_calls.setdefault(session_id, []).append((tool_name, dict(parameters)))


def pop_executed_calls(session_id: str) -> list:
    return executed_calls.pop(session_id, [])


def secure_tool_wrapper(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        from sanitizers import step_up
        tool_name = func.__name__
        session_id = current_session_id.get()

        import inspect
        bound = inspect.signature(func).bind(*args, **kwargs)
        bound.apply_defaults()
        parameters = dict(bound.arguments)

        if security_off():
            _record_dispatch(session_id, tool_name, parameters)
            return func(*args, **kwargs)

        # Phase 7: enforcement tier (Equation 2). The context tier is a floor:
        # a caller that already observed a lower tier cannot have it silently
        # raised by the session-engine lookup, so the minimum of the two wins.
        if trust_on():
            tier = current_trust_tier.get()
            session_tier = trust_engine.session_tier(session_id)
            if TIER_ORDER[session_tier] < TIER_ORDER[tier]:
                tier = session_tier
            current_trust_tier.set(tier)
            if tier == "LOW":
                _alert(session_id, 7, tool_name, "Tool blocked at LOW trust.")
                return "[REJECTED] Error: Action blocked by security policy (LOW trust)."
            if tier == "MEDIUM" and step_up.is_state_changing(tool_name):
                if settings.step_up_confirmation and step_up.request_confirmation(
                        session_id, tool_name, parameters):
                    logger.info(f"Phase 7: {tool_name} approved by step-up confirmation")
                else:
                    _alert(session_id, 7, tool_name, "Write blocked at MEDIUM trust.", "WARNING")
                    return (f"[REJECTED] Error: Tool {tool_name} blocked. "
                            "Medium trust only allows read-only tools.")

        # Hook 2: arguments.
        if hook_on(2):
            for key, value in parameters.items():
                res = _arg_sanitizer(tool_name, key, value)
                if res.is_malicious:
                    _alert(session_id, 2, tool_name, f"Tool arguments refused: {res.reason}")
                    if trust_on():
                        trust_engine.process_payload(session_id, str(value), "agent", True)
                    return "[REJECTED] Error: Suspicious tool arguments detected and blocked."

        # Phase 3: sandboxed execution.
        from agents.mcp_sandbox import mcp_sandbox
        result = mcp_sandbox.execute(tool_name, parameters, func)
        if '"error"' not in str(result)[:200]:
            _record_dispatch(session_id, tool_name, parameters)

        # Hook 3: tool response.
        if not hook_on(3):
            return result
        text = str(result)
        res = tool_sanitizer.sanitize(text)
        if res.is_malicious:
            sanitized, n = strip_flagged_spans(text)
            _alert(session_id, 4, tool_name, f"Injection in tool response: {res.reason}")
            logger.warning(f"Hook 3 ({tool_name}): {n} span(s) sanitized")
            text = f"{sanitized}\n{SANITIZED}"
        tier = current_trust_tier.get()
        score = 1.0
        if trust_on():
            score, tier = trust_engine.process_payload(
                session_id, _unroll_structured_text(str(result)), f"tool_{tool_name}", res.is_malicious)
            current_trust_tier.set(tier)

        from sanitizers.provenance import provenance_agent
        tag = provenance_agent.tag_input(session_id=session_id, content=text, source=f"tool_{tool_name}",
                                         modality="text", sanitizers=["ToolOutputSanitizer"],
                                         trust_score=score, trust_tier=tier, raw_content=str(result))
        return f"{tag}\n\n{text}"
    return wrapper


# ═══════════════════════════════════════════════════════════════════
# Hook 5: supervisor entry and worker returns
# ═══════════════════════════════════════════════════════════════════

def secure_routing_hook(supervisor_runnable):
    def wrapper(state):
        if security_off():
            return supervisor_runnable(state)
        session_id = state.get("session_id", "default_session")
        current_session_id.set(session_id)

        if hook_on(5) and state and state.get("messages"):
            from langchain_core.messages import HumanMessage
            is_user = isinstance(state["messages"][-1], HumanMessage)
            logger.info(f"Hook 5: screening {'user message' if is_user else 'worker return'}")
            _screen_message(state, session_id, 5, "user" if is_user else "agent", "Supervisor")

        tier = trust_engine.session_tier(session_id) if trust_on() else "HIGH"
        res_dict = _phase8_and_9(state, supervisor_runnable, "Supervisor", tier)
        if isinstance(res_dict, dict):
            res_dict["trust_score"] = state.get("trust_score", 1.0)
            res_dict["trust_tier"] = trust_engine.session_tier(session_id) if trust_on() else "HIGH"
        return res_dict
    return wrapper


# ═══════════════════════════════════════════════════════════════════
# Hook 4: memory write
# ═══════════════════════════════════════════════════════════════════

def secure_memory_hook(session_id: str, memory_string: str) -> str:
    """Screen a memory write; store a sanitized stub on a flag. Registers nothing,
    because the content is assembled from text already screened upstream."""
    if not hook_on(4):
        return memory_string
    logger.info("Hook 4: screening memory write")
    res = rag_sanitizer.sanitize(memory_string)
    score = trust_engine.calculate_trust(session_id, "rag", res.is_malicious)

    from sanitizers.provenance import provenance_agent
    tag = provenance_agent.tag_input(session_id=session_id,
                                     content=memory_string if not res.is_malicious else SANITIZED,
                                     source="rag", modality="text", sanitizers=["RAGSanitizer"],
                                     trust_score=score, trust_tier=trust_engine.determine_tier(score))
    if res.is_malicious:
        logger.warning(f"Hook 4: memory write replaced by a stub ({res.reason})")
        return f"{tag}\n{SANITIZED} Memory storage blocked due to suspicious content."
    return f"{tag}\n{memory_string}"
