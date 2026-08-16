"""
Agent model backends.

The paper evaluates on two base models of differing native alignment, and leads
with the weakly-aligned one because that is where the middleware has something
to do (§7.3, §8.1):

  * ``openai`` — ``gpt-4o-mini-2024-07-18`` through the OpenAI API. The
    strongly-aligned arm; a large share of the corpus is blocked by the model's
    own safety training before the runtime sees it.
  * ``vllm``  — ``meta-llama/Llama-3.1-8B-Instruct`` served locally in bf16
    through vLLM without quantization, exposed on vLLM's OpenAI-compatible
    endpoint. The **lead** arm: undefended attack success is roughly double.
  * ``deterministic`` — the offline susceptible-model oracle
    (``agents/deterministic_agent.py``). Not a paper arm; it is this
    repository's reproducibility harness, selected through the graph builder
    rather than here.

Holding corpus, domain, tool surface, and grader fixed while changing only this
setting is what produces the paper's base-model finding — undefended attack
success moves from 14.0% to 27.0%, which is why cross-paper ASR comparisons that
do not report the base model are close to uninterpretable.

Selection is by ``AGENT_BACKEND``; per-call overrides let an experiment run both
arms in one process without mutating global state.
"""

from __future__ import annotations

import os
from typing import Any, Optional

from config import settings
from logging_config import get_logger

logger = get_logger(__name__)

# Temperature 0 everywhere: it minimises model-side stochasticity, though the
# paper is explicit that it does not deliver run-to-run reproducibility for
# hosted models (§7.3), which is why the primary experiment repeats five times.
DEFAULT_TEMPERATURE = 0.0


def active_backend(override: Optional[str] = None) -> str:
    return (override or settings.agent_backend or "openai").strip().lower()


def model_identity(override: Optional[str] = None) -> dict:
    """The exact model identity for the run manifest (§7.3)."""
    backend = active_backend(override)
    if backend == "vllm":
        return {
            "backend": "vllm",
            "model": settings.vllm_model,
            "precision": "bf16",
            "quantization": "none",
            "endpoint": settings.vllm_base_url,
            "arm": "llama",
        }
    if backend == "deterministic":
        return {
            "backend": "deterministic",
            "model": "susceptible-model oracle (agents/deterministic_agent.py)",
            "arm": "oracle",
        }
    return {
        "backend": "openai",
        "model": settings.openai_agent_model,
        "endpoint": "https://api.openai.com/v1",
        "arm": "gpt4o-mini",
    }


def build_chat_model(
    *,
    backend: Optional[str] = None,
    temperature: float = DEFAULT_TEMPERATURE,
    timeout: int = 60,
    max_retries: int = 1,
) -> Any:
    """Return a LangChain chat model for the selected backend.

    vLLM serves an OpenAI-compatible API, so both arms use the same client
    class with a different base URL and model name. That is deliberate: the
    only thing that differs between arms is the model, not the harness.
    """
    from langchain_openai import ChatOpenAI

    which = active_backend(backend)

    if which == "vllm":
        api_key = os.getenv("VLLM_API_KEY", "EMPTY")
        logger.info(f"Agent backend: vLLM {settings.vllm_model} at {settings.vllm_base_url}")
        return ChatOpenAI(
            model=settings.vllm_model,
            base_url=settings.vllm_base_url,
            api_key=api_key,
            temperature=temperature,
            timeout=timeout,
            max_retries=max_retries,
        )

    logger.info(f"Agent backend: OpenAI {settings.openai_agent_model}")
    # No cross-model fallback chain: a silent fallback to a different model
    # would break the base-model comparison the paper's §8.1 rests on.
    return ChatOpenAI(
        model=settings.openai_agent_model,
        temperature=temperature,
        timeout=timeout,
        max_retries=max_retries,
    )


def reset_cached_models() -> None:
    """Drop cached node chains so a backend switch takes effect in-process."""
    from agents.nodes import supervisor, flight_agent, hotel_agent

    supervisor._supervisor_chain = None
    flight_agent._flight_react_agent = None
    hotel_agent._hotel_react_agent = None
    logger.info("Cached agent chains cleared for backend switch")
