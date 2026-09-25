"""
Reset process-wide trust state between tests.

``current_trust_tier``/``current_session_id`` (sanitizers/hooks.py) and the
TrustEngine's in-memory store are shared module-level state, not per-request:
production isolates them per request via ``secure_routing_hook``, which sets
a fresh tier from ``session_tier(session_id)`` at the top of every graph
invocation. Tests that call ``secure_tool_wrapper``-wrapped tools directly,
or hit an endpoint that skips that entry point, never take that reset, so a
tier written by one test's ContextVar ``.set()`` leaks into every later test
sharing the same interpreter thread — ``secure_tool_wrapper``'s floor logic
(Equation 2) then latches onto it, capping unrelated sessions that should be
HIGH. Resetting both before each test keeps tests independent of run order.
"""
import os
import pytest

os.environ["MCP_ISOLATION"] = "0"

from sanitizers.hooks import current_session_id, current_trust_tier
from sanitizers.trust_engine import trust_engine


@pytest.fixture(autouse=True)
def _reset_trust_state():
    trust_engine.reset_all()
    session_token = current_session_id.set("default_session")
    tier_token = current_trust_tier.set("HIGH")
    try:
        yield
    finally:
        trust_engine.reset_all()
        current_session_id.reset(session_token)
        current_trust_tier.reset(tier_token)
