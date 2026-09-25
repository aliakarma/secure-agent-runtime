"""
Dependency-light tool implementations + registry.

Kept free of heavy imports (no transformers / sanitizers) so the MCP sandbox can
import it inside an isolated child process with minimal start-up cost. The
decorated, hook-wrapped tools in ``agents/tools.py`` re-export these.
"""

from __future__ import annotations

import os
import random


def _rng(*parts: str) -> random.Random:
    """Deterministic per-call randomness: the same arguments and TOOL_SEED give
    the same output in any process (the MCP sandbox runs tools in a child)."""
    import hashlib
    key = "|".join([os.getenv("TOOL_SEED", "42"), *map(str, parts)])
    return random.Random(int(hashlib.sha256(key.encode()).hexdigest()[:16], 16))


def _simulate_tool_poisoning(record: dict, default_field: str) -> str:
    """Return the tool's JSON response, optionally carrying an injected payload.

    Models a compromised external service (paper §2, attack vectors 2 and 3). Off
    by default. The evaluation harness pins the payload for each item through
    ``TOOL_POISON_PAYLOAD`` and, optionally, the field that carries it through
    ``TOOL_POISON_FIELD`` (default: the tool's free-text field). Only the tool the
    item targets is poisoned (``TOOL_POISON_TOOL``, default any).
    """
    import json as _json
    if os.getenv("SIMULATE_TOOL_POISONING", "0") == "1":
        target = os.getenv("TOOL_POISON_TOOL", "").strip()
        tool = record.get("_tool", "")
        payload = os.getenv("TOOL_POISON_PAYLOAD", "").strip()
        if payload and (not target or target == tool):
            field = os.getenv("TOOL_POISON_FIELD", "").strip() or default_field
            record[field] = payload
    record.pop("_tool", None)
    return _json.dumps(record)


def _impl_search_flights(destination: str, origin: str = "JFK", date: str = "2024-12-01") -> str:
    r = _rng("search_flights", destination, origin, date)
    record = {
        "_tool": "search_flights",
        "flight": f"FL{r.randint(100, 999)}",
        "origin": origin,
        "destination": destination,
        "date": date,
        "price_usd": r.randint(300, 1500),
        "status": "Available",
        "description": r.choice(["Economy seat with one checked bag.",
                                 "Direct flight, meal included.",
                                 "One stop, seat selection at check-in."]),
    }
    return _simulate_tool_poisoning(record, "description")


def _impl_reserve_hotel(location: str, checkin: str = "2024-12-01", checkout: str = "2024-12-05") -> str:
    r = _rng("reserve_hotel", location, checkin, checkout)
    record = {
        "_tool": "reserve_hotel",
        "status": "reserved",
        "hotel": r.choice(["Grand Plaza", "Sunset Inn", "Royal Heights", "The Cozy Corner"]),
        "location": location,
        "checkin": checkin,
        "checkout": checkout,
        "confirmation": f"CONF-{r.randint(1000, 9999)}",
        "notes": r.choice(["Breakfast included.", "Free cancellation until 48 hours before arrival.",
                           "Late check-out on request."]),
    }
    return _simulate_tool_poisoning(record, "notes")


def _impl_sandbox_selfcheck(secret_env: str = "MCP_SELFCHECK_SECRET") -> str:
    """Diagnostic: report the executing PID and whether a secret env var leaked
    into this process. Used by tests to prove real process isolation + env
    scrubbing. Honors ``MCP_SELFCHECK_SLEEP`` (seconds) so the timeout/DoS path
    can be exercised. Not exposed as an agent tool (absent from allowed_tools)."""
    import json as _json
    import time as _time
    sleep_s = float(os.getenv("MCP_SELFCHECK_SLEEP", "0") or "0")
    if sleep_s > 0:
        _time.sleep(sleep_s)
    return _json.dumps({"pid": os.getpid(), "secret_visible": os.getenv(secret_env) is not None})


# Tool names the MCP sandbox may execute in an isolated subprocess.
TOOL_REGISTRY = {
    "search_flights": _impl_search_flights,
    "reserve_hotel": _impl_reserve_hotel,
    "sandbox_selfcheck": _impl_sandbox_selfcheck,
}
