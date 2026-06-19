"""
Thread-safe, bounded telemetry buffer for the dashboard.

The buffer is capped (oldest events evicted) so a long-running server cannot
leak memory, and every read can be scoped to a single ``session_id`` so one
client never sees another session's events.
"""

import threading
import time
from collections import deque
from typing import Optional

from config import settings

_lock = threading.Lock()
dashboard_events: deque = deque(maxlen=settings.max_events)
_next_event_id = 0


def push_dashboard_event(event_type: str, data: dict) -> None:
    """Append an event to the bounded queue (thread-safe)."""
    global _next_event_id
    with _lock:
        event = {
            "id": _next_event_id,
            "timestamp": time.time(),
            "type": event_type,
            "data": data or {},
        }
        dashboard_events.append(event)
        _next_event_id += 1


def get_events(since_id: int = -1, session_id: Optional[str] = None) -> list[dict]:
    """Return events newer than ``since_id``.

    When ``session_id`` is provided, only events belonging to that session
    (plus session-less global notices) are returned, so callers cannot
    observe other sessions' telemetry.
    """
    with _lock:
        snapshot = list(dashboard_events)

    result = []
    for event in snapshot:
        if event["id"] <= since_id:
            continue
        if session_id is not None:
            ev_session = (event.get("data") or {}).get("session_id")
            if ev_session is not None and ev_session != session_id:
                continue
        result.append(event)
    return result
