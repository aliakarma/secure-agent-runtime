import time
from collections import deque

# Global Event Queue for Dashboard Polling
dashboard_events = deque(maxlen=1000)
_next_event_id = 0

def push_dashboard_event(event_type: str, data: dict):
    """Synchronously push an event to the dashboard queue."""
    global _next_event_id
    dashboard_events.append({
        "id": _next_event_id,
        "timestamp": time.time(),
        "type": event_type,
        "data": data
    })
    _next_event_id += 1
