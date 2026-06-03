import time

# Global Event Queue for Dashboard Polling
dashboard_events = []

def push_dashboard_event(event_type: str, data: dict):
    """Synchronously push an event to the dashboard queue."""
    dashboard_events.append({
        "id": len(dashboard_events),
        "timestamp": time.time(),
        "type": event_type,
        "data": data
    })
