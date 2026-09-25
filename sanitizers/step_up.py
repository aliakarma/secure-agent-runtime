"""
Step-up confirmation for state-changing calls at MEDIUM (paper §3.3).

When ``STEP_UP_CONFIRMATION=1`` and the enforcement tier is MEDIUM, Phase 7 does
not refuse a state-changing call outright. The runtime, not the model, presents
the exact tool name and arguments to the user through a channel the model cannot
write to, and dispatches the call only on explicit approval.

The approval channel is a handler ``(session_id, tool_name, arguments) -> bool``.
The default handler rejects (no interactive user). Experiments install simulated
users: one that approves every request (the security worst case) and one that
approves only the writes the session script intends.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any, Callable, Dict

Handler = Callable[[str, str, Dict[str, Any]], bool]

_lock = threading.Lock()
_handler: Handler = lambda session_id, tool_name, arguments: False
_requests: Dict[str, int] = defaultdict(int)
_approvals: Dict[str, int] = defaultdict(int)

# Tools whose effect is read-only; everything else is state-changing.
READ_ONLY_TOOLS = {"search_flights", "read_image_ocr", "process_audio_memo",
                   "analyze_video_feed", "read_pdf_document"}


def is_state_changing(tool_name: str) -> bool:
    return tool_name not in READ_ONLY_TOOLS


def set_handler(handler: Handler) -> None:
    global _handler
    with _lock:
        _handler = handler


def request_confirmation(session_id: str, tool_name: str, arguments: Dict[str, Any]) -> bool:
    with _lock:
        _requests[session_id] += 1
        handler = _handler
    approved = bool(handler(session_id, tool_name, dict(arguments)))
    if approved:
        with _lock:
            _approvals[session_id] += 1
    return approved


def counts(session_id: str) -> Dict[str, int]:
    with _lock:
        return {"requests": _requests.get(session_id, 0), "approvals": _approvals.get(session_id, 0)}


def reset() -> None:
    with _lock:
        _requests.clear()
        _approvals.clear()
