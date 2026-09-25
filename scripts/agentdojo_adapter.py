"""
AgentDojo Integration and Tool-Interception Adapter (Paper §5.7 / Table tab:agentdojo).

Ports the Secure Agent Runtime to AgentDojo's benchmark suites:
- Workspace, Slack, Travel, Banking (97 user tasks, 629 security test cases).
- Classifies tools into side-effect classes: 'read_only' and 'state_changing'.
- Binds runtime hooks to benchmark tool-execution loops:
    * Hook 2: screens every positional and keyword tool argument.
    * Phase 7 write gate: gates state-changing tool executions based on current session trust tier.
    * Hook 3: unrolls and sanitizes tool responses.
"""

from __future__ import annotations

import os
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

STATE_CHANGING_VERBS = (
    "send", "post", "transfer", "pay", "write", "delete", "remove",
    "modify", "update", "cancel", "book", "reserve", "grant", "create",
    "schedule", "dispatch", "publish", "execute"
)

READ_ONLY_VERBS = (
    "get", "search", "read", "view", "list", "fetch", "check", "inspect",
    "status", "query", "find", "show"
)


def classify_tool_side_effect(tool_name: str) -> str:
    """Classify an AgentDojo tool as 'read_only' or 'state_changing'."""
    lowered = re.sub(r"(?<!^)(?=[A-Z])", " ", tool_name).lower()
    if any(v in lowered for v in STATE_CHANGING_VERBS):
        return "state_changing"
    return "read_only"


class AgentDojoRuntimeAdapter:
    """Wraps AgentDojo tool execution with Secure Agent Runtime hooks and write gating."""

    def __init__(self, session_id: str = "agentdojo_session", mode: str = "secured"):
        self.session_id = session_id
        self.mode = mode
        self.interceptions = []

    def wrap_tool(self, tool_name: str, tool_callable: Callable) -> Callable:
        """Wrap an individual AgentDojo tool with Hook 2 and Phase 7 checks."""
        side_effect = classify_tool_side_effect(tool_name)

        def tool_wrapper(*args, **kwargs) -> Any:
            if self.mode == "undefended":
                return tool_callable(*args, **kwargs)

            # Phase 7 Write Gate: check session trust tier if tool causes side effects
            if side_effect == "state_changing":
                from sanitizers.trust_engine import trust_engine
                tier = trust_engine.session_tier(self.session_id)
                if tier in ("MEDIUM", "LOW"):
                    self.interceptions.append({
                        "hook": "Phase_7_write_gate",
                        "tool": tool_name,
                        "action": "refused_write",
                        "tier": tier
                    })
                    return {
                        "status": "error",
                        "error": f"Execution of state-changing tool '{tool_name}' refused under trust tier {tier}."
                    }

            # Hook 2: Screen tool arguments for prompt injections
            from sanitizers.hooks import secure_tool_args_hook
            is_safe, violation = secure_tool_args_hook(self.session_id, tool_name, args, kwargs)
            if not is_safe:
                self.interceptions.append({
                    "hook": "Hook_2_tool_args",
                    "tool": tool_name,
                    "action": "refused_injection",
                    "detail": violation
                })
                return {
                    "status": "error",
                    "error": f"Tool call refused by Hook 2 security interceptor: {violation}"
                }

            # Execute tool
            raw_output = tool_callable(*args, **kwargs)

            # Hook 3: Screen and sanitize tool output
            from sanitizers.hooks import secure_tool_output_hook
            sanitized_output = secure_tool_output_hook(self.session_id, tool_name, raw_output)
            return sanitized_output

        return tool_wrapper


def status() -> Dict[str, Any]:
    info: Dict[str, Any] = {"agentdojo": False, "install": "pip install agentdojo"}
    try:
        import agentdojo
        info["agentdojo"] = True
        info["version"] = getattr(agentdojo, "__version__", "installed")
    except ImportError:
        info["agentdojo"] = False
    return info


def available() -> bool:
    return status()["agentdojo"]


def iter_suites() -> List[str]:
    return ["workspace", "slack", "travel", "banking"]


if __name__ == "__main__":
    import json
    adapter = AgentDojoRuntimeAdapter()
    print("AgentDojo Adapter Status:", json.dumps(status(), indent=2))
    print("Side effect of 'send_email':", classify_tool_side_effect("send_email"))
    print("Side effect of 'search_calendar':", classify_tool_side_effect("search_calendar"))
