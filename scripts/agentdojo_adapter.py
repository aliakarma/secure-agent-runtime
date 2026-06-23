"""
AgentDojo / InjecAgent adapter (gated).

Established agentic-injection benchmarks are the credible way to measure
end-to-end ASR *and* task utility (fixing the "mock tools → meaningless
utility" weakness). This adapter is import-gated: it reports availability and
install guidance when the package is absent, and exposes a uniform task
iterator when it is present, so the evaluation harness can plug it in without
the rest of the codebase depending on a heavy optional package.

Install:  pip install agentdojo
Docs:     https://github.com/ethz-spylab/agentdojo
"""

from __future__ import annotations

from typing import Any, Dict, List


def status() -> Dict[str, Any]:
    info: Dict[str, Any] = {"agentdojo": False, "injecagent": False, "install": "pip install agentdojo"}
    try:
        import agentdojo  # noqa: F401
        info["agentdojo"] = True
        try:
            info["version"] = agentdojo.__version__
        except Exception:
            info["version"] = "unknown"
    except Exception:
        info["agentdojo"] = False
    return info


def available() -> bool:
    return status()["agentdojo"]


def iter_suites() -> List[str]:
    """Return AgentDojo suite names when available, else an empty list."""
    if not available():
        return []
    try:
        from agentdojo.task_suite.load_suites import get_suites
        return sorted(get_suites("v1").keys())
    except Exception:
        return []


if __name__ == "__main__":
    import json
    print(json.dumps({"status": status(), "suites": iter_suites()}, indent=2))
