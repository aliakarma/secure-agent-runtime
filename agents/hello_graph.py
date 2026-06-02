"""
Hello LangGraph — a minimal state-graph demo.

This module builds a three-node graph that demonstrates the core LangGraph
concepts used throughout the secure-agent-runtime project:

  1. **Typed state** — a `TypedDict` that flows between nodes.
  2. **Nodes** — pure functions that receive and return state.
  3. **Edges** — connections (including conditional routing) between nodes.
  4. **Compilation & execution** — turning the graph into a runnable.

Run directly:
    python -m agents.hello_graph
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated, TypedDict

from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages

# Ensure project root is importable when running as a script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from logging_config import get_logger  # noqa: E402

logger = get_logger(__name__)


# ── State definition ──────────────────────────────────────────────────
class AgentState(TypedDict):
    """Minimal agent state that accumulates messages."""
    messages: Annotated[list[str], add_messages]
    step_count: int


# ── Node functions ────────────────────────────────────────────────────
def greet(state: AgentState) -> dict:
    """First node: produce a welcome message."""
    logger.info("node_executed", node="greet", step=state.get("step_count", 0))
    return {
        "messages": ["Hello! I am the Secure Agent Runtime."],
        "step_count": 1,
    }


def analyze(state: AgentState) -> dict:
    """Second node: simulate an analysis step."""
    logger.info("node_executed", node="analyze", step=state.get("step_count", 0))
    return {
        "messages": ["Analysis complete — all systems nominal."],
        "step_count": state.get("step_count", 0) + 1,
    }


def respond(state: AgentState) -> dict:
    """Third node: produce the final response."""
    logger.info("node_executed", node="respond", step=state.get("step_count", 0))
    return {
        "messages": [
            f"Pipeline finished after {state.get('step_count', 0) + 1} steps. "
            "Ready for Phase 2!"
        ],
        "step_count": state.get("step_count", 0) + 1,
    }


# ── Graph construction ───────────────────────────────────────────────
def build_hello_graph() -> StateGraph:
    """Build and compile the Hello LangGraph demo graph.

    Graph topology::

        greet → analyze → respond → END
    """
    graph = StateGraph(AgentState)

    graph.add_node("greet", greet)
    graph.add_node("analyze", analyze)
    graph.add_node("respond", respond)

    graph.set_entry_point("greet")
    graph.add_edge("greet", "analyze")
    graph.add_edge("analyze", "respond")
    graph.add_edge("respond", END)

    return graph.compile()


# ── Entrypoint ────────────────────────────────────────────────────────
def run() -> dict:
    """Execute the Hello graph and return the final state."""
    logger.info("graph_starting", graph="hello_langgraph")

    app = build_hello_graph()
    initial_state: AgentState = {"messages": [], "step_count": 0}
    result = app.invoke(initial_state)

    logger.info(
        "graph_completed",
        graph="hello_langgraph",
        total_steps=result.get("step_count"),
        message_count=len(result.get("messages", [])),
    )
    return result


if __name__ == "__main__":
    final_state = run()

    print("\n" + "=" * 60)
    print("  HELLO LANGGRAPH — Execution Result")
    print("=" * 60)
    for i, msg in enumerate(final_state["messages"], 1):
        if hasattr(msg, "content"):
            print(f"  [{i}] {msg.content}")
        else:
            print(f"  [{i}] {msg}")
    print(f"\n  Total steps: {final_state['step_count']}")
    print("=" * 60 + "\n")
