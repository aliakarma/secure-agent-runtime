"""
Secure Agent Runtime — FastAPI Application

The main API server that will host agent endpoints, health checks,
and administrative interfaces for the secure agentic AI system.
"""

from __future__ import annotations
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import time

from logging_config import get_logger

logger = get_logger(__name__)

from dashboard_events import dashboard_events, push_dashboard_event



@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    """Application lifespan: startup & shutdown hooks."""
    logger.info("app_starting", version="0.1.0", phase=1)
    yield
    logger.info("app_shutting_down")


app = FastAPI(
    title="Secure Agent Runtime",
    description=(
        "A security-first agentic AI runtime built on LangGraph. "
        "Provides sandboxed agent execution with trust scoring, "
        "input sanitization, and structured audit logging."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# Mount static files for the dashboard
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/api/events")
def get_events(since_id: int = -1):
    """Returns all events newer than since_id."""
    new_events = [e for e in dashboard_events if e["id"] > since_id]
    return JSONResponse({"events": new_events})




# ── Health & readiness ────────────────────────────────────────────────
@app.get("/health", tags=["infrastructure"])
async def health_check() -> JSONResponse:
    """Liveness probe — returns 200 if the server process is alive."""
    return JSONResponse({"status": "healthy", "phase": 1})


@app.get("/ready", tags=["infrastructure"])
async def readiness_check() -> JSONResponse:
    """Readiness probe — returns 200 when the app can serve traffic."""
    # In later phases this will verify DB connections, model loading, etc.
    return JSONResponse({"status": "ready", "services": {"chromadb": "unchecked"}})


# ── Demo endpoint ────────────────────────────────────────────────────
@app.get("/", tags=["demo"])
async def root() -> JSONResponse:
    """Landing endpoint showing project info."""
    logger.info("root_accessed")
    return JSONResponse({
        "project": "Secure Agent Runtime",
        "version": "0.1.0",
        "phase": 1,
        "message": "Welcome to the Secure Agent Runtime. All systems operational.",
    })


@app.post("/run-hello-graph", tags=["demo"])
async def run_hello_graph() -> JSONResponse:
    """Execute the Hello LangGraph demo graph and return the result."""
    from agents.hello_graph import run

    logger.info("hello_graph_triggered")
    result = run()

    # Serialize messages (handle both str and BaseMessage objects)
    messages = []
    for msg in result.get("messages", []):
        messages.append(msg.content if hasattr(msg, "content") else str(msg))

    return JSONResponse({
        "status": "completed",
        "messages": messages,
        "total_steps": result.get("step_count", 0),
    })

@app.post("/run-travel-graph", tags=["demo", "phase2"])
def run_travel_graph_endpoint(user_input: str, session_id: str = "default") -> JSONResponse:
    """Execute the Phase 2 travel booking graph."""
    from agents.workflow import run_travel_graph
    
    logger.info("travel_graph_triggered", session_id=session_id)
    push_dashboard_event("GRAPH_START", {"session_id": session_id, "input": user_input})
    
    result = run_travel_graph(user_input=user_input, session_id=session_id)
    
    # Serialize messages
    messages = []
    for msg in result.get("messages", []):
        name = msg.name if hasattr(msg, 'name') and msg.name else type(msg).__name__
        content = msg.content if hasattr(msg, 'content') else str(msg)
        messages.append({"role": name, "content": content})
        
    push_dashboard_event("GRAPH_END", {"session_id": session_id, "status": "completed"})
    
    return JSONResponse({
        "status": "completed",
        "messages": messages,
        "memory_used": result.get("memory", [])
    })
