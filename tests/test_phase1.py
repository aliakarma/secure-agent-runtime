"""Basic smoke tests for Phase 1 setup."""

from __future__ import annotations

import importlib


def test_logging_config_imports():
    """Verify structured logging initializes without errors."""
    mod = importlib.import_module("logging_config")
    logger = mod.get_logger("test")
    assert logger is not None


def test_hello_graph_runs():
    """Verify the Hello LangGraph graph executes end-to-end."""
    from agents.hello_graph import run

    result = run()
    assert result["step_count"] == 3
    assert len(result["messages"]) >= 3


def test_fastapi_app_exists():
    """Verify the FastAPI application object can be imported."""
    from main import app

    assert app.title == "Secure Agent Runtime"
