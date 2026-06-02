"""
Structured logging configuration for secure-agent-runtime.

Provides consistent, machine-readable JSON logs in production and
human-friendly colored console output during development. Every agent
action, sanitizer decision, and trust evaluation is traceable through
structured log events.

Usage:
    from logging_config import get_logger

    logger = get_logger(__name__)
    logger.info("agent_started", agent_id="planner-v1", task="summarize")
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

import structlog


def setup_logging(*, log_level: str | None = None, json_output: bool | None = None) -> None:
    """Initialize the structured logging pipeline.

    Parameters
    ----------
    log_level:
        Logging level name (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        Falls back to the ``LOG_LEVEL`` env-var, then defaults to ``INFO``.
    json_output:
        If ``True``, emit newline-delimited JSON.  If ``False``, emit
        colored console output.  Falls back to the ``LOG_JSON`` env-var
        (``"1"`` / ``"true"``), then defaults to ``False``.
    """
    level_name = (log_level or os.getenv("LOG_LEVEL", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)

    if json_output is None:
        json_output = os.getenv("LOG_JSON", "0").lower() in ("1", "true", "yes")

    # Shared processors applied to every log event
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if json_output:
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(level)

    # Quiet noisy third-party loggers
    for noisy in ("httpx", "httpcore", "chromadb", "openai"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str, **initial_bindings: Any) -> structlog.stdlib.BoundLogger:
    """Return a structured logger bound to `name`.

    Parameters
    ----------
    name:
        Typically ``__name__`` of the calling module.
    **initial_bindings:
        Key-value pairs permanently bound to every event from this logger.
    """
    return structlog.get_logger(name, **initial_bindings)


# Auto-initialize when the module is first imported
setup_logging()
