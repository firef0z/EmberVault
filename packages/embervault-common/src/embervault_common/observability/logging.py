"""Structured logging configuration with structlog and security redaction."""

from __future__ import annotations

import logging
import sys
from typing import Any, Literal, cast

import structlog
from structlog.contextvars import (
    bind_contextvars,
    clear_contextvars,
    merge_contextvars,
    unbind_contextvars,
)
from structlog.types import EventDict, FilteringBoundLogger, Processor

from embervault_common.security.redaction import RedactionProcessor

# Standard context keys used across EmberVault
STANDARD_CONTEXT_KEYS = (
    "request_id",
    "run_id",
    "task_id",
    "attempt_id",
    "proxy_id",
)


def bind_context(**kwargs: Any) -> None:
    """Bind contextual attributes (such as request_id, run_id, task_id) to the current execution context."""
    bind_contextvars(**kwargs)


def unbind_context(*keys: str) -> None:
    """Unbind specific keys from the current context."""
    unbind_contextvars(*keys)


def clear_context() -> None:
    """Clear all bound context variables."""
    clear_contextvars()


def get_logger(name: str | None = None) -> FilteringBoundLogger:
    """Get a structlog logger instance."""
    return cast(FilteringBoundLogger, structlog.get_logger(name))


def configure_logging(
    service: str,
    log_level: str = "INFO",
    log_format: Literal["json", "console"] = "json",
) -> None:
    """Configure structlog and standard logging for a given service."""
    # Convert string level to numeric logging level
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    # Standard library root logging configuration
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=numeric_level,
        force=True,
    )

    def add_service_processor(_logger: Any, _method_name: str, event_dict: EventDict) -> EventDict:
        event_dict.setdefault("service", service)
        return event_dict

    shared_processors: list[Processor] = [
        merge_contextvars,
        structlog.processors.add_log_level,
        add_service_processor,
        structlog.processors.TimeStamper(fmt="iso", utc=True, key="ts"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        RedactionProcessor(),
    ]

    if log_format.lower() == "console":
        renderer: Processor = structlog.dev.ConsoleRenderer(colors=True)
    else:
        renderer = structlog.processors.JSONRenderer()

    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )
