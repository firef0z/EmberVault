"""Observability utilities for EmberVault."""

from embervault_common.observability.logging import (
    bind_context,
    clear_context,
    configure_logging,
    get_logger,
    unbind_context,
)
from embervault_common.observability.metrics import (
    HTTP_REQUEST_DURATION_SECONDS,
    HTTP_REQUESTS_TOTAL,
    SERVICE_INFO,
    create_metrics_middleware,
    generate_metrics_response,
    init_service_metrics,
)

__all__ = [
    "HTTP_REQUEST_DURATION_SECONDS",
    "HTTP_REQUESTS_TOTAL",
    "SERVICE_INFO",
    "bind_context",
    "clear_context",
    "configure_logging",
    "create_metrics_middleware",
    "generate_metrics_response",
    "get_logger",
    "init_service_metrics",
    "unbind_context",
]
