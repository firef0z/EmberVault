"""Retry, backoff, and error classification package."""

from embervault_orchestrator.retry.backoff import (
    calculate_backoff_delay,
    get_base_backoff_delay,
)
from embervault_orchestrator.retry.classifier import (
    RCLONE_EXIT_CODE_MAP,
    FailureDecision,
    classify_rclone_exit_code,
    classify_task_failure,
)
from embervault_orchestrator.retry.cooldown import calculate_proxy_cooldown

__all__ = [
    "RCLONE_EXIT_CODE_MAP",
    "FailureDecision",
    "calculate_backoff_delay",
    "calculate_proxy_cooldown",
    "classify_rclone_exit_code",
    "classify_task_failure",
    "get_base_backoff_delay",
]
