"""Threshold evaluation, warnings, and limits for parallel task counts (§4.2)."""

from __future__ import annotations

from dataclasses import dataclass

from embervault_common.contracts.enums import (
    DiscoveryStatusLevel,
    ErrorCode,
    RunState,
)


@dataclass(frozen=True)
class RunPreconditionOutcome:
    """Outcome of evaluating parallel task count against thresholds before starting a run."""

    can_start: bool
    initial_state: RunState
    status_level: DiscoveryStatusLevel
    warning_code: str | None = None
    error_code: ErrorCode | None = None
    reason: str = ""


def calculate_task_count_estimate(subfolder_count: int, include_root_files: bool = True) -> int:
    """Calculate total task count estimate from discovered subfolders: 1 + subfolders count (§4.2).

    Args:
        subfolder_count: Number of first-level subfolders.
        include_root_files: Whether a root files task is generated (default True).

    Returns:
        Total estimated tasks.
    """
    base = 1 if include_root_files else 0
    return max(1, base + max(0, subfolder_count))


def evaluate_threshold_level(
    task_count: int,
    warn_threshold: int = 50,
    hard_limit: int = 500,
    enabled_proxy_count: int = 1,
) -> DiscoveryStatusLevel:
    """Evaluate warning level (ok, warn, blocked) for a given task count (§4.2).

    The warn threshold is evaluated against the ratio of estimated tasks to enabled proxies:
    task_count / max(1, enabled_proxy_count) > warn_threshold.

    Args:
        task_count: Total tasks to be executed.
        warn_threshold: Ratio threshold (tasks / enabled proxies) beyond which a warning is issued (default 50).
        hard_limit: Hard block limit on absolute task count (default 500).
        enabled_proxy_count: Number of enabled proxies available to execute the job (default 1).

    Returns:
        DiscoveryStatusLevel: OK, WARN, or BLOCKED.
    """
    if task_count > hard_limit:
        return DiscoveryStatusLevel.BLOCKED

    proxies = max(1, enabled_proxy_count)
    task_proxy_ratio = task_count / proxies
    if task_proxy_ratio > warn_threshold:
        return DiscoveryStatusLevel.WARN

    return DiscoveryStatusLevel.OK


def evaluate_run_preconditions(
    task_count: int,
    warn_threshold: int = 50,
    hard_limit: int = 500,
    is_manual: bool = False,
    ack_task_count: int | None = None,
    enabled_proxy_count: int = 1,
) -> RunPreconditionOutcome:
    """Evaluate whether a run can proceed to execution or requires confirmation / fails (§4.2).

    Rules:
    1. Ratio <= warn (and task_count <= hard): proceeds immediately -> RUNNING.
    2. Ratio > warn and task_count <= hard:
       - Manual run: holds in AWAITING_CONFIRMATION until admin ack.
       - Scheduled run: proceeds to RUNNING with warning_code=PARALLEL_TASK_COUNT_HIGH.
    3. N > hard:
       - If ack_task_count is set and >= N:
         - Manual run: holds in AWAITING_CONFIRMATION.
         - Scheduled run: proceeds to RUNNING.
       - If ack_task_count is None or < N:
         - Fails immediately -> FAILED, error_code=PARALLEL_TASK_LIMIT_EXCEEDED.

    Returns:
        RunPreconditionOutcome with state, warning/error codes, and explanation.
    """
    level = evaluate_threshold_level(
        task_count=task_count,
        warn_threshold=warn_threshold,
        hard_limit=hard_limit,
        enabled_proxy_count=enabled_proxy_count,
    )

    # 1. Within safe threshold
    if level == DiscoveryStatusLevel.OK:
        return RunPreconditionOutcome(
            can_start=True,
            initial_state=RunState.RUNNING,
            status_level=level,
            warning_code=None,
            error_code=None,
            reason="Task count within normal operational limits.",
        )

    # 2. Above warn threshold, but within hard limit
    if level == DiscoveryStatusLevel.WARN:
        proxies = max(1, enabled_proxy_count)
        ratio = round(task_count / proxies, 1)
        if is_manual:
            return RunPreconditionOutcome(
                can_start=False,
                initial_state=RunState.AWAITING_CONFIRMATION,
                status_level=level,
                warning_code="PARALLEL_TASK_COUNT_HIGH",
                error_code=None,
                reason=f"Task/Proxy ratio ({ratio} = {task_count}/{proxies}) exceeds warn threshold ({warn_threshold}). Confirmation required for manual run.",
            )
        return RunPreconditionOutcome(
            can_start=True,
            initial_state=RunState.RUNNING,
            status_level=level,
            warning_code="PARALLEL_TASK_COUNT_HIGH",
            error_code=None,
            reason=f"Task/Proxy ratio ({ratio} = {task_count}/{proxies}) exceeds warn threshold ({warn_threshold}). Proceeding with high task count warning.",
        )

    # 3. Exceeds hard limit
    has_valid_ack = ack_task_count is not None and ack_task_count >= task_count

    if has_valid_ack:
        if is_manual:
            return RunPreconditionOutcome(
                can_start=False,
                initial_state=RunState.AWAITING_CONFIRMATION,
                status_level=level,
                warning_code="PARALLEL_TASK_COUNT_HIGH",
                error_code=None,
                reason=f"Task count ({task_count}) exceeds hard limit ({hard_limit}) but was pre-acknowledged ({ack_task_count}). Confirmation requested for manual run.",
            )
        return RunPreconditionOutcome(
            can_start=True,
            initial_state=RunState.RUNNING,
            status_level=level,
            warning_code=None,
            error_code=None,
            reason=f"Task count ({task_count}) exceeds hard limit ({hard_limit}) but was explicitly pre-acknowledged in job ({ack_task_count}). Proceeding.",
        )

    # Exceeds hard limit without valid acknowledgment -> FAIL
    return RunPreconditionOutcome(
        can_start=False,
        initial_state=RunState.FAILED,
        status_level=level,
        warning_code=None,
        error_code=ErrorCode.PARALLEL_TASK_LIMIT_EXCEEDED,
        reason=f"Task count ({task_count}) exceeds hard limit ({hard_limit}) without explicit parallel_ack_task_count acknowledgment.",
    )
