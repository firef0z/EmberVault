"""Concurrency limits evaluation and precedence resolution (§4.3)."""

from __future__ import annotations


def can_assign_task(
    running_global: int,
    limit_global: int,
    running_job: int,
    limit_job: int,
    running_proxy: int,
    limit_proxy: int,
) -> bool:
    """Evaluate if a task can be assigned satisfying all 3 concurrency bounds simultaneously (§4.3).

    A task is assigned ONLY IF:
    running_global < limit_global AND running_job < limit_job AND running_proxy < limit_proxy.

    Args:
        running_global: Current running tasks cluster-wide.
        limit_global: Global concurrency bound.
        running_job: Current running tasks for this specific job.
        limit_job: Job concurrency bound.
        running_proxy: Current running tasks on candidate proxy.
        limit_proxy: Proxy capacity limit (min of max_concurrent_tasks and reported capacity).

    Returns:
        True if all 3 limits are strictly respected, False otherwise.
    """
    if running_global < 0 or running_job < 0 or running_proxy < 0:
        return False

    return running_global < limit_global and running_job < limit_job and running_proxy < limit_proxy


def resolve_concurrency_limit(
    job_override: int | None = None,
    gui_override: int | None = None,
    env_override: int | None = None,
    default_limit: int = 1,
) -> int:
    """Resolve effective concurrency limit following precedence: job > GUI > env > default (§4.3).

    Args:
        job_override: Per-job override (highest precedence).
        gui_override: Setting saved via GUI/database.
        env_override: Environment variable setting.
        default_limit: Fallback code default.

    Returns:
        Effective positive integer limit >= 1.
    """
    for val in (job_override, gui_override, env_override):
        if val is not None and val >= 1:
            return val
    return max(1, default_limit)
