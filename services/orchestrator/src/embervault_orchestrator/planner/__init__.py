"""Planner package for task generation, threshold limits, and concurrency control."""

from embervault_orchestrator.planner.concurrency import (
    can_assign_task,
    resolve_concurrency_limit,
)
from embervault_orchestrator.planner.spec import (
    DiscoveryResult,
    JobPlanningSpec,
    PlannedTask,
    plan_job_tasks,
)
from embervault_orchestrator.planner.thresholds import (
    RunPreconditionOutcome,
    calculate_task_count_estimate,
    evaluate_run_preconditions,
    evaluate_threshold_level,
)

__all__ = [
    "DiscoveryResult",
    "JobPlanningSpec",
    "PlannedTask",
    "RunPreconditionOutcome",
    "calculate_task_count_estimate",
    "can_assign_task",
    "evaluate_run_preconditions",
    "evaluate_threshold_level",
    "plan_job_tasks",
    "resolve_concurrency_limit",
]
