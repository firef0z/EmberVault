"""EmberVault Orchestrator service."""

from embervault_orchestrator.advisory_lock import PostgresAdvisoryLock
from embervault_orchestrator.factory import create_orchestrator_app
from embervault_orchestrator.health_monitor import HealthMonitor
from embervault_orchestrator.main import OrchestratorSupervisor
from embervault_orchestrator.planner import (
    DiscoveryResult,
    JobPlanningSpec,
    PlannedTask,
    RunPreconditionOutcome,
    calculate_task_count_estimate,
    can_assign_task,
    evaluate_run_preconditions,
    evaluate_threshold_level,
    plan_job_tasks,
    resolve_concurrency_limit,
)
from embervault_orchestrator.proxy_client import (
    ProxyClient,
    ProxyUnauthorizedError,
    ProxyUnreachableError,
)
from embervault_orchestrator.retry import (
    RCLONE_EXIT_CODE_MAP,
    FailureDecision,
    calculate_backoff_delay,
    calculate_proxy_cooldown,
    classify_rclone_exit_code,
    classify_task_failure,
    get_base_backoff_delay,
)
from embervault_orchestrator.transitions import (
    RUN_TRANSITIONS,
    TASK_TRANSITIONS,
    IllegalStateTransitionError,
    can_transition_run,
    can_transition_task,
    evaluate_run_outcome,
    transition_run,
    transition_task,
)

__version__ = "1.0.0"
__all__ = [
    "DiscoveryResult",
    "FailureDecision",
    "HealthMonitor",
    "IllegalStateTransitionError",
    "JobPlanningSpec",
    "OrchestratorSupervisor",
    "PlannedTask",
    "PostgresAdvisoryLock",
    "ProxyClient",
    "ProxyUnauthorizedError",
    "ProxyUnreachableError",
    "RCLONE_EXIT_CODE_MAP",
    "RUN_TRANSITIONS",
    "RunPreconditionOutcome",
    "TASK_TRANSITIONS",
    "calculate_backoff_delay",
    "calculate_proxy_cooldown",
    "calculate_task_count_estimate",
    "can_assign_task",
    "can_transition_run",
    "can_transition_task",
    "classify_rclone_exit_code",
    "classify_task_failure",
    "create_orchestrator_app",
    "evaluate_run_outcome",
    "evaluate_run_preconditions",
    "evaluate_threshold_level",
    "get_base_backoff_delay",
    "plan_job_tasks",
    "resolve_concurrency_limit",
    "transition_run",
    "transition_task",
]
