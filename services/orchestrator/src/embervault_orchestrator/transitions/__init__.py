"""Transitions and state machine package."""

from embervault_orchestrator.transitions.state_machine import (
    RUN_TRANSITIONS,
    TASK_TRANSITIONS,
    IllegalStateTransitionError,
    can_transition_run,
    can_transition_task,
    evaluate_run_outcome,
    transition_run,
    transition_task,
)

__all__ = [
    "RUN_TRANSITIONS",
    "TASK_TRANSITIONS",
    "IllegalStateTransitionError",
    "can_transition_run",
    "can_transition_task",
    "evaluate_run_outcome",
    "transition_run",
    "transition_task",
]
