"""Pure state machine transitions for JobRun and Task instances."""

from __future__ import annotations

from embervault_common.contracts.enums import RunState, TaskState


class IllegalStateTransitionError(Exception):
    """Raised when an invalid state transition is attempted."""

    def __init__(self, entity: str, current_state: str, target_state: str) -> None:
        self.entity = entity
        self.current_state = current_state
        self.target_state = target_state
        super().__init__(
            f"Illegal {entity} state transition from '{current_state}' to '{target_state}'."
        )


# Valid directed transitions for JobRun
RUN_TRANSITIONS: dict[RunState, frozenset[RunState]] = {
    RunState.QUEUED: frozenset(
        {
            RunState.PLANNING,
            RunState.FAILED,  # e.g., NO_ONLINE_PROXY immediately at start
            RunState.CANCELLED,  # e.g., SKIPPED_OVERLAP or manual cancel
        }
    ),
    RunState.PLANNING: frozenset(
        {
            RunState.RUNNING,
            RunState.AWAITING_CONFIRMATION,  # manual run with task count > warn threshold
            RunState.FAILED,  # discovery failed, hard limit exceeded without ack
            RunState.CANCELLED,
        }
    ),
    RunState.AWAITING_CONFIRMATION: frozenset(
        {
            RunState.RUNNING,  # confirmed by admin
            RunState.CANCELLED,  # rejected or timed out
        }
    ),
    RunState.RUNNING: frozenset(
        {
            RunState.SUCCEEDED,  # all tasks ok
            RunState.PARTIALLY_FAILED,  # some tasks failed, at least one succeeded
            RunState.FAILED,  # all tasks failed
            RunState.CANCELLED,  # cancelled while running
        }
    ),
    # Terminal states
    RunState.SUCCEEDED: frozenset(),
    RunState.PARTIALLY_FAILED: frozenset(),
    RunState.FAILED: frozenset(),
    RunState.CANCELLED: frozenset(),
}

# Valid directed transitions for Task
TASK_TRANSITIONS: dict[TaskState, frozenset[TaskState]] = {
    TaskState.PENDING: frozenset(
        {
            TaskState.READY,
            TaskState.CANCELLED,
        }
    ),
    TaskState.READY: frozenset(
        {
            TaskState.ASSIGNED,
            TaskState.FAILED,  # e.g., assignment_timeout reached without proxy
            TaskState.CANCELLED,
        }
    ),
    TaskState.ASSIGNED: frozenset(
        {
            TaskState.RUNNING,  # proxy confirmed start
            TaskState.RETRY_WAIT,  # dispatch failed (network error / 5xx)
            TaskState.READY,  # 429/503 capacity full (re-queued without consuming attempt)
            TaskState.CANCELLED,
        }
    ),
    TaskState.RUNNING: frozenset(
        {
            TaskState.SUCCEEDED,
            TaskState.RETRY_WAIT,  # temporary error, timeout, or lost with attempts left
            TaskState.FAILED,  # permanent error or attempts exhausted
            TaskState.CANCELLED,
        }
    ),
    TaskState.RETRY_WAIT: frozenset(
        {
            TaskState.READY,  # next_attempt_at reached
            TaskState.CANCELLED,
        }
    ),
    # Terminal states
    TaskState.SUCCEEDED: frozenset(),
    TaskState.PARTIALLY_FAILED: frozenset(),
    TaskState.FAILED: frozenset(),
    TaskState.CANCELLED: frozenset(),
}


def can_transition_run(current_state: RunState | str, target_state: RunState | str) -> bool:
    """Check if a JobRun transition from current_state to target_state is permitted."""
    curr = RunState(current_state)
    tgt = RunState(target_state)
    return tgt in RUN_TRANSITIONS.get(curr, frozenset())


def transition_run(current_state: RunState | str, target_state: RunState | str) -> RunState:
    """Validate and execute a JobRun transition, returning the new state.

    Raises:
        IllegalStateTransitionError: If the transition is not allowed.
    """
    curr = RunState(current_state)
    tgt = RunState(target_state)
    if not can_transition_run(curr, tgt):
        raise IllegalStateTransitionError("JobRun", curr.value, tgt.value)
    return tgt


def can_transition_task(current_state: TaskState | str, target_state: TaskState | str) -> bool:
    """Check if a Task transition from current_state to target_state is permitted."""
    curr = TaskState(current_state)
    tgt = TaskState(target_state)
    return tgt in TASK_TRANSITIONS.get(curr, frozenset())


def transition_task(current_state: TaskState | str, target_state: TaskState | str) -> TaskState:
    """Validate and execute a Task transition, returning the new state.

    Raises:
        IllegalStateTransitionError: If the transition is not allowed.
    """
    curr = TaskState(current_state)
    tgt = TaskState(target_state)
    if not can_transition_task(curr, tgt):
        raise IllegalStateTransitionError("Task", curr.value, tgt.value)
    return tgt


def evaluate_run_outcome(task_states: list[TaskState | str]) -> RunState:
    """Determine terminal RunState based on completion outcomes of all child tasks.

    Rules:
    - Empty task list -> FAILED
    - If any task is still in a non-terminal state -> raises ValueError
    - All tasks SUCCEEDED -> SUCCEEDED
    - At least one task SUCCEEDED, some FAILED or CANCELLED -> PARTIALLY_FAILED
    - Zero tasks SUCCEEDED, all CANCELLED -> CANCELLED
    - Zero tasks SUCCEEDED, one or more FAILED -> FAILED
    """
    if not task_states:
        return RunState.FAILED

    states = [TaskState(s) for s in task_states]
    terminal_states = {TaskState.SUCCEEDED, TaskState.FAILED, TaskState.CANCELLED}

    non_terminal = [s for s in states if s not in terminal_states]
    if non_terminal:
        raise ValueError(
            f"Cannot evaluate final run outcome: {len(non_terminal)} tasks still non-terminal: {non_terminal}"
        )

    succeeded_count = sum(1 for s in states if s == TaskState.SUCCEEDED)
    failed_count = sum(1 for s in states if s == TaskState.FAILED)
    cancelled_count = sum(1 for s in states if s == TaskState.CANCELLED)

    if succeeded_count == len(states):
        return RunState.SUCCEEDED

    if succeeded_count > 0:
        return RunState.PARTIALLY_FAILED

    if failed_count == 0 and cancelled_count > 0:
        return RunState.CANCELLED

    return RunState.FAILED
