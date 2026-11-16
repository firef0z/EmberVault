"""Unit and property-based tests for RunState and TaskState transitions and state machines."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from embervault_common.contracts.enums import RunState, TaskState
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


class TestRunStateMachine:
    """Test JobRun state transition rules (§4.4)."""

    def test_valid_queued_transitions(self) -> None:
        assert can_transition_run(RunState.QUEUED, RunState.PLANNING)
        assert can_transition_run(RunState.QUEUED, RunState.FAILED)
        assert can_transition_run(RunState.QUEUED, RunState.CANCELLED)
        assert transition_run(RunState.QUEUED, RunState.PLANNING) == RunState.PLANNING

    def test_valid_planning_transitions(self) -> None:
        assert can_transition_run(RunState.PLANNING, RunState.RUNNING)
        assert can_transition_run(RunState.PLANNING, RunState.AWAITING_CONFIRMATION)
        assert can_transition_run(RunState.PLANNING, RunState.FAILED)
        assert can_transition_run(RunState.PLANNING, RunState.CANCELLED)

    def test_valid_awaiting_confirmation_transitions(self) -> None:
        assert can_transition_run(RunState.AWAITING_CONFIRMATION, RunState.RUNNING)
        assert can_transition_run(RunState.AWAITING_CONFIRMATION, RunState.CANCELLED)

    def test_valid_running_transitions(self) -> None:
        assert can_transition_run(RunState.RUNNING, RunState.SUCCEEDED)
        assert can_transition_run(RunState.RUNNING, RunState.PARTIALLY_FAILED)
        assert can_transition_run(RunState.RUNNING, RunState.FAILED)
        assert can_transition_run(RunState.RUNNING, RunState.CANCELLED)

    def test_terminal_run_states_have_no_transitions(self) -> None:
        terminal_states = [
            RunState.SUCCEEDED,
            RunState.PARTIALLY_FAILED,
            RunState.FAILED,
            RunState.CANCELLED,
        ]
        for term in terminal_states:
            assert len(RUN_TRANSITIONS[term]) == 0
            for any_state in RunState:
                assert not can_transition_run(term, any_state)
                with pytest.raises(IllegalStateTransitionError) as exc_info:
                    transition_run(term, any_state)
                assert exc_info.value.entity == "JobRun"

    def test_illegal_run_transition_raises_error(self) -> None:
        # e.g., QUEUED directly to SUCCEEDED is illegal
        assert not can_transition_run(RunState.QUEUED, RunState.SUCCEEDED)
        with pytest.raises(IllegalStateTransitionError) as exc_info:
            transition_run(RunState.QUEUED, RunState.SUCCEEDED)
        assert "Illegal JobRun state transition from 'queued' to 'succeeded'" in str(exc_info.value)


class TestTaskStateMachine:
    """Test Task state transition rules (§4.4)."""

    def test_valid_task_transitions(self) -> None:
        assert can_transition_task(TaskState.PENDING, TaskState.READY)
        assert can_transition_task(TaskState.READY, TaskState.ASSIGNED)
        assert can_transition_task(TaskState.ASSIGNED, TaskState.RUNNING)
        assert can_transition_task(TaskState.ASSIGNED, TaskState.RETRY_WAIT)
        assert can_transition_task(TaskState.ASSIGNED, TaskState.READY)
        assert can_transition_task(TaskState.RUNNING, TaskState.SUCCEEDED)
        assert can_transition_task(TaskState.RUNNING, TaskState.RETRY_WAIT)
        assert can_transition_task(TaskState.RUNNING, TaskState.FAILED)
        assert can_transition_task(TaskState.RETRY_WAIT, TaskState.READY)

    def test_terminal_task_states_have_no_transitions(self) -> None:
        terminal_states = [TaskState.SUCCEEDED, TaskState.FAILED, TaskState.CANCELLED]
        for term in terminal_states:
            assert len(TASK_TRANSITIONS[term]) == 0
            for any_state in TaskState:
                assert not can_transition_task(term, any_state)
                with pytest.raises(IllegalStateTransitionError):
                    transition_task(term, any_state)

    def test_illegal_task_transition_raises_error(self) -> None:
        # e.g., PENDING directly to RUNNING is illegal
        assert not can_transition_task(TaskState.PENDING, TaskState.RUNNING)
        with pytest.raises(IllegalStateTransitionError) as exc_info:
            transition_task(TaskState.PENDING, TaskState.RUNNING)
        assert exc_info.value.entity == "Task"


class TestRunOutcomeEvaluation:
    """Test evaluating final RunState from child task completion states (§4.4)."""

    def test_empty_tasks_evaluates_to_failed(self) -> None:
        assert evaluate_run_outcome([]) == RunState.FAILED

    def test_all_tasks_succeeded_evaluates_to_succeeded(self) -> None:
        assert (
            evaluate_run_outcome([TaskState.SUCCEEDED, TaskState.SUCCEEDED, TaskState.SUCCEEDED])
            == RunState.SUCCEEDED
        )

    def test_some_succeeded_some_failed_evaluates_to_partially_failed(self) -> None:
        assert (
            evaluate_run_outcome([TaskState.SUCCEEDED, TaskState.FAILED, TaskState.SUCCEEDED])
            == RunState.PARTIALLY_FAILED
        )

    def test_zero_succeeded_some_failed_evaluates_to_failed(self) -> None:
        assert (
            evaluate_run_outcome([TaskState.FAILED, TaskState.FAILED, TaskState.FAILED])
            == RunState.FAILED
        )

    def test_zero_succeeded_all_cancelled_evaluates_to_cancelled(self) -> None:
        assert (
            evaluate_run_outcome([TaskState.CANCELLED, TaskState.CANCELLED]) == RunState.CANCELLED
        )

    def test_non_terminal_task_raises_error(self) -> None:
        with pytest.raises(ValueError, match="Cannot evaluate final run outcome"):
            evaluate_run_outcome([TaskState.SUCCEEDED, TaskState.RUNNING])


class TestStateMachineProperties:
    """Hypothesis property-based tests for state transitions."""

    @given(st.sampled_from(list(RunState)), st.sampled_from(list(RunState)))
    def test_run_transition_consistency(self, state1: RunState, state2: RunState) -> None:
        can = can_transition_run(state1, state2)
        if can:
            assert transition_run(state1, state2) == state2
        else:
            with pytest.raises(IllegalStateTransitionError):
                transition_run(state1, state2)

    @given(st.sampled_from(list(TaskState)), st.sampled_from(list(TaskState)))
    def test_task_transition_consistency(self, state1: TaskState, state2: TaskState) -> None:
        can = can_transition_task(state1, state2)
        if can:
            assert transition_task(state1, state2) == state2
        else:
            with pytest.raises(IllegalStateTransitionError):
                transition_task(state1, state2)
