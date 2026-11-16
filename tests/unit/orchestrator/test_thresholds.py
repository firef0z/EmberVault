"""Unit and property-based tests for parallel thresholds and run preconditions (§4.2)."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from embervault_common.contracts.enums import (
    DiscoveryStatusLevel,
    ErrorCode,
    RunState,
    TaskOperation,
)
from embervault_orchestrator.planner.spec import (
    DiscoveryResult,
    JobPlanningSpec,
    plan_job_tasks,
)
from embervault_orchestrator.planner.thresholds import (
    calculate_task_count_estimate,
    evaluate_run_preconditions,
    evaluate_threshold_level,
)


class TestThresholdEvaluation:
    """Test task count thresholds and level classifications (§4.2)."""

    def test_evaluate_threshold_level_boundaries(self) -> None:
        # Default warn=50, hard=500 with default enabled_proxy_count=1
        assert evaluate_threshold_level(1) == DiscoveryStatusLevel.OK
        assert evaluate_threshold_level(50) == DiscoveryStatusLevel.OK
        assert evaluate_threshold_level(51) == DiscoveryStatusLevel.WARN
        assert evaluate_threshold_level(500) == DiscoveryStatusLevel.WARN
        assert evaluate_threshold_level(501) == DiscoveryStatusLevel.BLOCKED

    def test_evaluate_threshold_level_with_multiple_proxies(self) -> None:
        # With 4 proxies, warn threshold is 50 * 4 = 200 tasks
        assert (
            evaluate_threshold_level(100, warn_threshold=50, enabled_proxy_count=4)
            == DiscoveryStatusLevel.OK
        )
        assert (
            evaluate_threshold_level(200, warn_threshold=50, enabled_proxy_count=4)
            == DiscoveryStatusLevel.OK
        )
        assert (
            evaluate_threshold_level(201, warn_threshold=50, enabled_proxy_count=4)
            == DiscoveryStatusLevel.WARN
        )
        # Absolute hard limit still applies
        assert (
            evaluate_threshold_level(501, warn_threshold=50, enabled_proxy_count=100)
            == DiscoveryStatusLevel.BLOCKED
        )

    def test_preconditions_within_safe_limit(self) -> None:
        res = evaluate_run_preconditions(task_count=20, warn_threshold=50, hard_limit=500)
        assert res.can_start is True
        assert res.initial_state == RunState.RUNNING
        assert res.status_level == DiscoveryStatusLevel.OK
        assert res.warning_code is None
        assert res.error_code is None

    def test_preconditions_warn_range_scheduled(self) -> None:
        """Scheduled run in warn range proceeds with high task count warning."""
        res = evaluate_run_preconditions(
            task_count=100, warn_threshold=50, hard_limit=500, is_manual=False
        )
        assert res.can_start is True
        assert res.initial_state == RunState.RUNNING
        assert res.status_level == DiscoveryStatusLevel.WARN
        assert res.warning_code == "PARALLEL_TASK_COUNT_HIGH"

    def test_preconditions_warn_range_manual(self) -> None:
        """Manual run in warn range holds in awaiting_confirmation until confirmed."""
        res = evaluate_run_preconditions(
            task_count=100, warn_threshold=50, hard_limit=500, is_manual=True
        )
        assert res.can_start is False
        assert res.initial_state == RunState.AWAITING_CONFIRMATION
        assert res.status_level == DiscoveryStatusLevel.WARN
        assert res.warning_code == "PARALLEL_TASK_COUNT_HIGH"

    def test_preconditions_blocked_without_ack_fails(self) -> None:
        """Run exceeding hard limit without explicit acknowledgment fails immediately."""
        res = evaluate_run_preconditions(
            task_count=600,
            warn_threshold=50,
            hard_limit=500,
            is_manual=False,
            ack_task_count=None,
        )
        assert res.can_start is False
        assert res.initial_state == RunState.FAILED
        assert res.status_level == DiscoveryStatusLevel.BLOCKED
        assert res.error_code == ErrorCode.PARALLEL_TASK_LIMIT_EXCEEDED

    def test_preconditions_blocked_with_valid_ack_scheduled(self) -> None:
        """Scheduled run exceeding hard limit with valid pre-ack proceeds."""
        res = evaluate_run_preconditions(
            task_count=600,
            warn_threshold=50,
            hard_limit=500,
            is_manual=False,
            ack_task_count=600,
        )
        assert res.can_start is True
        assert res.initial_state == RunState.RUNNING
        assert res.status_level == DiscoveryStatusLevel.BLOCKED
        assert res.error_code is None


class TestThresholdIdentityAndProperties:
    """Hypothesis property-based tests verifying identity between estimate and actual plan."""

    @given(
        st.lists(
            st.text(
                alphabet=st.characters(categories=["L", "N"]),
                min_size=1,
                max_size=15,
            ),
            min_size=0,
            max_size=100,
            unique=True,
        )
    )
    def test_task_count_estimate_matches_actual_planned_tasks(
        self, subfolder_names: list[str]
    ) -> None:
        """The formula in form creation (calculate_task_count_estimate) and run start (plan_job_tasks)

        MUST yield the exact same task count for any discovery output.
        """
        # Form creation calculation
        estimate = calculate_task_count_estimate(len(subfolder_names))

        # Run start calculation
        discovery = DiscoveryResult(subfolders=subfolder_names, root_files=["r.txt"])
        job = JobPlanningSpec(
            source_type="folder",
            parallel_mode="by_subfolder",
            operation=TaskOperation.COPY,
        )
        tasks = plan_job_tasks(job, discovery)

        assert estimate == len(tasks)
        assert estimate == 1 + len(subfolder_names)

    @given(st.integers(min_value=1, max_value=2000))
    def test_threshold_monotonicity(self, n: int) -> None:
        """For any N1 <= N2, status level of N1 is <= status level of N2."""
        level = evaluate_threshold_level(n, warn_threshold=50, hard_limit=500)
        level_plus_1 = evaluate_threshold_level(n + 1, warn_threshold=50, hard_limit=500)

        rank = {
            DiscoveryStatusLevel.OK: 0,
            DiscoveryStatusLevel.WARN: 1,
            DiscoveryStatusLevel.BLOCKED: 2,
        }
        assert rank[level] <= rank[level_plus_1]
