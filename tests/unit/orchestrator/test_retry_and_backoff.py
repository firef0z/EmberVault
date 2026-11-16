"""Unit and property-based tests for error classification, exponential backoff, and cooldown (§5.4)."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from embervault_common.contracts.enums import ErrorClass, ErrorCode
from embervault_orchestrator.planner.concurrency import (
    can_assign_task,
    resolve_concurrency_limit,
)
from embervault_orchestrator.retry.backoff import (
    calculate_backoff_delay,
    get_base_backoff_delay,
)
from embervault_orchestrator.retry.classifier import (
    classify_rclone_exit_code,
    classify_task_failure,
)
from embervault_orchestrator.retry.cooldown import calculate_proxy_cooldown


class TestRcloneExitCodeTable:
    """Verify exact exit-code classification table specified in §5.4."""

    def test_exit_codes_permanent(self) -> None:
        # 1, 3, 4, 7, 8, 9, 10 must be permanent
        for code in (1, 3, 4, 7, 8, 9, 10):
            err_class, err_code = classify_rclone_exit_code(code)
            assert err_class == ErrorClass.PERMANENT
            if code in (3, 4):
                assert err_code == ErrorCode.SOURCE_NOT_FOUND
            else:
                assert err_code == ErrorCode.RCLONE_FATAL

    def test_exit_codes_temporary(self) -> None:
        # 2, 5, 6, and unknown codes must be temporary
        for code in (2, 5, 6, 99, 137):
            err_class, err_code = classify_rclone_exit_code(code)
            assert err_class == ErrorClass.TEMPORARY
            assert err_code == ErrorCode.RCLONE_TEMPORARY


class TestFailureDecisions:
    """Test decision logic under various failure modes (§5.4)."""

    def test_401_unauthorized_reassigns_without_attempt_consumption(self) -> None:
        dec = classify_task_failure(http_status=401, attempts_used=1, max_attempts=3)
        assert dec.action == "reassign"
        assert dec.error_code == ErrorCode.PROXY_UNAUTHORIZED
        assert dec.consumes_attempt is False

    def test_429_capacity_full_returns_to_ready_without_attempt_consumption(self) -> None:
        dec = classify_task_failure(http_status=429, attempts_used=1, max_attempts=3)
        assert dec.action == "ready_no_attempt"
        assert dec.error_code == ErrorCode.PROXY_CAPACITY_FULL
        assert dec.consumes_attempt is False

    def test_503_capacity_full_returns_to_ready(self) -> None:
        dec = classify_task_failure(http_status=503, attempts_used=2, max_attempts=3)
        assert dec.action == "ready_no_attempt"
        assert dec.consumes_attempt is False

    def test_timeout_retries_when_attempts_remain(self) -> None:
        dec = classify_task_failure(is_timeout=True, attempts_used=1, max_attempts=3)
        assert dec.action == "retry"
        assert dec.error_class == ErrorClass.TIMEOUT
        assert dec.consumes_attempt is True

    def test_timeout_fails_when_attempts_exhausted(self) -> None:
        dec = classify_task_failure(is_timeout=True, attempts_used=3, max_attempts=3)
        assert dec.action == "fail"
        assert dec.error_code == ErrorCode.TASK_TIMEOUT

    def test_lost_triggers_proxy_cooldown(self) -> None:
        dec = classify_task_failure(is_lost=True, attempts_used=1, max_attempts=3)
        assert dec.action == "retry"
        assert dec.error_class == ErrorClass.LOST
        assert dec.should_cooldown_proxy is True

    def test_remote_auth_is_permanent_fail(self) -> None:
        dec = classify_task_failure(is_remote_auth_error=True)
        assert dec.action == "fail"
        assert dec.error_class == ErrorClass.PERMANENT
        assert dec.error_code == ErrorCode.REMOTE_AUTH_FAILED


class TestProxyCooldown:
    """Test proxy cooldown calculations (§5.4)."""

    def test_no_cooldown_under_three_failures(self) -> None:
        assert calculate_proxy_cooldown(0) is None
        assert calculate_proxy_cooldown(1) is None
        assert calculate_proxy_cooldown(2) is None

    def test_cooldown_escalation_and_ceiling(self) -> None:
        # 3 failures -> 60s
        assert calculate_proxy_cooldown(3) == 60
        # 4 failures -> 120s
        assert calculate_proxy_cooldown(4) == 120
        # 5 failures -> 240s
        assert calculate_proxy_cooldown(5) == 480 / 2  # 240
        # 6 failures -> 480s
        assert calculate_proxy_cooldown(6) == 480
        # 7 failures -> 600s (capped at 10 min)
        assert calculate_proxy_cooldown(7) == 600
        # 8 failures -> capped at 600s
        assert calculate_proxy_cooldown(8) == 600


class TestConcurrencyEvaluation:
    """Test concurrency check and precedence rules (§4.3)."""

    def test_concurrency_three_limits_respected(self) -> None:
        # Global: 2/5, Job: 1/2, Proxy: 0/1 -> Can assign
        assert can_assign_task(
            running_global=2,
            limit_global=5,
            running_job=1,
            limit_job=2,
            running_proxy=0,
            limit_proxy=1,
        )

    def test_concurrency_fails_if_any_limit_reached(self) -> None:
        # Proxy full (1/1)
        assert not can_assign_task(
            running_global=2,
            limit_global=5,
            running_job=1,
            limit_job=2,
            running_proxy=1,
            limit_proxy=1,
        )
        # Job full (2/2)
        assert not can_assign_task(
            running_global=2,
            limit_global=5,
            running_job=2,
            limit_job=2,
            running_proxy=0,
            limit_proxy=1,
        )
        # Global full (5/5)
        assert not can_assign_task(
            running_global=5,
            limit_global=5,
            running_job=1,
            limit_job=2,
            running_proxy=0,
            limit_proxy=1,
        )

    def test_precedence_resolution(self) -> None:
        # Job > GUI > Env > Default
        assert (
            resolve_concurrency_limit(
                job_override=4, gui_override=3, env_override=2, default_limit=1
            )
            == 4
        )
        assert (
            resolve_concurrency_limit(
                job_override=None, gui_override=3, env_override=2, default_limit=1
            )
            == 3
        )
        assert (
            resolve_concurrency_limit(
                job_override=None, gui_override=None, env_override=2, default_limit=1
            )
            == 2
        )
        assert (
            resolve_concurrency_limit(
                job_override=None, gui_override=None, env_override=None, default_limit=1
            )
            == 1
        )


class TestBackoffProperties:
    """Hypothesis property-based tests for exponential backoff monotonicity and bounds."""

    @given(st.integers(min_value=1, max_value=30))
    def test_base_backoff_monotonicity(self, attempt: int) -> None:
        """Base backoff delay is strictly monotonic: base(attempt) <= base(attempt + 1)."""
        d1 = get_base_backoff_delay(attempt, base_s=30.0, max_s=900.0)
        d2 = get_base_backoff_delay(attempt + 1, base_s=30.0, max_s=900.0)
        assert d1 <= d2
        assert d1 <= 900.0
        assert d2 <= 900.0

    @given(
        st.integers(min_value=1, max_value=50),
        st.floats(min_value=-1.0, max_value=1.0),
    )
    def test_backoff_bounded_and_non_negative(self, attempt: int, random_factor: float) -> None:
        """Delay with +/-10% jitter never exceeds max_s * 1.1 and is never negative."""
        base_s = 30.0
        max_s = 900.0
        jitter_pct = 0.1

        delay = calculate_backoff_delay(
            attempt=attempt,
            base_s=base_s,
            max_s=max_s,
            jitter_pct=jitter_pct,
            random_factor=random_factor,
        )

        assert delay >= 0.0
        assert delay <= max_s * (1.0 + jitter_pct) + 0.001
