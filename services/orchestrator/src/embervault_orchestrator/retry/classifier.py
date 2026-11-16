"""Classification of task execution errors, RClone exit codes, and retry decisions (§5.4)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from embervault_common.contracts.enums import ErrorClass, ErrorCode

# Standard RClone Exit Codes Mapping (§5.4)
RCLONE_EXIT_CODE_MAP: dict[int, tuple[ErrorClass, ErrorCode]] = {
    0: (ErrorClass.TEMPORARY, ErrorCode.UNKNOWN_ERROR),  # Success (not an error)
    1: (ErrorClass.PERMANENT, ErrorCode.RCLONE_FATAL),  # Syntax or usage error
    2: (ErrorClass.TEMPORARY, ErrorCode.RCLONE_TEMPORARY),  # Error not otherwise categorised
    3: (ErrorClass.PERMANENT, ErrorCode.SOURCE_NOT_FOUND),  # Directory not found
    4: (ErrorClass.PERMANENT, ErrorCode.SOURCE_NOT_FOUND),  # File not found
    5: (ErrorClass.TEMPORARY, ErrorCode.RCLONE_TEMPORARY),  # Temporary error (e.g. rate limit)
    6: (ErrorClass.TEMPORARY, ErrorCode.RCLONE_TEMPORARY),  # Less serious error
    7: (ErrorClass.PERMANENT, ErrorCode.RCLONE_FATAL),  # Fatal error
    8: (ErrorClass.PERMANENT, ErrorCode.RCLONE_FATAL),  # Transfer limit exceeded
    9: (ErrorClass.PERMANENT, ErrorCode.RCLONE_FATAL),  # Server-side copy not supported
    10: (ErrorClass.PERMANENT, ErrorCode.RCLONE_FATAL),  # Max transfer limit reached
}


@dataclass(frozen=True)
class FailureDecision:
    """Actionable decision derived from a task attempt failure (§5.4)."""

    action: Literal["retry", "reassign", "ready_no_attempt", "fail"]
    error_class: ErrorClass
    error_code: ErrorCode
    consumes_attempt: bool
    should_cooldown_proxy: bool
    description: str


def classify_rclone_exit_code(exit_code: int) -> tuple[ErrorClass, ErrorCode]:
    """Classify an RClone process exit code according to the §5.4 specification table."""
    return RCLONE_EXIT_CODE_MAP.get(exit_code, (ErrorClass.TEMPORARY, ErrorCode.RCLONE_TEMPORARY))


def classify_task_failure(
    http_status: int | None = None,
    rclone_exit_code: int | None = None,
    is_timeout: bool = False,
    is_lost: bool = False,
    is_remote_auth_error: bool = False,
    attempts_used: int = 1,
    max_attempts: int = 3,
) -> FailureDecision:
    """Evaluate a task failure and determine the appropriate recovery or failure action (§5.4).

    Rules:
    - 401 Unauthorized -> proxy unauthorized, reassign to another proxy without consuming attempt.
    - 429/503 Capacity full -> proxy full, return to ready queue without consuming attempt.
    - is_timeout -> TIMEOUT error, retry with backoff on another proxy (consumes attempt).
    - is_lost (> LOST_AFTER_S) -> LOST error, treated as temporary retry (consumes attempt).
    - is_remote_auth_error -> PERMANENT failure (REMOTE_AUTH_FAILED), no retry.
    - rclone_exit_code -> evaluated against §5.4 table. Permanent -> fail. Temporary -> retry.
    - If temporary action would be 'retry' but attempts_used >= max_attempts -> 'fail'.
    """
    # 1. Proxy Auth Mismatch (401)
    if http_status == 401:
        return FailureDecision(
            action="reassign",
            error_class=ErrorClass.TEMPORARY,
            error_code=ErrorCode.PROXY_UNAUTHORIZED,
            consumes_attempt=False,
            should_cooldown_proxy=False,
            description="Proxy returned 401 Unauthorized. Reassigning task without consuming attempts.",
        )

    # 2. Proxy Capacity Full (429 / 503)
    if http_status in (429, 503):
        return FailureDecision(
            action="ready_no_attempt",
            error_class=ErrorClass.TEMPORARY,
            error_code=ErrorCode.PROXY_CAPACITY_FULL,
            consumes_attempt=False,
            should_cooldown_proxy=False,
            description="Proxy capacity full (429/503). Re-queuing to ready queue without consuming attempts.",
        )

    # 3. Remote Authentication Failed
    if is_remote_auth_error:
        return FailureDecision(
            action="fail",
            error_class=ErrorClass.PERMANENT,
            error_code=ErrorCode.REMOTE_AUTH_FAILED,
            consumes_attempt=True,
            should_cooldown_proxy=False,
            description="Remote storage authentication failed. Permanent failure.",
        )

    # 4. Task Execution Timeout
    if is_timeout:
        if attempts_used >= max_attempts:
            return FailureDecision(
                action="fail",
                error_class=ErrorClass.TIMEOUT,
                error_code=ErrorCode.TASK_TIMEOUT,
                consumes_attempt=True,
                should_cooldown_proxy=False,
                description=f"Task timed out and exhausted all {max_attempts} attempts.",
            )
        return FailureDecision(
            action="retry",
            error_class=ErrorClass.TIMEOUT,
            error_code=ErrorCode.TASK_TIMEOUT,
            consumes_attempt=True,
            should_cooldown_proxy=False,
            description=f"Task timed out (attempt {attempts_used}/{max_attempts}). Scheduling retry.",
        )

    # 5. Proxy Lost (unreachable > LOST_AFTER_S)
    if is_lost:
        if attempts_used >= max_attempts:
            return FailureDecision(
                action="fail",
                error_class=ErrorClass.LOST,
                error_code=ErrorCode.TASK_LOST,
                consumes_attempt=True,
                should_cooldown_proxy=True,
                description=f"Proxy lost contact and task exhausted all {max_attempts} attempts.",
            )
        return FailureDecision(
            action="retry",
            error_class=ErrorClass.LOST,
            error_code=ErrorCode.TASK_LOST,
            consumes_attempt=True,
            should_cooldown_proxy=True,
            description=f"Proxy lost contact (attempt {attempts_used}/{max_attempts}). Scheduling retry on another proxy.",
        )

    # 6. HTTP 5xx / Network connection failure on dispatch
    if http_status is not None and http_status >= 500:
        if attempts_used >= max_attempts:
            return FailureDecision(
                action="fail",
                error_class=ErrorClass.TEMPORARY,
                error_code=ErrorCode.PROXY_UNREACHABLE,
                consumes_attempt=True,
                should_cooldown_proxy=True,
                description=f"Dispatch failed with HTTP {http_status} and exhausted all {max_attempts} attempts.",
            )
        return FailureDecision(
            action="retry",
            error_class=ErrorClass.TEMPORARY,
            error_code=ErrorCode.PROXY_UNREACHABLE,
            consumes_attempt=True,
            should_cooldown_proxy=True,
            description=f"Dispatch failed with HTTP {http_status} (attempt {attempts_used}/{max_attempts}). Scheduling retry with backoff.",
        )

    # 7. Evaluate RClone Exit Code
    if rclone_exit_code is not None:
        err_class, err_code = classify_rclone_exit_code(rclone_exit_code)

        if err_class == ErrorClass.PERMANENT:
            return FailureDecision(
                action="fail",
                error_class=err_class,
                error_code=err_code,
                consumes_attempt=True,
                should_cooldown_proxy=False,
                description=f"RClone failed with permanent error (exit code {rclone_exit_code}: {err_code}).",
            )

        # Temporary error
        if attempts_used >= max_attempts:
            return FailureDecision(
                action="fail",
                error_class=err_class,
                error_code=err_code,
                consumes_attempt=True,
                should_cooldown_proxy=False,
                description=f"RClone temporary error (exit {rclone_exit_code}) exhausted all {max_attempts} attempts.",
            )

        return FailureDecision(
            action="retry",
            error_class=err_class,
            error_code=err_code,
            consumes_attempt=True,
            should_cooldown_proxy=False,
            description=f"RClone temporary error (exit {rclone_exit_code}, attempt {attempts_used}/{max_attempts}). Scheduling retry.",
        )

    # Default unknown failure
    if attempts_used >= max_attempts:
        return FailureDecision(
            action="fail",
            error_class=ErrorClass.TEMPORARY,
            error_code=ErrorCode.UNKNOWN_ERROR,
            consumes_attempt=True,
            should_cooldown_proxy=False,
            description=f"Unclassified failure exhausted all {max_attempts} attempts.",
        )

    return FailureDecision(
        action="retry",
        error_class=ErrorClass.TEMPORARY,
        error_code=ErrorCode.UNKNOWN_ERROR,
        consumes_attempt=True,
        should_cooldown_proxy=False,
        description=f"Unclassified failure (attempt {attempts_used}/{max_attempts}). Scheduling retry.",
    )
