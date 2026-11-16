"""Pydantic contracts and schemas for Orchestrator <-> Proxy protocol (v1)."""

from __future__ import annotations

import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from embervault_common.contracts.enums import (
    DiscoveryStatusLevel,
    ErrorClass,
    ErrorCode,
    TaskKind,
    TaskOperation,
    TaskState,
)

EMBERVAULT_PROTOCOL_VERSION: int = 1
PROTOCOL_HEADER: str = "X-EmberVault-Protocol"
REQUEST_ID_HEADER: str = "X-Request-ID"


class BaseContract(BaseModel):
    """Base model for all protocol contracts."""

    model_config = ConfigDict(
        populate_by_name=True,
        validate_assignment=True,
        extra="forbid",
    )


class ProxyHealthResponse(BaseContract):
    """Payload returned by GET /v1/health."""

    status: str = Field(default="ok", description="Proxy health status ('ok')")
    proxy_version: str = Field(..., description="Semantic version of embervault-proxy")
    rclone_version: str = Field(..., description="Pinned rclone binary version string")
    uptime_s: float = Field(..., ge=0, description="Uptime of proxy process in seconds")
    capacity: int = Field(..., ge=1, description="Declared max concurrent task capacity")
    running_tasks: int = Field(..., ge=0, description="Currently executing tasks count")
    server_time: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC),
        description="Current server time (UTC)",
    )
    cert_expires_at: datetime.datetime | None = Field(
        default=None,
        description="Expiration timestamp (UTC) of proxy TLS certificate",
    )


class RemoteConfigPayload(BaseContract):
    """Sanitized remote connection parameters passed to the proxy."""

    alias: str = Field(..., description="Internal alias for the remote (e.g. 'src', 'dst')")
    backend_type: str = Field(
        ..., description="RClone backend provider type (e.g. 's3', 'drive', 'local')"
    )
    config: dict[str, Any] = Field(
        default_factory=dict,
        description="Configuration dictionary for the remote provider",
    )
    path: str = Field(..., description="Target path or folder inside the remote")


class TaskDispatchPayload(BaseContract):
    """Payload accepted by POST /v1/tasks to launch a job task."""

    attempt_id: UUID = Field(..., description="Unique attempt UUID for idempotency")
    task_id: UUID = Field(..., description="Parent task UUID")
    run_id: UUID = Field(..., description="Parent run UUID")
    kind: TaskKind = Field(default=TaskKind.TRANSFER, description="Task kind: transfer or discover")
    operation: TaskOperation = Field(
        default=TaskOperation.COPY, description="RClone operation: copy or sync"
    )
    timeout_s: int = Field(default=3600, ge=10, le=86400, description="Hard timeout in seconds")
    source: RemoteConfigPayload = Field(..., description="Source remote configuration")
    destination: RemoteConfigPayload | None = Field(
        default=None,
        description="Destination remote configuration (omitted for discover tasks)",
    )
    files_from: list[str] = Field(
        default_factory=list,
        description="Optional list of relative file paths for --files-from",
    )
    options: dict[str, Any] = Field(
        default_factory=dict,
        description="Whitelisted rclone transfer options and flags",
    )
    secret_fields: list[str] = Field(
        default_factory=list,
        description="List of secret config keys requiring obscuring and masking",
    )
    referenced_remotes: list[RemoteConfigPayload] = Field(
        default_factory=list,
        description="Optional configurations of upstream/referenced remotes for wrapper backends",
    )


class TaskDispatchResponse(BaseContract):
    """Response returned by POST /v1/tasks."""

    attempt_id: UUID = Field(..., description="Attempt UUID")
    status: str = Field(
        ...,
        description="'accepted' for new task (HTTP 202) or 'already_known' (HTTP 200)",
    )
    message: str = Field(default="", description="Optional human-readable informational message")


class TaskProgress(BaseContract):
    """Real-time progress metrics for a running transfer task."""

    bytes_transferred: int = Field(default=0, ge=0)
    bytes_total: int | None = Field(default=None, ge=0)
    files_transferred: int = Field(default=0, ge=0)
    files_total: int | None = Field(default=None, ge=0)
    files_percentage: float | None = Field(default=None, ge=0, le=100)
    checks_completed: int = Field(default=0, ge=0)
    checks_total: int | None = Field(default=None, ge=0)
    checks_percentage: float | None = Field(default=None, ge=0, le=100)
    speed_bytes_per_sec: float = Field(default=0.0, ge=0)
    speed_str: str | None = Field(default=None)
    eta_seconds: int | None = Field(default=None, ge=0)
    eta_str: str | None = Field(default=None)
    percentage: float = Field(default=0.0, ge=0, le=100)


class DiscoverTaskResultPayload(BaseContract):
    """Result payload produced by a discover task."""

    subfolders: list[str] = Field(
        default_factory=list,
        description="First-level subfolder names discovered in source path",
    )
    root_files: list[str] = Field(
        default_factory=list,
        description="Root files discovered directly inside source path",
    )
    total_subfolders: int = Field(
        default=0, ge=0, description="Total number of first-level subfolders"
    )
    total_root_files: int = Field(default=0, ge=0, description="Total number of root files")
    truncated: bool = Field(
        default=False,
        description="Whether the result was truncated due to exceeding discovery cap",
    )
    task_count_estimate: int = Field(
        default=0,
        ge=0,
        description="Estimated parallel tasks: 1 (root files if present) + total_subfolders",
    )
    status_level: DiscoveryStatusLevel = Field(
        default=DiscoveryStatusLevel.OK,
        description="Threshold classification: ok, warn, or blocked",
    )


class TaskStatusResponse(BaseContract):
    """Response returned by GET /v1/tasks/{attempt_id}."""

    attempt_id: UUID = Field(..., description="Attempt UUID")
    status: TaskState = Field(..., description="Current execution state")
    progress: TaskProgress = Field(default_factory=TaskProgress)
    exit_code: int | None = Field(default=None, description="Subprocess exit code upon completion")
    error_code: ErrorCode | None = Field(default=None, description="Standard error code if failed")
    error_class: ErrorClass | None = Field(default=None, description="Error classification")
    error_message: str | None = Field(default=None, description="Sanitized error description")
    started_at: datetime.datetime | None = Field(
        default=None, description="Task start timestamp (UTC)"
    )
    completed_at: datetime.datetime | None = Field(
        default=None, description="Task completion timestamp (UTC)"
    )
    result: DiscoverTaskResultPayload | None = Field(
        default=None,
        description="Discover results if kind was discover",
    )


class TaskLogLine(BaseContract):
    """A single masked log line from a task attempt."""

    seq: int = Field(..., ge=0, description="Monotonic sequence number")
    ts: datetime.datetime = Field(..., description="Timestamp of log event (UTC)")
    level: str = Field(default="INFO", description="Log level: INFO, WARN, ERROR, DEBUG")
    message: str = Field(..., description="Masked log message")


class TaskLogsResponse(BaseContract):
    """Response returned by GET /v1/tasks/{attempt_id}/logs."""

    attempt_id: UUID = Field(..., description="Attempt UUID")
    lines: list[TaskLogLine] = Field(default_factory=list, description="Array of log lines")
    next_seq: int = Field(default=0, ge=0, description="Sequence offset for next poll query")
    has_more: bool = Field(default=False, description="Whether additional log lines are pending")


class TaskCancelResponse(BaseContract):
    """Response returned by POST /v1/tasks/{attempt_id}/cancel."""

    attempt_id: UUID = Field(..., description="Attempt UUID")
    status: str = Field(default="cancelled", description="Status code ('cancelled')")
    message: str = Field(default="", description="Information message")


class TaskListResponse(BaseContract):
    """Response returned by GET /v1/tasks."""

    tasks: list[TaskStatusResponse] = Field(
        default_factory=list,
        description="List of active or unacknowledged tasks",
    )
