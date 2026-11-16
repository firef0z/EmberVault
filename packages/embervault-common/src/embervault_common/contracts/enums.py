"""Standard protocol enums and error codes for EmberVault."""

from __future__ import annotations

from enum import StrEnum


class ProxyState(StrEnum):
    """Lifecycle states of an execution proxy."""

    UNKNOWN = "unknown"
    ONLINE = "online"
    OFFLINE = "offline"
    UNAUTHORIZED = "unauthorized"
    UNTRUSTED = "untrusted"
    COOLDOWN = "cooldown"


class TaskKind(StrEnum):
    """Execution kind of a task."""

    TRANSFER = "transfer"
    DISCOVER = "discover"


class TaskOperation(StrEnum):
    """RClone operation type for transfer tasks."""

    COPY = "copy"
    SYNC = "sync"


class TaskScope(StrEnum):
    """Scope of execution for a transfer task."""

    WHOLE = "whole"
    FILES = "files"
    ROOT_FILES = "root_files"
    SUBFOLDER = "subfolder"


class RunState(StrEnum):
    """Lifecycle state of a job run instance."""

    QUEUED = "queued"
    PLANNING = "planning"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIALLY_FAILED = "partially_failed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskState(StrEnum):
    """Execution state of a task attempt."""

    PENDING = "pending"
    READY = "ready"
    ASSIGNED = "assigned"
    RUNNING = "running"
    RETRY_WAIT = "retry_wait"
    SUCCEEDED = "succeeded"
    PARTIALLY_FAILED = "partially_failed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


class ErrorClass(StrEnum):
    """Classification of errors determining retry vs permanent failure."""

    TEMPORARY = "temporary"
    PERMANENT = "permanent"
    TIMEOUT = "timeout"
    LOST = "lost"


class DiscoveryStatus(StrEnum):
    """Status of folder discovery."""

    UNVERIFIED = "unverified"
    IN_PROGRESS = "in_progress"
    VERIFIED = "verified"
    FAILED = "failed"


class DiscoveryStatusLevel(StrEnum):
    """Warning level evaluated against parallel task thresholds."""

    OK = "ok"
    WARN = "warn"
    BLOCKED = "blocked"


class ErrorCode(StrEnum):
    """Standardized machine-readable error codes."""

    NO_ONLINE_PROXY = "NO_ONLINE_PROXY"
    PROXY_UNREACHABLE = "PROXY_UNREACHABLE"
    PROXY_UNAUTHORIZED = "PROXY_UNAUTHORIZED"
    PROXY_CERT_MISMATCH = "PROXY_CERT_MISMATCH"
    PROXY_CAPACITY_FULL = "PROXY_CAPACITY_FULL"
    TASK_TIMEOUT = "TASK_TIMEOUT"
    TASK_LOST = "TASK_LOST"
    RCLONE_TEMPORARY = "RCLONE_TEMPORARY"
    RCLONE_FATAL = "RCLONE_FATAL"
    SOURCE_NOT_FOUND = "SOURCE_NOT_FOUND"
    REMOTE_AUTH_FAILED = "REMOTE_AUTH_FAILED"
    DISCOVERY_FAILED = "DISCOVERY_FAILED"
    PARALLEL_TASK_LIMIT_EXCEEDED = "PARALLEL_TASK_LIMIT_EXCEEDED"
    CREDENTIAL_DECRYPT_FAILED = "CREDENTIAL_DECRYPT_FAILED"
    FILES_EXCLUDED = "FILES_EXCLUDED"
    PROXY_VERSION_INCOMPATIBLE = "PROXY_VERSION_INCOMPATIBLE"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"
