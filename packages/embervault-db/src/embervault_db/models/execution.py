"""SQLAlchemy models for job runs, tasks, task assignments, task logs, and error events."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from embervault_db.models.proxy import Proxy

from sqlalchemy import (
    JSON,
    BigInteger,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from embervault_db.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, utc_now


class JobRun(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Specific execution instance of a backup job."""

    __tablename__ = "job_runs"
    __table_args__ = (
        CheckConstraint(
            "trigger IN ('schedule', 'manual', 'api')",
            name="ck_job_runs_trigger",
        ),
        CheckConstraint(
            "status IN ('queued', 'planning', 'awaiting_confirmation', 'running', 'succeeded', 'partially_failed', 'failed', 'cancelled')",
            name="ck_job_runs_status",
        ),
        Index(
            "ix_job_runs_one_active_per_job",
            "job_id",
            unique=False,
            postgresql_where=text(
                "status IN ('queued', 'planning', 'awaiting_confirmation', 'running')"
            ),
            sqlite_where=text(
                "status IN ('queued', 'planning', 'awaiting_confirmation', 'running')"
            ),
        ),
    )

    job_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    trigger: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="queued", nullable=False)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    scheduled_for: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    job_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    planned_task_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    warning_code: Mapped[str | None] = mapped_column(String(50), nullable=True)
    ack_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    ack_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(50), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    bytes_transferred: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    files_transferred: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    tasks_succeeded: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tasks_failed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    notification_sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    tasks: Mapped[list[Task]] = relationship(
        "Task", back_populates="run", cascade="all, delete-orphan", lazy="selectin"
    )
    hooks: Mapped[list[JobRunHook]] = relationship(
        "JobRunHook", back_populates="run", cascade="all, delete-orphan", lazy="selectin"
    )
    job: Mapped[Any] = relationship("Job", back_populates="runs", lazy="joined")


class Task(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Discrete unit of work within a job run (discovery or transfer)."""

    __tablename__ = "tasks"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('discover', 'transfer')",
            name="ck_tasks_kind",
        ),
        CheckConstraint(
            "scope IN ('whole', 'root_files', 'subfolder', 'files')",
            name="ck_tasks_scope",
        ),
        CheckConstraint(
            "status IN ('pending', 'ready', 'assigned', 'running', 'retry_wait', 'succeeded', 'failed', 'cancelled', 'skipped')",
            name="ck_tasks_status",
        ),
        Index("ix_tasks_status_next_attempt", "status", "next_attempt_at"),
    )

    run_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("job_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    scope: Mapped[str] = mapped_column(String(20), nullable=False)
    seq: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    spec: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ready_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_code: Mapped[str | None] = mapped_column(String(50), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    run: Mapped[JobRun] = relationship("JobRun", back_populates="tasks")
    assignments: Mapped[list[TaskAssignment]] = relationship(
        "TaskAssignment", back_populates="task", cascade="all, delete-orphan", lazy="selectin"
    )


class TaskAssignment(Base, UUIDPrimaryKeyMixin):
    """Execution attempt of a task dispatched to a specific proxy node."""

    __tablename__ = "task_assignments"
    __table_args__ = (
        CheckConstraint(
            "status IN ('assigned', 'dispatched', 'running', 'succeeded', 'failed', 'cancelled')",
            name="ck_task_assignments_status",
        ),
        CheckConstraint(
            "error_class IS NULL OR error_class IN ('temporary', 'permanent', 'timeout', 'proxy_unreachable', 'lost')",
            name="ck_task_assignments_error_class",
        ),
        UniqueConstraint("task_id", "attempt_no", name="uq_task_assignments_task_attempt"),
    )

    task_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
    )
    attempt_no: Mapped[int] = mapped_column(Integer, nullable=False)
    proxy_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("proxies.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(String(20), default="assigned", nullable=False)
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_class: Mapped[str | None] = mapped_column(String(30), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(50), nullable=True)
    bytes_transferred: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    files_transferred: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    errors_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    checks_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    task: Mapped[Task] = relationship("Task", back_populates="assignments")
    proxy: Mapped[Proxy] = relationship("Proxy", lazy="joined")
    logs: Mapped[list[TaskLog]] = relationship(
        "TaskLog", back_populates="assignment", cascade="all, delete-orphan"
    )


class TaskLog(Base):
    """Captured stdout/stderr/system log entry from an execution attempt."""

    __tablename__ = "task_logs"
    __table_args__ = (
        CheckConstraint(
            "stream IN ('stdout', 'stderr', 'system')",
            name="ck_task_logs_stream",
        ),
        Index("ix_task_logs_assignment_seq", "assignment_id", "seq"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True
    )
    assignment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("task_assignments.id", ondelete="CASCADE"),
        nullable=False,
    )
    task_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tasks.id", ondelete="CASCADE"),
        nullable=False,
    )
    run_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("job_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    seq: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    level: Mapped[str] = mapped_column(String(20), default="info", nullable=False)
    stream: Mapped[str] = mapped_column(String(10), default="stdout", nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)

    assignment: Mapped[TaskAssignment] = relationship("TaskAssignment", back_populates="logs")


class ErrorEvent(Base, UUIDPrimaryKeyMixin):
    """System-wide captured error event for diagnostic tracking and alerts."""

    __tablename__ = "error_events"
    __table_args__ = (
        CheckConstraint(
            "component IN ('app', 'orchestrator', 'proxy')",
            name="ck_error_events_component",
        ),
        Index("ix_error_events_ts", "ts"),
    )

    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    component: Mapped[str] = mapped_column(String(20), nullable=False)
    error_code: Mapped[str] = mapped_column(String(50), nullable=False)
    error_class: Mapped[str] = mapped_column(String(50), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    run_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("job_runs.id", ondelete="SET NULL"),
        nullable=True,
    )
    task_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("tasks.id", ondelete="SET NULL"),
        nullable=True,
    )
    assignment_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("task_assignments.id", ondelete="SET NULL"),
        nullable=True,
    )
    proxy_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("proxies.id", ondelete="SET NULL"),
        nullable=True,
    )


class JobRunHook(Base, UUIDPrimaryKeyMixin):
    """Captured execution of pre-run or post-run bash hook for a JobRun."""

    __tablename__ = "job_run_hooks"
    __table_args__ = (
        CheckConstraint(
            "hook_type IN ('pre_run', 'post_run')",
            name="ck_job_run_hooks_hook_type",
        ),
        CheckConstraint(
            "status IN ('succeeded', 'failed', 'timeout', 'skipped')",
            name="ck_job_run_hooks_status",
        ),
        Index("ix_job_run_hooks_run_id", "run_id"),
    )

    run_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("job_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    hook_type: Mapped[str] = mapped_column(String(20), nullable=False)
    script_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[float] = mapped_column(default=0.0, nullable=False)
    output: Mapped[str] = mapped_column(Text, default="", nullable=False)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    run: Mapped[JobRun] = relationship("JobRun", back_populates="hooks")


class ThroughputSample(Base, UUIDPrimaryKeyMixin):
    """Historical sample of aggregate transfer throughput across proxies/runs."""

    __tablename__ = "throughput_samples"
    __table_args__ = (Index("ix_throughput_samples_recorded_at", "recorded_at"),)

    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    bytes_per_sec: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    active_runs: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
