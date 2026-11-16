"""SQLAlchemy models for RClone remotes, jobs, job sources, and discoveries."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from embervault_db.models.auth import Role
    from embervault_db.models.proxy import Proxy

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from embervault_db.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, utc_now


class RcloneRemote(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Configured RClone remote endpoint (source or destination)."""

    __tablename__ = "rclone_remotes"

    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    backend_type: Mapped[str] = mapped_column(String(50), nullable=False)
    config_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    public_params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    secret_field_names: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    proxies: Mapped[list[Proxy]] = relationship(
        "Proxy",
        secondary="proxy_remotes",
        back_populates="reachable_remotes",
        lazy="selectin",
    )
    roles: Mapped[list[Role]] = relationship(
        "Role",
        secondary="remote_roles",
        lazy="selectin",
    )


class Job(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Configured backup job definition."""

    __tablename__ = "jobs"
    __table_args__ = (
        CheckConstraint(
            "source_kind IN ('folder', 'files')",
            name="ck_jobs_source_kind",
        ),
        CheckConstraint(
            "operation IN ('copy', 'sync')",
            name="ck_jobs_operation",
        ),
        CheckConstraint(
            "parallelization IN ('none', 'by_subfolder')",
            name="ck_jobs_parallelization",
        ),
        CheckConstraint(
            "discovery_status IN ('not_required', 'unverified', 'verified')",
            name="ck_jobs_discovery_status",
        ),
        CheckConstraint(
            "missed_run_policy IS NULL OR missed_run_policy IN ('skip', 'run_once', 'fail')",
            name="ck_jobs_missed_run_policy",
        ),
        CheckConstraint(
            "overlap_policy IS NULL OR overlap_policy IN ('skip', 'allow', 'cancel_previous', 'queue', 'fail')",
            name="ck_jobs_overlap_policy",
        ),
        CheckConstraint(
            "pending_policy IS NULL OR pending_policy IN ('fail', 'retry')",
            name="ck_jobs_pending_policy",
        ),
        CheckConstraint(
            "notification_policy IS NULL OR notification_policy IN ('always', 'only_errors')",
            name="ck_jobs_notification_policy",
        ),
    )

    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notifications_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notification_policy: Mapped[str | None] = mapped_column(String(20), nullable=True, default=None)

    source_remote_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("rclone_remotes.id"),
        nullable=False,
    )
    source_path: Mapped[str] = mapped_column(Text, nullable=False, default="")

    destination_remote_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("rclone_remotes.id"),
        nullable=False,
    )
    destination_path: Mapped[str] = mapped_column(Text, nullable=False, default="")

    source_kind: Mapped[str] = mapped_column(String(20), default="folder", nullable=False)
    operation: Mapped[str] = mapped_column(String(20), default="copy", nullable=False)
    parallelization: Mapped[str] = mapped_column(String(20), default="none", nullable=False)
    discovery_status: Mapped[str] = mapped_column(
        String(20), default="not_required", nullable=False
    )
    last_discovery_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)

    max_parallel_tasks: Mapped[int | None] = mapped_column(Integer, nullable=True)
    files_per_task: Mapped[int | None] = mapped_column(Integer, nullable=True)
    schedule_cron: Mapped[str | None] = mapped_column(String(100), nullable=True)
    timezone: Mapped[str] = mapped_column(String(50), default="UTC", nullable=False)
    follow_dst: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    missed_run_policy: Mapped[str | None] = mapped_column(String(20), default=None, nullable=True)
    overlap_policy: Mapped[str | None] = mapped_column(String(20), default=None, nullable=True)
    pending_policy: Mapped[str | None] = mapped_column(String(20), default=None, nullable=True)
    max_runtime_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)
    missed_run_notify: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false"), nullable=False
    )
    overlap_notify: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false"), nullable=False
    )
    pending_notify: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false"), nullable=False
    )
    max_runtime_notify: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false"), nullable=False
    )
    max_attempts: Mapped[int | None] = mapped_column(Integer, nullable=True)
    task_timeout_s: Mapped[int | None] = mapped_column(Integer, nullable=True)
    parallel_ack_task_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rclone_options: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    pre_run_hook: Mapped[str | None] = mapped_column(Text, nullable=True)
    post_run_hook: Mapped[str | None] = mapped_column(Text, nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    source_remote: Mapped[RcloneRemote] = relationship(
        "RcloneRemote", foreign_keys=[source_remote_id], lazy="joined"
    )
    destination_remote: Mapped[RcloneRemote] = relationship(
        "RcloneRemote", foreign_keys=[destination_remote_id], lazy="joined"
    )
    sources: Mapped[list[JobSource]] = relationship(
        "JobSource", back_populates="job", cascade="all, delete-orphan"
    )
    runs: Mapped[list[Any]] = relationship(
        "JobRun", back_populates="job", cascade="all, delete-orphan"
    )
    assigned_proxies: Mapped[list[Proxy]] = relationship(
        "Proxy",
        secondary="job_proxies",
        lazy="selectin",
    )


class JobProxy(Base):
    """Many-to-many association between jobs and assigned execution proxies."""

    __tablename__ = "job_proxies"

    job_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("jobs.id", ondelete="CASCADE"),
        primary_key=True,
    )
    proxy_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("proxies.id", ondelete="CASCADE"),
        primary_key=True,
    )


class ProxyRemote(Base):
    """Many-to-many association between execution proxies and reachable remotes."""

    __tablename__ = "proxy_remotes"

    proxy_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("proxies.id", ondelete="CASCADE"),
        primary_key=True,
    )
    remote_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("rclone_remotes.id", ondelete="CASCADE"),
        primary_key=True,
    )


class RemoteRole(Base):
    """Many-to-many association between remotes and roles allowed to view/use them."""

    __tablename__ = "remote_roles"

    remote_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("rclone_remotes.id", ondelete="CASCADE"),
        primary_key=True,
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("roles.id", ondelete="CASCADE"),
        primary_key=True,
    )


class JobSource(Base, UUIDPrimaryKeyMixin):
    """Individual paths or files comprising a job's source specification."""

    __tablename__ = "job_sources"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('dir', 'file')",
            name="ck_job_sources_kind",
        ),
    )

    job_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("jobs.id", ondelete="CASCADE"),
        nullable=False,
    )
    kind: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    position: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    job: Mapped[Job] = relationship("Job", back_populates="sources")


class JobDiscovery(Base, UUIDPrimaryKeyMixin):
    """Result of source path inspection for subfolder parallelization estimation."""

    __tablename__ = "job_discoveries"
    __table_args__ = (
        CheckConstraint(
            "trigger IN ('job_form', 'run_start', 'manual')",
            name="ck_job_discoveries_trigger",
        ),
        CheckConstraint(
            "status IN ('pending', 'running', 'succeeded', 'failed')",
            name="ck_job_discoveries_status",
        ),
        CheckConstraint(
            "level IN ('ok', 'warn', 'blocked')",
            name="ck_job_discoveries_level",
        ),
    )

    job_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("jobs.id", ondelete="SET NULL"),
        nullable=True,
    )
    source_remote_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("rclone_remotes.id", ondelete="CASCADE"),
        nullable=False,
    )
    source_remote_version: Mapped[int] = mapped_column(Integer, nullable=False)
    source_path: Mapped[str] = mapped_column(Text, nullable=False)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    trigger: Mapped[str] = mapped_column(String(20), nullable=False)
    proxy_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    folder_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    root_file_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    task_count_estimate: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    level: Mapped[str] = mapped_column(String(10), default="ok", nullable=False)
    entries: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(50), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
