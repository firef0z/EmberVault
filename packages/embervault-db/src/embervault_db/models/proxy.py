"""SQLAlchemy models for execution proxies and proxy monitoring status."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from embervault_db.models.remotes import RcloneRemote

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from embervault_db.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, utc_now


class Proxy(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Registered execution proxy node."""

    __tablename__ = "proxies"
    __table_args__ = (UniqueConstraint("host", "port", name="uq_proxies_host_port"),)

    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=8443, nullable=False)
    token_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    cert_fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    cert_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fingerprint_confirmed_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    fingerprint_confirmed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    max_concurrent_tasks: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    proxy_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    rclone_version: Mapped[str | None] = mapped_column(String(50), nullable=True)

    status: Mapped[ProxyStatus] = relationship(
        "ProxyStatus",
        back_populates="proxy",
        uselist=False,
        cascade="all, delete-orphan",
        lazy="joined",
    )
    state_events: Mapped[list[ProxyStateEvent]] = relationship(
        "ProxyStateEvent",
        back_populates="proxy",
        cascade="all, delete-orphan",
    )
    reachable_remotes: Mapped[list[RcloneRemote]] = relationship(
        "RcloneRemote",
        secondary="proxy_remotes",
        back_populates="proxies",
        lazy="selectin",
    )


class ProxyStatus(Base):
    """Dynamic real-time health and load status of an execution proxy (1:1)."""

    __tablename__ = "proxy_status"
    __table_args__ = (
        CheckConstraint(
            "state IN ('unknown', 'online', 'offline', 'unauthorized', 'untrusted', 'cooldown')",
            name="ck_proxy_status_state",
        ),
    )

    proxy_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("proxies.id", ondelete="CASCADE"),
        primary_key=True,
    )
    state: Mapped[str] = mapped_column(String(20), default="unknown", nullable=False)
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    consecutive_successes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    cooldown_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    running_tasks: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    capacity: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error_code: Mapped[str | None] = mapped_column(String(50), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    proxy: Mapped[Proxy] = relationship("Proxy", back_populates="status")


class ProxyStateEvent(Base, UUIDPrimaryKeyMixin):
    """Historical audit of proxy state transitions."""

    __tablename__ = "proxy_state_events"

    proxy_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("proxies.id", ondelete="CASCADE"),
        nullable=False,
    )
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    from_state: Mapped[str] = mapped_column(String(20), nullable=False)
    to_state: Mapped[str] = mapped_column(String(20), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    proxy: Mapped[Proxy] = relationship("Proxy", back_populates="state_events")


from sqlalchemy import event, select
from sqlalchemy.orm import Session


@event.listens_for(Session, "before_flush")
def _default_proxy_remotes_listener(session: Session, flush_context: Any, instances: Any) -> None:
    from embervault_db.models.remotes import RcloneRemote

    for obj in session.new:
        if isinstance(obj, Proxy):
            if not obj.reachable_remotes and not getattr(
                obj, "_explicitly_set_reachable_remotes", False
            ):
                all_remotes = list(session.scalars(select(RcloneRemote)).all())
                if all_remotes:
                    obj.reachable_remotes = all_remotes
        elif isinstance(obj, RcloneRemote):
            if not obj.proxies and not getattr(obj, "_explicitly_set_reachable_proxies", False):
                all_proxies = list(session.scalars(select(Proxy)).all())
                if all_proxies:
                    obj.proxies = all_proxies
