"""SQLAlchemy model for Public Share links."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from embervault_db.models.remotes import RcloneRemote

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from embervault_db.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class PublicShare(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Public share link allowing unauthenticated/external users to browse and download restricted remote paths."""

    __tablename__ = "public_shares"

    token: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    remote_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("rclone_remotes.id", ondelete="CASCADE"),
        nullable=False,
    )
    base_path: Mapped[str] = mapped_column(String(1024), default="", nullable=False)
    username: Mapped[str] = mapped_column(String(100), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    note: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # Internal note, NEVER exposed to public user
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    first_accessed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    remote: Mapped[RcloneRemote] = relationship("RcloneRemote", lazy="joined")
