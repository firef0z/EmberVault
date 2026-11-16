"""Notification channel model for EmberVault."""

from __future__ import annotations

from typing import Any

from sqlalchemy import Boolean, CheckConstraint, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from embervault_db.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class NotificationChannel(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Notification channel configuration (Apprise endpoints: Email, Telegram, Custom)."""

    __tablename__ = "notification_channels"
    __table_args__ = (
        CheckConstraint(
            "channel_type IN ('email', 'telegram', 'custom')",
            name="ck_notification_channels_channel_type",
        ),
        CheckConstraint(
            "telegram_format IN ('text', 'html', 'markdown')",
            name="ck_notification_channels_telegram_format",
        ),
    )

    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    channel_type: Mapped[str] = mapped_column(String(20), default="custom", nullable=False)

    # Encrypted Apprise URL (AES-256-GCM envelope, tied to channel ID AAD)
    url_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    # Specific formatting for telegram: 'text' (simple), 'html', 'markdown'
    telegram_format: Mapped[str] = mapped_column(String(20), default="html", nullable=False)

    # Rate-limit interval in seconds (0 = disabled, e.g. 60 = at most 1 notification per 60s)
    rate_limit_interval_s: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Additional metadata / friendly config (non-secret, e.g. smtp host, chat_id, recipients)
    config_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
