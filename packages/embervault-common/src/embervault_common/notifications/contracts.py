"""Contracts and enumerations for EmberVault notification system."""

from __future__ import annotations

from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class ChannelType(StrEnum):
    """Supported notification channel types."""

    EMAIL = "email"
    TELEGRAM = "telegram"
    CUSTOM = "custom"


class TelegramFormat(StrEnum):
    """Telegram message formatting syntax modes."""

    TEXT = "text"  # Simple plain text, no tags or special markup
    HTML = "html"  # Telegram HTML tags (<b>, <i>, <code>, <pre>)
    MARKDOWN = "markdown"  # Telegram Markdown (*bold*, _italic_, `code`, ```pre```)


class NotificationEventType(StrEnum):
    """Notification event types emitted by EmberVault."""

    JOB_RUN_COMPLETED = "job_run_completed"
    JOB_POLICY_EXECUTED = "job_policy_executed"
    PROXY_OFFLINE = "proxy_offline"
    PROXY_CERT_EXPIRING = "proxy_cert_expiring"
    PROXY_UNTRUSTED = "proxy_untrusted"
    HOOK_FAILED = "hook_failed"
    RCLONE_UPDATE_AVAILABLE = "rclone_update_available"
    TEST = "test"


class NotificationChannelCreate(BaseModel):
    """Request payload to create a notification channel."""

    name: str = Field(..., min_length=1, max_length=100)
    channel_type: ChannelType = ChannelType.CUSTOM
    url: str = Field(..., min_length=1)
    telegram_format: TelegramFormat = TelegramFormat.HTML
    rate_limit_interval_s: int = Field(default=0, ge=0, le=86400)
    enabled: bool = True
    config_metadata: dict[str, Any] = Field(default_factory=dict)


class NotificationChannelUpdate(BaseModel):
    """Request payload to update an existing notification channel."""

    name: str | None = Field(default=None, min_length=1, max_length=100)
    channel_type: ChannelType | None = None
    url: str | None = None
    telegram_format: TelegramFormat | None = None
    rate_limit_interval_s: int | None = Field(default=None, ge=0, le=86400)
    enabled: bool | None = None
    config_metadata: dict[str, Any] | None = None


class NotificationChannelResponse(BaseModel):
    """Serialized notification channel response with secrets masked."""

    id: UUID
    name: str
    channel_type: ChannelType
    masked_url: str
    telegram_format: TelegramFormat
    rate_limit_interval_s: int
    enabled: bool
    config_metadata: dict[str, Any]
    created_at: str
    updated_at: str


class NotificationTestRequest(BaseModel):
    """Request payload to test a channel or arbitrary URL."""

    channel_type: ChannelType = ChannelType.CUSTOM
    url: str
    telegram_format: TelegramFormat = TelegramFormat.HTML
