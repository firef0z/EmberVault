"""Notification package for EmberVault."""

from embervault_common.notifications.apprise_notifier import (
    AppriseNotifier,
    build_email_url,
    build_telegram_url,
    mask_apprise_url,
    validate_apprise_url,
)
from embervault_common.notifications.contracts import (
    ChannelType,
    NotificationChannelCreate,
    NotificationChannelResponse,
    NotificationChannelUpdate,
    NotificationEventType,
    NotificationTestRequest,
    TelegramFormat,
)
from embervault_common.notifications.formatter import (
    NotificationFormatter,
    escape_telegram_html,
    escape_telegram_markdown,
    format_bytes,
    format_duration,
    split_notification_body,
)

__all__ = [
    "AppriseNotifier",
    "ChannelType",
    "NotificationChannelCreate",
    "NotificationChannelResponse",
    "NotificationChannelUpdate",
    "NotificationEventType",
    "NotificationFormatter",
    "NotificationTestRequest",
    "TelegramFormat",
    "build_email_url",
    "build_telegram_url",
    "escape_telegram_html",
    "escape_telegram_markdown",
    "format_bytes",
    "format_duration",
    "mask_apprise_url",
    "split_notification_body",
    "validate_apprise_url",
]
