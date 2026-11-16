"""Data access repository for NotificationChannel entities with envelope AES-GCM encryption."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from embervault_common.notifications.apprise_notifier import mask_apprise_url, validate_apprise_url
from embervault_common.security.crypto import decrypt_blob_to_str, encrypt_blob
from embervault_db.models.notifications import NotificationChannel


class NotificationRepository:
    """Repository handling CRUD, envelope encryption, and query helpers for notification channels."""

    @staticmethod
    def encrypt_url(url: str, channel_id: uuid.UUID) -> bytes:
        """Encrypt an Apprise URL using AES-256-GCM envelope encryption bound to channel_id AAD."""
        aad = f"notification_channel:{channel_id}".encode()
        return encrypt_blob(url.strip(), aad=aad)

    @staticmethod
    def decrypt_url(url_encrypted: bytes, channel_id: uuid.UUID) -> str:
        """Decrypt an encrypted Apprise URL using channel_id AAD."""
        aad = f"notification_channel:{channel_id}".encode()
        return decrypt_blob_to_str(url_encrypted, aad=aad)

    @classmethod
    def create_channel(
        cls,
        session: Session,
        name: str,
        url: str,
        channel_type: str = "custom",
        telegram_format: str = "html",
        rate_limit_interval_s: int = 0,
        enabled: bool = True,
        config_metadata: dict[str, Any] | None = None,
    ) -> NotificationChannel:
        """Create and persist a new notification channel with encrypted Apprise URL."""
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Il nome del canale non può essere vuoto.")

        existing = cls.get_channel_by_name(session, clean_name)
        if existing is not None:
            raise ValueError(f"Un canale di notifica con il nome '{clean_name}' esiste già.")

        valid, err = validate_apprise_url(url)
        if not valid:
            raise ValueError(f"URL Apprise non valido: {err}")

        clean_type = channel_type.strip().lower()
        if clean_type not in ("email", "telegram", "custom"):
            clean_type = "custom"

        clean_tg_fmt = telegram_format.strip().lower()
        if clean_tg_fmt not in ("text", "html", "markdown"):
            clean_tg_fmt = "html"

        channel_id = uuid.uuid4()
        url_enc = cls.encrypt_url(url, channel_id)

        channel = NotificationChannel(
            id=channel_id,
            name=clean_name,
            enabled=enabled,
            channel_type=clean_type,
            url_encrypted=url_enc,
            telegram_format=clean_tg_fmt,
            rate_limit_interval_s=max(0, int(rate_limit_interval_s)),
            config_metadata=config_metadata or {},
        )
        session.add(channel)
        session.flush()
        return channel

    @classmethod
    def update_channel(
        cls,
        session: Session,
        channel_id: uuid.UUID,
        name: str | None = None,
        url: str | None = None,
        channel_type: str | None = None,
        telegram_format: str | None = None,
        rate_limit_interval_s: int | None = None,
        enabled: bool | None = None,
        config_metadata: dict[str, Any] | None = None,
    ) -> NotificationChannel:
        """Update an existing notification channel."""
        channel = session.get(NotificationChannel, channel_id)
        if channel is None:
            raise ValueError(f"Canale di notifica con ID '{channel_id}' non trovato.")

        if name is not None:
            clean_name = name.strip()
            if not clean_name:
                raise ValueError("Il nome del canale non può essere vuoto.")
            existing = cls.get_channel_by_name(session, clean_name)
            if existing is not None and existing.id != channel_id:
                raise ValueError(f"Un canale con il nome '{clean_name}' esiste già.")
            channel.name = clean_name

        if url is not None and url.strip():
            valid, err = validate_apprise_url(url)
            if not valid:
                raise ValueError(f"URL Apprise non valido: {err}")
            channel.url_encrypted = cls.encrypt_url(url, channel_id)

        if channel_type is not None:
            clean_type = channel_type.strip().lower()
            if clean_type in ("email", "telegram", "custom"):
                channel.channel_type = clean_type

        if telegram_format is not None:
            clean_tg_fmt = telegram_format.strip().lower()
            if clean_tg_fmt in ("text", "html", "markdown"):
                channel.telegram_format = clean_tg_fmt

        if rate_limit_interval_s is not None:
            channel.rate_limit_interval_s = max(0, int(rate_limit_interval_s))

        if enabled is not None:
            channel.enabled = bool(enabled)

        if config_metadata is not None:
            channel.config_metadata = config_metadata

        session.flush()
        return channel

    @classmethod
    def delete_channel(cls, session: Session, channel_id: uuid.UUID) -> bool:
        """Delete a notification channel by ID."""
        channel = session.get(NotificationChannel, channel_id)
        if channel is None:
            return False
        session.delete(channel)
        session.flush()
        return True

    @classmethod
    def get_channel_by_id(
        cls, session: Session, channel_id: uuid.UUID
    ) -> NotificationChannel | None:
        """Retrieve a notification channel by UUID."""
        return session.get(NotificationChannel, channel_id)

    @classmethod
    def get_channel_by_name(cls, session: Session, name: str) -> NotificationChannel | None:
        """Retrieve a notification channel by its unique name."""
        return session.scalar(
            select(NotificationChannel).where(NotificationChannel.name == name.strip())
        )

    @classmethod
    def list_channels(
        cls, session: Session, only_enabled: bool = False
    ) -> list[NotificationChannel]:
        """List all notification channels ordered by name."""
        stmt = select(NotificationChannel)
        if only_enabled:
            stmt = stmt.where(NotificationChannel.enabled.is_(True))
        stmt = stmt.order_by(NotificationChannel.name)
        return list(session.scalars(stmt).all())

    @classmethod
    def get_decrypted_url(cls, channel: NotificationChannel) -> str:
        """Retrieve the decrypted Apprise URL for delivery."""
        return cls.decrypt_url(channel.url_encrypted, channel.id)

    @classmethod
    def to_dict(cls, channel: NotificationChannel, mask_secrets: bool = True) -> dict[str, Any]:
        """Convert channel entity to dictionary format with optional credential masking."""
        raw_url = cls.get_decrypted_url(channel)
        display_url = mask_apprise_url(raw_url) if mask_secrets else raw_url

        return {
            "id": str(channel.id),
            "name": channel.name,
            "enabled": channel.enabled,
            "channel_type": channel.channel_type,
            "url": display_url,
            "telegram_format": channel.telegram_format,
            "rate_limit_interval_s": channel.rate_limit_interval_s,
            "config_metadata": channel.config_metadata or {},
            "created_at": channel.created_at.isoformat() if channel.created_at else None,
            "updated_at": channel.updated_at.isoformat() if channel.updated_at else None,
        }

    @classmethod
    def reencrypt_channel_url(
        cls,
        session: Session,
        channel_id: uuid.UUID,
        new_key_id: str | None = None,
    ) -> bool:
        """Re-encrypt notification channel Apprise URL using target or primary key.

        Returns True if the URL was re-encrypted, False if already current or not found.
        """
        from embervault_common.security.crypto import reencrypt_blob

        channel = cls.get_channel_by_id(session, channel_id)
        if channel is None:
            return False

        aad = f"notification_channel:{channel.id}".encode()
        reencrypted = reencrypt_blob(channel.url_encrypted, new_key_id=new_key_id, aad=aad)
        if reencrypted != channel.url_encrypted:
            channel.url_encrypted = reencrypted
            session.flush()
            return True
        return False
