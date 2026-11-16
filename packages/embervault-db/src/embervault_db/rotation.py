"""Centralized cryptographic rotation service for EmberVault credentials."""

from __future__ import annotations

from typing import TYPE_CHECKING

from embervault_common.observability import get_logger
from embervault_db.repositories.notification_repository import NotificationRepository
from embervault_db.repositories.proxy_repository import ProxyRepository
from embervault_db.repositories.remote_repository import RemoteRepository
from embervault_db.repositories.user_repository import UserRepository

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from embervault_db.settings_store import SettingsStore

logger = get_logger("embervault_db.rotation")


def rotate_all_credentials(
    session: Session,
    settings_store: SettingsStore | None = None,
    target_key_id: str | None = None,
) -> dict[str, int]:
    """Re-encrypt all envelope-encrypted secrets across all database tables.

    Iterates over:
      - RClone remotes (encrypted configurations)
      - Proxies (encrypted bearer tokens)
      - Notification channels (encrypted Apprise URLs)
      - User MFA factors (encrypted TOTP seeds)
      - Application settings (encrypted secret settings in database)

    Each entity is inspected and re-encrypted with `target_key_id` (or the default
    primary master key if None). Blobs already encrypted with the target key are skipped.

    Returns:
        dict[str, int]: Summary counts of re-encrypted records per category.
    """
    logger.info("credential_rotation_started", target_key_id=target_key_id or "primary")

    remotes_rotated = 0
    all_remotes = RemoteRepository.list_remotes(session, include_disabled=True)
    for remote in all_remotes:
        if RemoteRepository.reencrypt_remote(session, remote.id, new_key_id=target_key_id):
            remotes_rotated += 1

    proxies_rotated = 0
    all_proxies = ProxyRepository.get_all_proxies(session)
    for proxy in all_proxies:
        if ProxyRepository.reencrypt_proxy_token(session, proxy.id, new_key_id=target_key_id):
            proxies_rotated += 1

    channels_rotated = 0
    all_channels = NotificationRepository.list_channels(session)
    for channel in all_channels:
        if NotificationRepository.reencrypt_channel_url(
            session, channel.id, new_key_id=target_key_id
        ):
            channels_rotated += 1

    mfa_rotated = UserRepository.reencrypt_user_mfa_factors(session, new_key_id=target_key_id)

    settings_rotated = 0
    if settings_store is not None:
        settings_rotated = settings_store.reencrypt_secret_settings(new_key_id=target_key_id)

    total_rotated = (
        remotes_rotated + proxies_rotated + channels_rotated + mfa_rotated + settings_rotated
    )

    logger.info(
        "credential_rotation_completed",
        remotes=remotes_rotated,
        proxies=proxies_rotated,
        notification_channels=channels_rotated,
        mfa_factors=mfa_rotated,
        settings=settings_rotated,
        total=total_rotated,
    )

    return {
        "remotes": remotes_rotated,
        "proxies": proxies_rotated,
        "notification_channels": channels_rotated,
        "mfa_factors": mfa_rotated,
        "settings": settings_rotated,
        "total": total_rotated,
    }
