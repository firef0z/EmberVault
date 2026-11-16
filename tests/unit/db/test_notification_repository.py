"""Unit tests for NotificationChannel model, NotificationRepository, and Job notifications toggle."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models.base import Base
from embervault_db.repositories.job_repository import JobRepository
from embervault_db.repositories.notification_repository import NotificationRepository
from embervault_db.repositories.remote_repository import RemoteRepository
from embervault_db.settings_store import SettingsStore


@pytest.fixture
def db_session() -> sessionmaker[Session]:
    set_default_key_ring(KeyRing(keys={"v1": "test_encryption_key_32_characters_"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def test_create_and_decrypt_notification_channel(db_session: sessionmaker[Session]) -> None:
    raw_url = "tgram://123456789:ABC_SECRET_TOKEN/-100123456789/?format=html"
    with db_session() as session:
        channel = NotificationRepository.create_channel(
            session=session,
            name="Telegram DevOps",
            url=raw_url,
            channel_type="telegram",
            telegram_format="html",
            rate_limit_interval_s=60,
            enabled=True,
            config_metadata={"chat_id": "-100123456789"},
        )
        session.commit()
        channel_id = channel.id

    with db_session() as session:
        loaded = NotificationRepository.get_channel_by_id(session, channel_id)
        assert loaded is not None
        assert loaded.name == "Telegram DevOps"
        assert loaded.channel_type == "telegram"
        assert loaded.telegram_format == "html"
        assert loaded.rate_limit_interval_s == 60
        assert loaded.enabled is True
        assert loaded.config_metadata == {"chat_id": "-100123456789"}

        # Verify URL is stored encrypted (not in plaintext)
        assert isinstance(loaded.url_encrypted, bytes)
        assert raw_url.encode("utf-8") not in loaded.url_encrypted

        # Verify decryption
        decrypted = NotificationRepository.get_decrypted_url(loaded)
        assert decrypted == raw_url

        # Verify to_dict with secret masking
        dict_masked = NotificationRepository.to_dict(loaded, mask_secrets=True)
        assert "ABC_SECRET_TOKEN" not in dict_masked["url"]
        assert "••••••••" in dict_masked["url"]
        assert dict_masked["name"] == "Telegram DevOps"

        dict_unmasked = NotificationRepository.to_dict(loaded, mask_secrets=False)
        assert dict_unmasked["url"] == raw_url


def test_list_and_update_notification_channels(db_session: sessionmaker[Session]) -> None:
    with db_session() as session:
        c1 = NotificationRepository.create_channel(
            session=session,
            name="Channel 1",
            url="mailto://user:pass1@smtp.example.com",
            channel_type="email",
            enabled=True,
        )
        c2 = NotificationRepository.create_channel(
            session=session,
            name="Channel 2",
            url="mailto://user:pass2@smtp.example.com",
            channel_type="email",
            enabled=False,
        )
        session.commit()
        c1_id, c2_id = c1.id, c2.id

    with db_session() as session:
        # Test listing
        all_channels = NotificationRepository.list_channels(session, only_enabled=False)
        assert len(all_channels) == 2

        enabled_channels = NotificationRepository.list_channels(session, only_enabled=True)
        assert len(enabled_channels) == 1
        assert enabled_channels[0].id == c1_id

        # Test updating channel properties
        new_url = "mailto://user:NewPass123@smtp.example.com"
        updated = NotificationRepository.update_channel(
            session=session,
            channel_id=c1_id,
            name="Channel 1 Updated",
            url=new_url,
            rate_limit_interval_s=120,
            enabled=False,
        )
        session.commit()
        assert updated is not None
        assert updated.name == "Channel 1 Updated"
        assert updated.rate_limit_interval_s == 120
        assert updated.enabled is False
        assert NotificationRepository.get_decrypted_url(updated) == new_url

        # Test deletion
        deleted = NotificationRepository.delete_channel(session, c2_id)
        session.commit()
        assert deleted is True

        rem = NotificationRepository.get_channel_by_id(session, c2_id)
        assert rem is None


def test_job_notifications_enabled_flag(db_session: sessionmaker[Session]) -> None:
    with db_session() as session:
        r1 = RemoteRepository.create_remote(session, "src-remote", "local", {"path": "/src"})
        r2 = RemoteRepository.create_remote(session, "dst-remote", "local", {"path": "/dst"})
        session.commit()
        r1_id, r2_id = r1.id, r2.id

    # Create job with default notifications_enabled (True)
    with db_session() as session:
        job1 = JobRepository.create_job(
            session=session,
            name="job-notifications-default",
            source_remote_id=r1_id,
            source_path="/photos",
            destination_remote_id=r2_id,
            destination_path="/photos-backup",
            operation="sync",
            parallelization="none",
        )
        session.commit()
        assert job1.notifications_enabled is True
        job1_id = job1.id

    # Create job with notifications_enabled=False
    with db_session() as session:
        job2 = JobRepository.create_job(
            session=session,
            name="job-notifications-disabled",
            source_remote_id=r1_id,
            source_path="/photos",
            destination_remote_id=r2_id,
            destination_path="/photos-backup",
            operation="sync",
            parallelization="none",
            notifications_enabled=False,
        )
        session.commit()
        assert job2.notifications_enabled is False
        job2_id = job2.id

    # Update job to toggle notifications_enabled
    with db_session() as session:
        updated = JobRepository.update_job(
            session=session,
            job_id=job1_id,
            notifications_enabled=False,
        )
        session.commit()
        assert updated.notifications_enabled is False

        loaded2 = JobRepository.get_job_by_id(session, job2_id)
        assert loaded2 is not None
        assert loaded2.notifications_enabled is False


def test_settings_store_notification_job_policy_validation(
    db_session: sessionmaker[Session],
) -> None:
    from embervault_db.settings_store import InvalidSettingValueError

    store = SettingsStore(session_factory=db_session)

    # Valid policies: only_errors and always
    store.set_setting("notification_job_policy", "only_errors")
    assert store.get_setting("notification_job_policy") == "only_errors"

    store.set_setting("notification_job_policy", "always")
    assert store.get_setting("notification_job_policy") == "always"

    # Invalid policy must raise InvalidSettingValueError
    with pytest.raises(InvalidSettingValueError, match="must be 'only_errors' or 'always'"):
        store.set_setting("notification_job_policy", "never")
