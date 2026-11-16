"""Unit tests for RClone update checking, notification dispatch, and periodic reconciler check."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from embervault_common.notifications.contracts import (
    NotificationEventType,
    TelegramFormat,
)
from embervault_common.notifications.formatter import NotificationFormatter
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import Base, Proxy
from embervault_db.repositories.notification_repository import NotificationRepository
from embervault_db.repositories.proxy_repository import ProxyRepository
from embervault_db.settings_store import SettingsStore
from embervault_orchestrator.notifier import NotificationService
from embervault_orchestrator.reconciler import ExecutionReconciler


@pytest.fixture
def session_factory() -> sessionmaker[Session]:
    set_default_key_ring(KeyRing(keys={"v1": "test_orch_key_32_chars_minimum_"}))
    engine = create_engine(
        "sqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def test_rclone_update_notification_formatting() -> None:
    """Verify single consolidated notification formatting for multiple proxies."""
    context = {"proxies": ["Proxy01", "Proxy03"], "latest_version": "1.75.2"}

    # HTML
    title, body, fmt = NotificationFormatter.format(
        NotificationEventType.RCLONE_UPDATE_AVAILABLE, context, TelegramFormat.HTML
    )
    assert "Aggiornamenti RClone disponibili" in title
    assert "Proxy01, Proxy03" in body
    assert "v1.75.2" in body

    # Plain text
    title, body, fmt = NotificationFormatter.format(
        NotificationEventType.RCLONE_UPDATE_AVAILABLE, context, TelegramFormat.TEXT
    )
    assert "Proxy01, Proxy03" in body
    assert "v1.75.2" in body


def test_notifier_dispatches_single_notification_for_proxies(
    session_factory: sessionmaker[Session],
) -> None:
    """Verify NotificationService.notify_rclone_updates_available sends one consolidated message."""
    store = SettingsStore(session_factory)
    store.set_setting("notifications_enabled", True)
    store.set_setting("notification_rclone_update_enabled", True)

    with session_factory() as session:
        NotificationRepository.create_channel(
            session=session,
            name="TelegramOps",
            channel_type="telegram",
            url="tgram://123456789:ABCdef/-100123456789/?format=html",
            telegram_format="html",
            rate_limit_interval_s=0,
            enabled=True,
        )
        session.commit()

    service = NotificationService(store)
    mock_notifier = MagicMock()
    mock_notifier.send.return_value = True
    service.notifier = mock_notifier

    with session_factory() as session:
        sent = service.notify_rclone_updates_available(
            session=session,
            proxy_names=["Proxy01", "Proxy03"],
            latest_version="1.75.2",
        )
        assert sent == 1
        assert mock_notifier.send.call_count == 1
        _, kwargs = mock_notifier.send.call_args
        assert "Proxy01, Proxy03" in kwargs["body"]


def test_reconciler_periodic_check_identifies_outdated_proxies(
    session_factory: sessionmaker[Session],
) -> None:
    """Verify reconciler checks proxies and alerts only on outdated versions."""
    store = SettingsStore(session_factory)
    store.set_setting("notifications_enabled", True)
    store.set_setting("notification_rclone_update_enabled", True)
    store.set_setting("rclone_auto_update_check_enabled", True)
    store.set_setting("rclone_auto_update_check_interval_hours", 24)

    with session_factory() as session:
        # Proxy01 is outdated (1.68.0)
        p1_id = uuid4()
        session.add(
            Proxy(
                id=p1_id,
                name="Proxy01",
                host="10.0.0.1",
                port=8443,
                token_encrypted=ProxyRepository.encrypt_token("tok" * 15, p1_id),
                cert_fingerprint_sha256="11" * 32,
                is_enabled=True,
                rclone_version="rclone v1.68.0",
            )
        )
        # Proxy02 is already up-to-date (1.75.2)
        p2_id = uuid4()
        session.add(
            Proxy(
                id=p2_id,
                name="Proxy02",
                host="10.0.0.2",
                port=8443,
                token_encrypted=ProxyRepository.encrypt_token("tok" * 15, p2_id),
                cert_fingerprint_sha256="22" * 32,
                is_enabled=True,
                rclone_version="rclone v1.75.2",
            )
        )
        # Proxy03 is outdated (1.67.0)
        p3_id = uuid4()
        session.add(
            Proxy(
                id=p3_id,
                name="Proxy03",
                host="10.0.0.3",
                port=8443,
                token_encrypted=ProxyRepository.encrypt_token("tok" * 15, p3_id),
                cert_fingerprint_sha256="33" * 32,
                is_enabled=True,
                rclone_version="rclone v1.67.0",
            )
        )
        session.commit()

    reconciler = ExecutionReconciler(
        session_factory=session_factory,
        settings_store=store,
    )
    mock_notif_service = MagicMock()
    reconciler.notification_service = mock_notif_service

    with patch(
        "embervault_common.rclone_version.get_latest_rclone_version",
        return_value="1.75.2",
    ):
        now_ts = time.time()
        reconciler._check_proxy_rclone_updates_if_due(now_ts)

        # Should notify once with both Proxy01 and Proxy03
        assert mock_notif_service.notify_rclone_updates_available.call_count == 1
        _, kwargs = mock_notif_service.notify_rclone_updates_available.call_args
        assert sorted(kwargs["proxy_names"]) == ["Proxy01", "Proxy03"]
        assert kwargs["latest_version"] == "1.75.2"

        # Calling again immediately should respect interval and NOT notify
        reconciler._check_proxy_rclone_updates_if_due(now_ts + 100)
        assert mock_notif_service.notify_rclone_updates_available.call_count == 1
