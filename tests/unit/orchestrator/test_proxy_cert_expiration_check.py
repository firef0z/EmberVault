"""Unit tests for periodic 24-hour proxy certificate expiration checking and notifications."""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from embervault_common.notifications.contracts import NotificationEventType, TelegramFormat
from embervault_common.notifications.formatter import NotificationFormatter
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import Base, Proxy
from embervault_db.repositories.proxy_repository import ProxyRepository
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


def test_proxy_cert_notification_formatters() -> None:
    # PROXY_CERT_EXPIRING formatting
    exp_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
    title, body, fmt = NotificationFormatter.format(
        NotificationEventType.PROXY_CERT_EXPIRING,
        {
            "proxy_name": "Proxy-Node-1",
            "proxy_host": "10.0.0.1",
            "proxy_port": 8443,
            "days_remaining": 10,
            "expires_at": exp_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
        },
        TelegramFormat.HTML,
    )
    assert "Proxy-Node-1" in title
    assert "10" in body
    assert "Proxy-Node-1" in body

    # PROXY_UNTRUSTED formatting
    title_u, body_u, fmt_u = NotificationFormatter.format(
        NotificationEventType.PROXY_UNTRUSTED,
        {
            "proxy_name": "Proxy-Node-2",
            "proxy_host": "10.0.0.2",
            "proxy_port": 8443,
            "reason": "TLS certificate fingerprint mismatch",
        },
        TelegramFormat.HTML,
    )
    assert "Proxy-Node-2" in title_u
    assert "Non Affidabile" in title_u
    assert "Untrusted" in body_u


def test_reconciler_periodic_cert_expiration_check(session_factory: sessionmaker[Session]) -> None:
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    exp_soon = now_utc + datetime.timedelta(days=10)
    exp_safe = now_utc + datetime.timedelta(days=45)

    with session_factory() as session:
        p1 = Proxy(
            id=uuid4(),
            name="Proxy-Expiring",
            host="10.0.0.1",
            port=8443,
            token_encrypted=b"dummy",
            cert_fingerprint_sha256="aa" * 32,
            cert_expires_at=exp_soon,
            is_enabled=True,
        )
        p2 = Proxy(
            id=uuid4(),
            name="Proxy-Safe",
            host="10.0.0.2",
            port=8443,
            token_encrypted=b"dummy",
            cert_fingerprint_sha256="bb" * 32,
            cert_expires_at=exp_safe,
            is_enabled=True,
        )
        session.add_all([p1, p2])
        session.commit()

    mock_notifier = MagicMock()
    mock_notifier.notify_proxy_cert_expiring.return_value = 1

    reconciler = ExecutionReconciler(
        session_factory=session_factory,
        notification_service=mock_notifier,
    )

    # First run: check is due (last_ts is 0)
    now_ts = 1000000.0
    reconciler._check_proxy_cert_expirations_if_due(now_ts)

    # Should notify for Proxy-Expiring, but not Proxy-Safe
    assert mock_notifier.notify_proxy_cert_expiring.call_count == 1
    call_args = mock_notifier.notify_proxy_cert_expiring.call_args[1]
    assert call_args["proxy"].name == "Proxy-Expiring"
    assert call_args["days_remaining"] <= 10

    # Second run immediately after: not due (< 86400s) -> no additional call
    reconciler._check_proxy_cert_expirations_if_due(now_ts + 3600.0)
    assert mock_notifier.notify_proxy_cert_expiring.call_count == 1
