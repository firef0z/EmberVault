"""Unit tests for HealthMonitor hysteresis state transitions and event recording."""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.config import OrchestratorSettings
from embervault_common.contracts import ErrorCode, ProxyHealthResponse, ProxyState
from embervault_common.security import TLSFingerprintMismatchError
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models.base import Base
from embervault_db.models.proxy import Proxy, ProxyStateEvent
from embervault_db.repositories.proxy_repository import ProxyRepository
from embervault_orchestrator.health_monitor import HealthMonitor
from embervault_orchestrator.proxy_client import (
    ProxyClient,
    ProxyUnauthorizedError,
    ProxyUnreachableError,
)


@pytest.fixture
def db_session_factory() -> sessionmaker[Session]:
    # Ensure global KeyRing has master key for encrypting proxy tokens
    set_default_key_ring(KeyRing(keys={"v1": "test_master_key_at_least_16_bytes_long"}))

    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture
def sample_proxy(db_session_factory: sessionmaker[Session]) -> Proxy:
    with db_session_factory() as session:
        proxy_id = uuid4()
        token = "test_proxy_token_very_long_and_secret_32"
        encrypted_token = ProxyRepository.encrypt_token(token, proxy_id)

        proxy = Proxy(
            id=proxy_id,
            name="test-proxy-1",
            host="127.0.0.1",
            port=8443,
            token_encrypted=encrypted_token,
            cert_fingerprint_sha256="aa" * 32,
            is_enabled=True,
            max_concurrent_tasks=2,
        )
        session.add(proxy)
        session.commit()
        return proxy


class TestHealthMonitorHysteresis:
    """Tests for proxy state transitions with hysteresis."""

    def test_transition_to_online_after_two_successes(
        self,
        db_session_factory: sessionmaker[Session],
        sample_proxy: Proxy,
    ) -> None:
        mock_client = MagicMock(spec=ProxyClient)
        mock_client.get_health.return_value = (
            ProxyHealthResponse(
                status="ok",
                proxy_version="1.0.0",
                rclone_version="rclone v1.68.2",
                uptime_s=100.0,
                capacity=4,
                running_tasks=0,
                server_time=datetime.datetime.now(datetime.UTC),
            ),
            15,  # 15 ms latency
        )

        settings = OrchestratorSettings(
            online_after_successes=2,
            offline_after_failures=3,
        )
        monitor = HealthMonitor(
            session_factory=db_session_factory,
            settings=settings,
            proxy_client=mock_client,
        )

        with db_session_factory() as session:
            # Poll 1: initial state is unknown -> success count = 1, stays unknown
            state_1 = monitor.check_proxy(session, sample_proxy)
            assert state_1 == ProxyState.UNKNOWN
            status_1 = ProxyRepository.get_or_create_status(session, sample_proxy.id)
            assert status_1.consecutive_successes == 1

            # Poll 2: success count reaches 2 -> transitions to online
            state_2 = monitor.check_proxy(session, sample_proxy)
            assert state_2 == ProxyState.ONLINE
            status_2 = ProxyRepository.get_or_create_status(session, sample_proxy.id)
            assert status_2.consecutive_successes == 2
            assert status_2.state == ProxyState.ONLINE
            assert status_2.capacity == 4

            # Verify event logged
            events = session.query(ProxyStateEvent).filter_by(proxy_id=sample_proxy.id).all()
            assert len(events) == 1
            assert events[0].from_state == ProxyState.UNKNOWN
            assert events[0].to_state == ProxyState.ONLINE

    def test_transition_to_offline_after_three_failures(
        self,
        db_session_factory: sessionmaker[Session],
        sample_proxy: Proxy,
    ) -> None:
        mock_client = MagicMock(spec=ProxyClient)
        settings = OrchestratorSettings(
            online_after_successes=2,
            offline_after_failures=3,
        )
        monitor = HealthMonitor(
            session_factory=db_session_factory,
            settings=settings,
            proxy_client=mock_client,
        )

        with db_session_factory() as session:
            # Set proxy state to online initially
            status = ProxyRepository.get_or_create_status(session, sample_proxy.id)
            status.state = ProxyState.ONLINE
            status.consecutive_successes = 5
            status.consecutive_failures = 0
            session.commit()

        # Simulate network errors
        mock_client.get_health.side_effect = ProxyUnreachableError("Connection refused")

        with db_session_factory() as session:
            # Failure 1: stays online
            st1 = monitor.check_proxy(session, sample_proxy)
            assert st1 == ProxyState.ONLINE
            assert (
                ProxyRepository.get_or_create_status(session, sample_proxy.id).consecutive_failures
                == 1
            )

            # Failure 2: stays online
            st2 = monitor.check_proxy(session, sample_proxy)
            assert st2 == ProxyState.ONLINE
            assert (
                ProxyRepository.get_or_create_status(session, sample_proxy.id).consecutive_failures
                == 2
            )

            # Failure 3: transitions to offline!
            st3 = monitor.check_proxy(session, sample_proxy)
            assert st3 == ProxyState.OFFLINE
            status_final = ProxyRepository.get_or_create_status(session, sample_proxy.id)
            assert status_final.consecutive_failures == 3
            assert status_final.state == ProxyState.OFFLINE
            assert status_final.last_error_code == ErrorCode.PROXY_UNREACHABLE

            events = session.query(ProxyStateEvent).filter_by(proxy_id=sample_proxy.id).all()
            assert len(events) == 1
            assert events[0].from_state == ProxyState.ONLINE
            assert events[0].to_state == ProxyState.OFFLINE

    def test_immediate_transition_to_untrusted_on_cert_mismatch(
        self,
        db_session_factory: sessionmaker[Session],
        sample_proxy: Proxy,
    ) -> None:
        mock_client = MagicMock(spec=ProxyClient)
        mock_client.get_health.side_effect = TLSFingerprintMismatchError("Fingerprint mismatch")

        monitor = HealthMonitor(session_factory=db_session_factory, proxy_client=mock_client)

        with db_session_factory() as session:
            # Set proxy online initially
            status = ProxyRepository.get_or_create_status(session, sample_proxy.id)
            status.state = ProxyState.ONLINE
            session.commit()

            # Single poll immediately marks untrusted without hysteresis
            res_state = monitor.check_proxy(session, sample_proxy)
            assert res_state == ProxyState.UNTRUSTED

            status_updated = ProxyRepository.get_or_create_status(session, sample_proxy.id)
            assert status_updated.state == ProxyState.UNTRUSTED
            assert status_updated.last_error_code == ErrorCode.PROXY_CERT_MISMATCH

    def test_immediate_transition_to_unauthorized_on_401(
        self,
        db_session_factory: sessionmaker[Session],
        sample_proxy: Proxy,
    ) -> None:
        mock_client = MagicMock(spec=ProxyClient)
        mock_client.get_health.side_effect = ProxyUnauthorizedError("HTTP 401")

        monitor = HealthMonitor(session_factory=db_session_factory, proxy_client=mock_client)

        with db_session_factory() as session:
            status = ProxyRepository.get_or_create_status(session, sample_proxy.id)
            status.state = ProxyState.ONLINE
            session.commit()

            res_state = monitor.check_proxy(session, sample_proxy)
            assert res_state == ProxyState.UNAUTHORIZED

            status_updated = ProxyRepository.get_or_create_status(session, sample_proxy.id)
            assert status_updated.state == ProxyState.UNAUTHORIZED
            assert status_updated.last_error_code == ErrorCode.PROXY_UNAUTHORIZED

    def test_incompatible_proxy_version_marked_offline_and_notified(
        self,
        db_session_factory: sessionmaker[Session],
        sample_proxy: Proxy,
    ) -> None:
        mock_client = MagicMock(spec=ProxyClient)
        mock_client.get_health.return_value = (
            ProxyHealthResponse(
                status="ok",
                proxy_version="0.1.0",
                rclone_version="rclone v1.68.2",
                uptime_s=100.0,
                capacity=4,
                running_tasks=0,
                server_time=datetime.datetime.now(datetime.UTC),
            ),
            15,
        )
        mock_notifier = MagicMock()

        monitor = HealthMonitor(
            session_factory=db_session_factory,
            proxy_client=mock_client,
            notification_service=mock_notifier,
        )

        with db_session_factory() as session:
            # Set proxy online initially
            status = ProxyRepository.get_or_create_status(session, sample_proxy.id)
            status.state = ProxyState.ONLINE
            session.commit()

            # Check proxy
            state = monitor.check_proxy(session, sample_proxy)
            assert state == ProxyState.OFFLINE

            # Check DB status
            status_updated = ProxyRepository.get_or_create_status(session, sample_proxy.id)
            assert status_updated.state == ProxyState.OFFLINE
            assert status_updated.last_error_code == ErrorCode.PROXY_VERSION_INCOMPATIBLE

            # Check notification sent
            mock_notifier.notify_proxy_offline.assert_called_once()
            call_kwargs = mock_notifier.notify_proxy_offline.call_args[1]
            assert call_kwargs["is_incompatible"] is True
            assert call_kwargs["detected_version"] == "0.1.0"
            assert call_kwargs["min_version"] == "1.0.0"
