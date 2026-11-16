"""Integration tests: Orchestrator HealthMonitor and ProxyClient over real in-process TLS server."""

from __future__ import annotations

import ssl
import threading
from collections.abc import Generator
from typing import Any
from uuid import uuid4
from wsgiref.simple_server import WSGIRequestHandler, make_server

import pytest
from pydantic import SecretStr
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_common.config import OrchestratorSettings, ProxySettings
from embervault_common.contracts import ProxyState
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
from embervault_proxy.factory import create_proxy_app

PROXY_TEST_TOKEN = "INTEGRATION_TEST_PROXY_TOKEN_AT_LEAST_32_CHARS"


class SilentWSGIRequestHandler(WSGIRequestHandler):
    """WSGI request handler suppressing stdout logs during test execution."""

    def log_message(self, format: str, *args: Any) -> None:
        pass


@pytest.fixture(scope="module")
def real_tls_proxy_server(
    tmp_path_factory: pytest.TempPathFactory,
) -> Generator[tuple[str, int, str, Any], None, None]:
    """Start a real HTTPS server serving embervault-proxy on a free localhost port."""
    temp_dir = tmp_path_factory.mktemp("proxy_tls")
    settings = ProxySettings(
        token=SecretStr(PROXY_TEST_TOKEN),
        proxy_state_dir=temp_dir,
        proxy_tls_auto_self_signed=True,
    )
    app = create_proxy_app(settings)
    cert_path = app.config["TLS_CERT_PATH"]
    key_path = app.config["TLS_KEY_PATH"]
    fingerprint = app.config["TLS_FINGERPRINT"]

    # Create WSGI server on free port (0)
    server = make_server("127.0.0.1", 0, app, handler_class=SilentWSGIRequestHandler)
    port = server.server_address[1]

    # Wrap server socket with TLS
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    server.socket = ssl_context.wrap_socket(server.socket, server_side=True)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield "127.0.0.1", port, fingerprint, server

    server.shutdown()
    server.server_close()
    thread.join(timeout=2.0)


@pytest.fixture
def test_db_session_factory() -> sessionmaker[Session]:
    set_default_key_ring(KeyRing(keys={"v1": "orchestrator_integration_master_key_16"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


class TestOrchestratorProxyTLSIntegration:
    """Integration tests connecting orchestrator components to a live TLS proxy."""

    def test_probe_tls_certificate_matches_server(
        self,
        real_tls_proxy_server: tuple[str, int, str, Any],
    ) -> None:
        host, port, expected_fp, _ = real_tls_proxy_server
        probed_fp = ProxyClient.probe_tls_certificate(host, port)
        assert probed_fp == expected_fp

    def test_get_health_success_with_pinning(
        self,
        real_tls_proxy_server: tuple[str, int, str, Any],
    ) -> None:
        host, port, expected_fp, _ = real_tls_proxy_server
        client = ProxyClient()

        health, latency = client.get_health(
            host=host,
            port=port,
            token=PROXY_TEST_TOKEN,
            expected_fingerprint=expected_fp,
        )
        assert health.status == "ok"
        from embervault_proxy import __version__ as expected_proxy_version

        assert health.proxy_version == expected_proxy_version
        assert latency >= 0

    def test_get_health_fails_on_fingerprint_mismatch(
        self,
        real_tls_proxy_server: tuple[str, int, str, Any],
    ) -> None:
        host, port, _, _ = real_tls_proxy_server
        client = ProxyClient()

        wrong_fp = "00" * 32
        with pytest.raises(TLSFingerprintMismatchError):
            client.get_health(
                host=host,
                port=port,
                token=PROXY_TEST_TOKEN,
                expected_fingerprint=wrong_fp,
            )

    def test_get_health_fails_on_unauthorized_token(
        self,
        real_tls_proxy_server: tuple[str, int, str, Any],
    ) -> None:
        host, port, expected_fp, _ = real_tls_proxy_server
        client = ProxyClient()

        with pytest.raises(ProxyUnauthorizedError):
            client.get_health(
                host=host,
                port=port,
                token="wrong_token_with_minimum_32_characters_here",
                expected_fingerprint=expected_fp,
            )

    def test_get_health_fails_on_unreachable_port(self) -> None:
        client = ProxyClient()
        # Querying closed port on localhost
        with pytest.raises(ProxyUnreachableError):
            client.get_health(
                host="127.0.0.1",
                port=59999,
                token=PROXY_TEST_TOKEN,
                expected_fingerprint="aa" * 32,
                timeout=(0.5, 0.5),
            )

    def test_health_monitor_end_to_end_lifecycle(
        self,
        real_tls_proxy_server: tuple[str, int, str, Any],
        test_db_session_factory: sessionmaker[Session],
    ) -> None:
        host, port, expected_fp, _ = real_tls_proxy_server
        proxy_id = uuid4()

        # Register proxy in DB
        with test_db_session_factory() as session:
            enc_token = ProxyRepository.encrypt_token(PROXY_TEST_TOKEN, proxy_id)
            proxy = Proxy(
                id=proxy_id,
                name="live-tls-proxy",
                host=host,
                port=port,
                token_encrypted=enc_token,
                cert_fingerprint_sha256=expected_fp,
                is_enabled=True,
                max_concurrent_tasks=2,
            )
            session.add(proxy)
            session.commit()

        settings = OrchestratorSettings(online_after_successes=2, offline_after_failures=3)
        monitor = HealthMonitor(session_factory=test_db_session_factory, settings=settings)

        # Tick 1: first success -> stays unknown (hysteresis)
        res1 = monitor.tick()
        assert res1[proxy_id] == ProxyState.UNKNOWN

        # Tick 2: second success -> transitions to online!
        res2 = monitor.tick()
        assert res2[proxy_id] == ProxyState.ONLINE

        with test_db_session_factory() as session:
            st = ProxyRepository.get_or_create_status(session, proxy_id)
            assert st.state == ProxyState.ONLINE
            assert st.consecutive_successes == 2

            # Now tamper with certificate fingerprint in DB to simulate cert change
            proxy_db = session.get(Proxy, proxy_id)
            assert proxy_db is not None
            proxy_db.cert_fingerprint_sha256 = "11" * 32
            session.commit()

        # Tick 3: fingerprint mismatch -> immediate transition to untrusted
        res3 = monitor.tick()
        assert res3[proxy_id] == ProxyState.UNTRUSTED

        with test_db_session_factory() as session:
            st = ProxyRepository.get_or_create_status(session, proxy_id)
            assert st.state == ProxyState.UNTRUSTED

            events = session.query(ProxyStateEvent).filter_by(proxy_id=proxy_id).all()
            # Initial unknown -> online, then online -> untrusted
            assert len(events) == 2
            assert events[0].to_state == ProxyState.ONLINE
            assert events[1].to_state == ProxyState.UNTRUSTED
