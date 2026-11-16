"""Unit tests verifying incompatible proxy version detection, banner, and badge rendering in the Web UI."""

from __future__ import annotations

from uuid import uuid4

import pytest
from flask.testing import FlaskClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from embervault_app.factory import create_app
from embervault_common.config import AppSettings
from embervault_common.contracts import ErrorCode, ProxyState
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import Base, Proxy, ProxyStatus
from embervault_db.repositories.proxy_repository import ProxyRepository
from embervault_db.seed import seed_initial_data
from embervault_db.settings_store import SettingsStore


@pytest.fixture
def app_and_db() -> tuple[FlaskClient, sessionmaker[Session]]:
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine(
        "sqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    with session_factory() as session:
        seed_initial_data(session)

    store = SettingsStore(session_factory)
    settings = AppSettings(app_port=8080, dev_noauth=True)
    app = create_app(
        settings=settings,
        session_factory=session_factory,
        settings_store=store,
    )
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    return app.test_client(), session_factory


def test_incompatible_proxy_shows_banner_and_badge_on_proxies_page(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    client, session_factory = app_and_db

    with session_factory() as session:
        pid = uuid4()
        token = ProxyRepository.encrypt_token("tok" * 15, pid)
        proxy = Proxy(
            id=pid,
            name="Proxy-Outdated",
            host="192.168.1.100",
            port=8443,
            token_encrypted=token,
            cert_fingerprint_sha256="aa" * 32,
            is_enabled=True,
            proxy_version="0.1.0",
        )
        session.add(proxy)
        session.flush()

        status = ProxyStatus(
            proxy_id=pid,
            state=ProxyState.OFFLINE,
            last_error_code=ErrorCode.PROXY_VERSION_INCOMPATIBLE,
            consecutive_failures=1,
            consecutive_successes=0,
            running_tasks=0,
            capacity=1,
            latency_ms=10,
        )
        session.add(status)
        session.commit()

    resp = client.get("/proxies")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    # Incompatibility banner should be rendered
    assert "banner-proxy-incompatible" in html
    assert (
        "Proxy con versione non compatibile rilevato" in html
        or "Incompatible proxy version detected" in html
    )

    # Status column should show Incompatible badge
    assert "Incompatibile" in html or "Incompatible" in html
    assert "v0.1.0" in html


def test_compatible_proxy_does_not_show_incompatible_banner(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    client, session_factory = app_and_db

    with session_factory() as session:
        pid = uuid4()
        token = ProxyRepository.encrypt_token("tok" * 15, pid)
        proxy = Proxy(
            id=pid,
            name="Proxy-Modern",
            host="192.168.1.101",
            port=8443,
            token_encrypted=token,
            cert_fingerprint_sha256="bb" * 32,
            is_enabled=True,
            proxy_version="1.0.0",
        )
        session.add(proxy)
        session.flush()

        status = ProxyStatus(
            proxy_id=pid,
            state=ProxyState.ONLINE,
            consecutive_failures=0,
            consecutive_successes=2,
            running_tasks=0,
            capacity=2,
            latency_ms=15,
        )
        session.add(status)
        session.commit()

    resp = client.get("/proxies")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)

    # Incompatibility banner must NOT be rendered
    assert "banner-proxy-incompatible" not in html

    # Status column should show Online badge
    assert "badge-online" in html
    assert "v1.0.0" in html
