"""Unit tests verifying that disabled proxies are counted as offline in the Dashboard Proxies Online counter."""

from __future__ import annotations

from uuid import uuid4

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.blueprints.api import _build_dashboard_snapshot
from embervault_app.factory import create_app
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import Base, Proxy, ProxyStatus
from embervault_db.seed import seed_initial_data
from embervault_db.settings_store import SettingsStore


@pytest.fixture
def app_and_db() -> tuple[FlaskClient, sessionmaker[Session]]:
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
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


def test_disabled_proxies_counted_as_offline_on_dashboard(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    client, session_factory = app_and_db

    # Create 3 proxies:
    # 1: is_enabled=True, state="online" -> should be ONLINE
    # 2: is_enabled=False, state="online" -> DISABLED! MUST be counted as OFFLINE
    # 3: is_enabled=True, state="offline" -> OFFLINE
    with session_factory() as session:
        p1 = Proxy(
            id=uuid4(),
            name="Proxy-Active-Online",
            host="10.0.0.1",
            port=8443,
            is_enabled=True,
            cert_fingerprint_sha256="test-fp-1",
            token_encrypted=b"test-tok-1",
        )
        ps1 = ProxyStatus(proxy_id=p1.id, state="online")

        p2 = Proxy(
            id=uuid4(),
            name="Proxy-Disabled-But-OnlineState",
            host="10.0.0.2",
            port=8443,
            is_enabled=False,  # <--- DISABLED
            cert_fingerprint_sha256="test-fp-2",
            token_encrypted=b"test-tok-2",
        )
        ps2 = ProxyStatus(
            proxy_id=p2.id, state="online"
        )  # State is 'online', but proxy is disabled

        p3 = Proxy(
            id=uuid4(),
            name="Proxy-Active-Offline",
            host="10.0.0.3",
            port=8443,
            is_enabled=True,
            cert_fingerprint_sha256="test-fp-3",
            token_encrypted=b"test-tok-3",
        )
        ps3 = ProxyStatus(proxy_id=p3.id, state="offline")

        session.add_all([p1, ps1, p2, ps2, p3, ps3])
        session.commit()

        # 1. Test _build_dashboard_snapshot directly
        snapshot = _build_dashboard_snapshot(session)
        assert snapshot["proxies_count"]["total"] == 3
        # Only p1 should be online!
        assert snapshot["proxies_count"]["online"] == 1
        # p2 (disabled) and p3 (offline) should both be offline!
        assert snapshot["proxies_count"]["offline"] == 2

    # 2. Test GET /api/ui/status endpoint
    res_status = client.get("/api/ui/status")
    assert res_status.status_code == 200
    data = res_status.get_json()
    assert data["proxies"]["total"] == 3
    assert data["proxies"]["online"] == 1
    assert data["proxies"]["offline"] == 2

    # 3. Test GET / (Dashboard HTML view)
    res_dash = client.get("/")
    assert res_dash.status_code == 200
    html = res_dash.data.decode("utf-8")
    # Verify the stat card shows 1/3 (1 online out of 3 total)
    assert '<span id="stat-proxies-online">1</span>/<span id="stat-proxies-total">3</span>' in html


def test_re_enabling_proxy_updates_online_count(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    client, session_factory = app_and_db

    with session_factory() as session:
        p = Proxy(
            id=uuid4(),
            name="Toggle-Proxy",
            host="10.0.0.10",
            port=8443,
            is_enabled=False,
            cert_fingerprint_sha256="test-fp-toggle",
            token_encrypted=b"test-tok-toggle",
        )
        ps = ProxyStatus(proxy_id=p.id, state="online")
        session.add_all([p, ps])
        session.commit()

        proxy_id = p.id

    # Initially disabled -> 0 online, 1 offline
    res1 = client.get("/api/ui/status")
    assert res1.get_json()["proxies"]["online"] == 0
    assert res1.get_json()["proxies"]["offline"] == 1

    # Enable proxy
    with session_factory() as session:
        proxy = session.get(Proxy, proxy_id)
        assert proxy is not None
        proxy.is_enabled = True
        session.commit()

    # Now enabled with state='online' -> 1 online, 0 offline
    res2 = client.get("/api/ui/status")
    assert res2.get_json()["proxies"]["online"] == 1
    assert res2.get_json()["proxies"]["offline"] == 0
