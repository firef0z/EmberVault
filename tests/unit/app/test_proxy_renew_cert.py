"""Unit tests for proxy certificate renewal and expiration UI indicators."""

from __future__ import annotations

import datetime
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from flask.testing import FlaskClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from embervault_app.factory import create_app
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import Base, Proxy, ProxyStatus, Role, User
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


def test_renew_proxy_certificate_endpoint(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    client, session_factory = app_and_db

    pid = uuid4()
    with session_factory() as session:
        token = ProxyRepository.encrypt_token("tok" * 15, pid)
        proxy = Proxy(
            id=pid,
            name="Proxy-Renew-Target",
            host="127.0.0.1",
            port=8443,
            token_encrypted=token,
            cert_fingerprint_sha256="aa" * 32,
            is_enabled=True,
        )
        session.add(proxy)
        session.commit()

    with patch(
        "embervault_app.orchestrator_client.OrchestratorClient.renew_proxy_certificate"
    ) as mock_renew:
        mock_renew.return_value = {
            "status": "ok",
            "message": "Certificate renewed successfully",
            "cert_fingerprint": "bb" * 32,
            "cert_expires_at": (
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=90)
            ).isoformat(),
        }

        res = client.post(f"/api/ui/proxies/{pid}/renew-cert")
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "ok"
        mock_renew.assert_called_once_with(proxy_id=pid)


def test_renew_proxy_certificate_forbidden_without_permission(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    client, session_factory = app_and_db
    pid = uuid4()

    # Create unprivileged user (e.g. Viewer)
    with session_factory() as session:
        token = ProxyRepository.encrypt_token("tok" * 15, pid)
        proxy = Proxy(
            id=pid,
            name="Proxy-Forbidden-Test",
            host="127.0.0.1",
            port=8443,
            token_encrypted=token,
            cert_fingerprint_sha256="aa" * 32,
            is_enabled=True,
        )
        session.add(proxy)

        viewer_role = session.query(Role).filter_by(name="Viewer").first()
        viewer = User(
            id=uuid4(),
            username="viewer_user",
            password_hash="dummy_hash",
            is_active=True,
            role_id=viewer_role.id,
        )
        session.add(viewer)
        session.commit()
        viewer_id = str(viewer.id)

    with client.session_transaction() as sess:
        sess["user_id"] = viewer_id

    # Create app with dev_noauth=False to test RBAC enforcement
    store = SettingsStore(session_factory)
    settings = AppSettings(app_port=8080, dev_noauth=False)
    app = create_app(
        settings=settings,
        session_factory=session_factory,
        settings_store=store,
    )
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    auth_client = app.test_client()

    with auth_client.session_transaction() as sess:
        sess["user_id"] = viewer_id

    res = auth_client.post(f"/api/ui/proxies/{pid}/renew-cert")
    assert res.status_code == 403


def test_proxies_view_renders_cert_expiring_badge(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    client, session_factory = app_and_db

    pid = uuid4()
    exp_soon = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=5)

    with session_factory() as session:
        token = ProxyRepository.encrypt_token("tok" * 15, pid)
        proxy = Proxy(
            id=pid,
            name="Proxy-Expiring-Soon",
            host="127.0.0.1",
            port=8443,
            token_encrypted=token,
            cert_fingerprint_sha256="aa" * 32,
            cert_expires_at=exp_soon,
            is_enabled=True,
        )
        session.add(proxy)
        session.commit()

    res = client.get("/proxies", headers={"Accept-Language": "it"})
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    # Should contain the expiring badge and warning
    assert "Proxy-Expiring-Soon" in html
    assert "data-proxy-cert-expires-at" in html
    assert "Scadenza imminente" in html
    assert "btn-renew-cert-proxy" in html
    assert "modal-renew-cert-proxy" in html
