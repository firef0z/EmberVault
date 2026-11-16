"""Unit tests for Proxy RClone version querying and upgrade endpoints in the Web App."""

from __future__ import annotations

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


def test_get_rclone_available_versions(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    client, _ = app_and_db

    resp = client.get("/api/ui/proxies/rclone/versions")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert "latest" in data
    assert isinstance(data["versions"], list)
    assert len(data["versions"]) > 0


def test_get_proxy_rclone_status(app_and_db: tuple[FlaskClient, sessionmaker[Session]]) -> None:
    client, session_factory = app_and_db

    with session_factory() as session:
        pid = uuid4()
        token = ProxyRepository.encrypt_token("tok" * 15, pid)
        proxy = Proxy(
            id=pid,
            name="Proxy01",
            host="10.0.0.1",
            port=8443,
            token_encrypted=token,
            cert_fingerprint_sha256="aa" * 32,
            is_enabled=True,
            rclone_version="rclone v1.68.2",
        )
        session.add(proxy)
        session.commit()

    resp = client.get(f"/api/ui/proxies/{pid}/rclone/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert data["proxy_name"] == "Proxy01"
    assert "1.68.2" in data["installed_version"]
    assert "latest_version" in data
    assert "update_available" in data
    assert isinstance(data["versions"], list)


def test_proxy_rclone_upgrade_flow(app_and_db: tuple[FlaskClient, sessionmaker[Session]]) -> None:
    client, session_factory = app_and_db

    with session_factory() as session:
        pid = uuid4()
        token = ProxyRepository.encrypt_token("tok" * 15, pid)
        proxy = Proxy(
            id=pid,
            name="Proxy02",
            host="10.0.0.2",
            port=8443,
            token_encrypted=token,
            cert_fingerprint_sha256="bb" * 32,
            is_enabled=True,
            rclone_version="rclone v1.68.0",
        )
        session.add(proxy)
        session.commit()

    mock_orch_client = MagicMock()
    mock_orch_client.upgrade_proxy_rclone.return_value = {
        "status": "ok",
        "version": "rclone v1.69.0",
        "previous_version": "rclone v1.68.0",
    }

    with patch("embervault_app.blueprints.api.get_orchestrator", return_value=mock_orch_client):
        resp = client.post(
            f"/api/ui/proxies/{pid}/rclone/upgrade",
            json={"version": "1.69.0"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "1.69.0" in data["version"]

        # Check DB updated
        with session_factory() as session:
            updated_proxy = session.get(Proxy, pid)
            assert updated_proxy is not None
            assert "1.69.0" in (updated_proxy.rclone_version or "")


def test_proxies_edit_modal_tabs_and_upgrade_button_label(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    """Verify proxies edit modal renders separate tabs and button has label 'Aggiorna'."""
    client, _ = app_and_db
    res = client.get("/proxies")
    assert res.status_code == 200
    html = res.data.decode("utf-8")

    # Tabs structure
    assert 'id="tab-proxy-general"' in html
    assert 'id="tab-proxy-rclone"' in html
    assert 'data-tab="tab-proxy-general"' in html
    assert 'data-tab="tab-proxy-rclone"' in html
    assert "proxy-tab-btn" in html

    # Upgrade button has label 'Aggiorna' / 'Update'
    assert 'id="btn-upgrade-rclone-latest"' in html
    assert "Aggiorna" in html or "Update" in html or "Upgrade" in html
