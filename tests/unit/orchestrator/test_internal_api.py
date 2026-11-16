"""Unit tests for orchestrator internal API endpoints."""

from __future__ import annotations

from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from flask.testing import FlaskClient

from embervault_common.contracts import ProxyProbeResponse
from embervault_orchestrator.factory import create_orchestrator_app
from embervault_orchestrator.internal_api import set_proxy_client
from embervault_orchestrator.proxy_client import (
    ProxyClient,
    ProxyUnauthorizedError,
    ProxyUnreachableError,
)


@pytest.fixture
def orch_client() -> FlaskClient:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from embervault_common.security.crypto import KeyRing, set_default_key_ring
    from embervault_db.models.base import Base

    from sqlalchemy.pool import StaticPool

    set_default_key_ring(KeyRing(keys={"v1": "test_encryption_key_32_characters_"}))
    engine = create_engine(
        "sqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    app = create_orchestrator_app(session_factory=session_factory)
    app.config["TESTING"] = True
    return app.test_client()


class TestInternalApiProbe:
    """Tests for POST /internal/v1/proxies/probe."""

    def test_probe_missing_json(self, orch_client: FlaskClient) -> None:
        resp = orch_client.post("/internal/v1/proxies/probe")
        assert resp.status_code == 400

    def test_probe_invalid_payload(self, orch_client: FlaskClient) -> None:
        resp = orch_client.post(
            "/internal/v1/proxies/probe",
            json={"host": "127.0.0.1"},  # missing port and token
        )
        assert resp.status_code == 422

    def test_probe_success(self, orch_client: FlaskClient) -> None:
        mock_client = MagicMock(spec=ProxyClient)
        mock_client.probe.return_value = ProxyProbeResponse(
            cert_fingerprint_sha256="aa" * 32,
            status="ok",
            latency_ms=12.5,
            proxy_version="0.1.0",
            rclone_version="rclone v1.68.2",
        )
        set_proxy_client(mock_client)

        resp = orch_client.post(
            "/internal/v1/proxies/probe",
            json={
                "host": "127.0.0.1",
                "port": 8443,
                "token": "a" * 32,
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["cert_fingerprint_sha256"] == "aa" * 32
        assert data["proxy_version"] == "0.1.0"

    def test_probe_unauthorized(self, orch_client: FlaskClient) -> None:
        mock_client = MagicMock(spec=ProxyClient)
        mock_client.probe.side_effect = ProxyUnauthorizedError("Invalid token")
        set_proxy_client(mock_client)

        resp = orch_client.post(
            "/internal/v1/proxies/probe",
            json={"host": "127.0.0.1", "port": 8443, "token": "a" * 32},
        )
        assert resp.status_code == 401
        assert resp.get_json()["status"] == "unauthorized"

    def test_probe_unreachable(self, orch_client: FlaskClient) -> None:
        mock_client = MagicMock(spec=ProxyClient)
        mock_client.probe.side_effect = ProxyUnreachableError("Connection refused")
        set_proxy_client(mock_client)

        resp = orch_client.post(
            "/internal/v1/proxies/probe",
            json={"host": "127.0.0.1", "port": 8443, "token": "a" * 32},
        )
        assert resp.status_code == 502
        assert resp.get_json()["status"] == "offline"

    def test_discovery_endpoints(self, orch_client: FlaskClient) -> None:
        # Non-existent remote -> 404
        post_resp = orch_client.post(
            "/internal/v1/discoveries",
            json={"source_remote_id": str(uuid4()), "source_path": "/test"},
        )
        assert post_resp.status_code == 404

        # Non-existent discovery ID -> 404
        get_resp = orch_client.get(f"/internal/v1/discoveries/{uuid4()}")
        assert get_resp.status_code == 404


class TestInternalApiRenewProxyCert:
    """Tests for POST /internal/v1/proxies/<uuid:proxy_id>/renew-cert."""

    def test_renew_proxy_not_found(self, orch_client: FlaskClient) -> None:
        resp = orch_client.post(f"/internal/v1/proxies/{uuid4()}/renew-cert")
        assert resp.status_code == 404

    def test_renew_proxy_success(self, orch_client: FlaskClient) -> None:
        import datetime
        from embervault_db.models.proxy import Proxy
        from embervault_db.repositories.proxy_repository import ProxyRepository

        session_factory = orch_client.application.config["SESSION_FACTORY"]
        pid = uuid4()
        with session_factory() as session:
            tok = ProxyRepository.encrypt_token("tok" * 15, pid)
            p = Proxy(
                id=pid,
                name="Proxy-To-Renew",
                host="127.0.0.1",
                port=8443,
                token_encrypted=tok,
                cert_fingerprint_sha256="aa" * 32,
                is_enabled=True,
            )
            session.add(p)
            session.commit()

        exp_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=90)
        mock_client = MagicMock(spec=ProxyClient)
        mock_client.renew_certificate.return_value = {
            "status": "ok",
            "message": "Certificate renewed",
            "cert_fingerprint": "bb" * 32,
            "cert_expires_at": exp_dt.isoformat(),
        }
        set_proxy_client(mock_client)

        resp = orch_client.post(f"/internal/v1/proxies/{pid}/renew-cert")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert data["cert_fingerprint"] == "bb" * 32

        # Verify DB updated
        with session_factory() as session:
            session.expire_all()
            db_p = session.get(Proxy, pid)
            assert db_p is not None
            assert db_p.cert_expires_at is not None
            assert db_p.status is not None
            assert db_p.status.state == "untrusted"


class TestInternalApiPublicShares:
    """Tests for /internal/v1/public-shares/validate and browse."""

    def test_validate_public_share(self, orch_client: FlaskClient) -> None:
        from datetime import UTC, datetime, timedelta
        from embervault_db.repositories.public_share_repository import PublicShareRepository
        from embervault_db.repositories.remote_repository import RemoteRepository

        session_factory = orch_client.application.config["SESSION_FACTORY"]
        with session_factory() as session:
            remote = RemoteRepository.create_remote(
                session=session,
                name="ShareRemoteTest",
                backend_type="local",
                raw_config={"path": "/tmp/test"},
            )
            session.commit()
            share, token, username, raw_password = PublicShareRepository.create_share(
                session=session,
                remote_id=remote.id,
                base_path="subfolder",
                username="shareuser",
                raw_password="TestPassword123!",
                expires_at=datetime.now(UTC) + timedelta(hours=72),
            )
            session.commit()

        # Valid credentials
        res = orch_client.post(
            "/internal/v1/public-shares/validate",
            json={
                "token": token,
                "username": username,
                "password": raw_password,
            },
        )
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "ok"
        assert data["token"] == token
        assert data["remote_name"] == "ShareRemoteTest"
        assert data["base_path"] == "subfolder"
        assert data["first_accessed_at"] is not None

        # Verify first_accessed_at was recorded in DB
        with session_factory() as session:
            s_db = PublicShareRepository.get_share_by_token(session, token)
            assert s_db is not None
            assert s_db.first_accessed_at is not None

        # Invalid password
        bad_res = orch_client.post(
            "/internal/v1/public-shares/validate",
            json={
                "token": token,
                "username": username,
                "password": "wrongpassword",
            },
        )
        assert bad_res.status_code == 401

        # Deactivated share returns 410
        with session_factory() as session:
            PublicShareRepository.deactivate_share(session, share.id)
            session.commit()

        deact_res = orch_client.post(
            "/internal/v1/public-shares/validate",
            json={
                "token": token,
                "username": username,
                "password": raw_password,
            },
        )
        assert deact_res.status_code == 410

    def test_public_shares_branding_endpoint(self, orch_client: FlaskClient) -> None:
        from embervault_db.settings_store import SettingsStore

        # Default branding
        res = orch_client.get("/internal/v1/public-shares/branding")
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "ok"
        assert data["enabled"] is True
        assert data["language"] == "en"
        assert data["app_name"] == "EmberVault public portal"
        assert data["custom_app_name"] == ""
        assert data["has_custom_logo"] is False
        assert data["logo_data"] is None

        # Update settings store
        app = orch_client.application
        session_factory = app.config["SESSION_FACTORY"]
        store = app.config.get("SETTINGS_STORE")
        if not store:
            store = SettingsStore(session_factory)
            app.config["SETTINGS_STORE"] = store
        store.set_setting("portal_custom_app_name", "Acme Portal")
        store.set_setting("portal_custom_logo", "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=")
        store.set_setting("public_portal_enabled", False)
        store.set_setting("portal_language", "fr")

        res2 = orch_client.get("/internal/v1/public-shares/branding")
        assert res2.status_code == 200
        data2 = res2.get_json()
        assert data2["enabled"] is False
        assert data2["language"] == "fr"
        assert data2["app_name"] == "Acme Portal"
        assert data2["custom_app_name"] == "Acme Portal"
        assert data2["has_custom_logo"] is True
        assert data2["logo_data"] == "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4="

        # Validate returns 403 when portal is disabled
        res_val = orch_client.post(
            "/internal/v1/public-shares/validate",
            json={"token": "any", "username": "u", "password": "p"},
        )
        assert res_val.status_code == 403
        assert "disattivato" in res_val.get_json()["message"]
