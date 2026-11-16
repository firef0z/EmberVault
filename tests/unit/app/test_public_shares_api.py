"""Unit tests for Public Shares App API endpoints."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
import pytest
from flask.testing import FlaskClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.factory import create_app
from embervault_app.orchestrator_client import OrchestratorClient
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import Base
from embervault_db.repositories.remote_repository import RemoteRepository
from embervault_db.seed import seed_initial_data


class FakeOrchestrator(OrchestratorClient):
    pass


@pytest.fixture
def app_and_db() -> tuple[FlaskClient, sessionmaker[Session]]:
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    with session_factory() as session:
        seed_initial_data(session)

    settings = AppSettings(app_port=8080, dev_noauth=True)
    fake_orch = FakeOrchestrator()
    app = create_app(
        settings=settings,
        session_factory=session_factory,
        orchestrator_client=fake_orch,
    )
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app.test_client(), session_factory


def test_public_shares_crud_lifecycle(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    client, session_factory = app_and_db

    # 1. Create a remote first
    with session_factory() as session:
        remote = RemoteRepository.create_remote(
            session=session,
            name="RemotePublicTest",
            backend_type="local",
            raw_config={"path": "/tmp/test"},
        )
        session.commit()
        remote_id = remote.id

    # 2. Create public share with default 72h expiration
    create_res = client.post(
        "/api/ui/public-shares",
        json={
            "remote_id": str(remote_id),
            "base_path": "folderb",
            "note": "Nota riservata per il cliente",
        },
    )
    assert create_res.status_code == 201
    created_data = create_res.json
    assert created_data["status"] == "ok"
    share_info = created_data["share"]
    assert share_info["remote_name"] == "RemotePublicTest"
    assert share_info["base_path"] == "folderb"
    assert share_info["note"] == "Nota riservata per il cliente"
    assert len(share_info["username"]) > 0
    assert len(share_info["password"]) >= 8
    assert "/share/" in share_info["url"]
    share_id = share_info["id"]

    # 3. List public shares
    list_res = client.get("/api/ui/public-shares")
    assert list_res.status_code == 200
    shares = list_res.json["shares"]
    assert len(shares) == 1
    assert shares[0]["id"] == share_id
    assert shares[0]["note"] == "Nota riservata per il cliente"
    assert shares[0]["is_active"] is True
    assert shares[0]["is_expired"] is False

    # 4. Update expiration (PATCH)
    new_exp = (datetime.now(UTC) + timedelta(days=7)).isoformat()
    patch_res = client.patch(
        f"/api/ui/public-shares/{share_id}",
        json={"expires_at": new_exp},
    )
    assert patch_res.status_code == 200
    assert patch_res.json["status"] == "ok"

    # Verify expiration updated
    list_res2 = client.get("/api/ui/public-shares")
    assert list_res2.status_code == 200
    updated_share = list_res2.json["shares"][0]
    assert "T" in updated_share["expires_at"]
    assert updated_share["first_accessed_at"] is None

    # 5. Deactivate public share (POST /deactivate)
    deact_res = client.post(f"/api/ui/public-shares/{share_id}/deactivate")
    assert deact_res.status_code == 200
    assert deact_res.json["status"] == "ok"
    assert deact_res.json["share"]["is_active"] is False

    # Verify listing shows deactivated
    list_res_deact = client.get("/api/ui/public-shares")
    assert list_res_deact.json["shares"][0]["is_active"] is False

    # Attempting to update expiration on deactivated share should fail
    patch_deact_res = client.patch(
        f"/api/ui/public-shares/{share_id}",
        json={"expires_at": new_exp},
    )
    assert patch_deact_res.status_code == 400

    # 6. Delete public share
    del_res = client.delete(f"/api/ui/public-shares/{share_id}")
    assert del_res.status_code == 200
    assert del_res.json["status"] == "ok"

    # Verify deleted
    list_res3 = client.get("/api/ui/public-shares")
    assert len(list_res3.json["shares"]) == 0


def test_public_shares_validation_and_security(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]],
) -> None:
    client, session_factory = app_and_db

    with session_factory() as session:
        remote = RemoteRepository.create_remote(
            session=session,
            name="SecurityTestRemote",
            backend_type="local",
            raw_config={"path": "/tmp/test"},
        )
        session.commit()
        remote_id = remote.id

    # 1. Past expiration date should fail
    past_exp = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    res_past = client.post(
        "/api/ui/public-shares",
        json={"remote_id": str(remote_id), "expires_at": past_exp},
    )
    assert res_past.status_code == 400

    # 2. Path traversal in base_path should fail
    res_traversal = client.post(
        "/api/ui/public-shares",
        json={"remote_id": str(remote_id), "base_path": "../../etc/shadow"},
    )
    assert res_traversal.status_code == 400

    # 3. Invalid remote id should fail
    res_invalid_remote = client.post(
        "/api/ui/public-shares",
        json={"remote_id": str(uuid.uuid4())},
    )
    assert res_invalid_remote.status_code == 404


def test_public_share_uses_configured_public_url(
    app_and_db: tuple[FlaskClient, sessionmaker[Session]], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, session_factory = app_and_db
    monkeypatch.setenv("EMBERVAULT_PUBLIC_URL", "https://embervault.azienda.it")

    with session_factory() as session:
        remote = RemoteRepository.create_remote(
            session=session,
            name="RemoteUrlTest",
            backend_type="local",
            raw_config={"path": "/tmp/test"},
        )
        session.commit()
        remote_id = remote.id

    create_res = client.post(
        "/api/ui/public-shares",
        json={"remote_id": str(remote_id), "base_path": "docs"},
    )
    assert create_res.status_code == 201
    url = create_res.json["share"]["url"]
    assert url.startswith("https://embervault.azienda.it/share/")
