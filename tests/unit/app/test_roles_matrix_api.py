"""Unit tests for roles and permissions matrix API endpoints."""

from __future__ import annotations

import uuid
from typing import Any
import pytest
from flask import Flask
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.factory import create_app
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import Base
from embervault_db.repositories.user_repository import UserRepository
from embervault_db.seed import seed_initial_data


@pytest.fixture
def test_app_and_db() -> tuple[Flask, sessionmaker[Session]]:
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    with session_factory() as db:
        seed_initial_data(db)

    settings = AppSettings(app_port=8080, dev_noauth=False)
    app = create_app(settings=settings, session_factory=session_factory)
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app, session_factory


def _setup_active_admin(client: Any) -> None:
    client.post("/login", data={"username": "admin", "password": "admin"}, follow_redirects=False)
    client.post(
        "/change-password",
        data={
            "current_password": "admin",
            "new_password": "SuperAdminPass123!",
            "confirm_password": "SuperAdminPass123!",
        },
        follow_redirects=False,
    )


def test_roles_matrix_api_lifecycle(test_app_and_db: tuple[Flask, sessionmaker[Session]]) -> None:
    """Test full API lifecycle for custom roles and permissions matrix."""
    app, session_factory = test_app_and_db
    client = app.test_client()
    _setup_active_admin(client)

    # 1. GET /api/ui/roles/matrix
    matrix_resp = client.get("/api/ui/roles/matrix")
    assert matrix_resp.status_code == 200
    m_data = matrix_resp.get_json()
    assert "roles" in m_data
    assert "categories" in m_data
    assert "matrix" in m_data

    # Verify built-in roles in matrix
    names = [r["name"] for r in m_data["roles"]]
    assert "Administrator" in names
    assert "Operator" in names
    assert "Viewer" in names

    # 2. POST /api/ui/roles (Create custom role)
    create_resp = client.post(
        "/api/ui/roles",
        json={
            "name": "Cloud Backup Auditor",
            "description": "Solo lettura log e metriche",
            "permissions": ["job.read", "remote.read", "audit.read"],
        },
    )
    assert create_resp.status_code == 201
    created = create_resp.get_json()["role"]
    assert created["name"] == "Cloud Backup Auditor"
    assert created["is_system"] is False
    assert len(created["permissions"]) == 3
    new_role_id = created["id"]

    # 3. GET /api/ui/roles/<id>
    get_resp = client.get(f"/api/ui/roles/{new_role_id}")
    assert get_resp.status_code == 200
    assert get_resp.get_json()["name"] == "Cloud Backup Auditor"

    # 4. POST /api/ui/roles/<id>/permissions/<code_or_full>/toggle (Enable 2FA mandatory)
    toggle_resp = client.post(
        f"/api/ui/roles/{new_role_id}/permissions/auth.enforce_2fa/toggle",
        json={"enabled": True},
    )
    assert toggle_resp.status_code == 200
    t_data = toggle_resp.get_json()
    assert t_data["permission_code"] == "auth.enforce_2fa"
    assert t_data["enabled"] is True
    assert t_data["enforce_2fa"] is True

    # 5. PUT /api/ui/roles/<id> (Update name and description)
    put_resp = client.put(
        f"/api/ui/roles/{new_role_id}",
        json={"name": "Senior Cloud Auditor", "description": "Aggiornato"},
    )
    assert put_resp.status_code == 200
    assert put_resp.get_json()["role"]["name"] == "Senior Cloud Auditor"

    # 6. DELETE /api/ui/roles/<id> (Delete custom role)
    del_resp = client.delete(f"/api/ui/roles/{new_role_id}")
    assert del_resp.status_code == 200
    assert del_resp.get_json()["status"] == "deleted"

    # Verify not found after deletion
    get_after = client.get(f"/api/ui/roles/{new_role_id}")
    assert get_after.status_code == 404
