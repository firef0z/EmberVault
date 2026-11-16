"""Unit tests for M2 Role-Based Access Control (RBAC), User Management & Audit Logging."""

from __future__ import annotations

import pytest
from flask import Flask
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.factory import create_app
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_common.security.passwords import verify_password
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


def _login(client, username: str, password: str = "Password123456!") -> None:
    client.post("/login", data={"username": username, "password": password})


def _setup_active_admin(client) -> None:
    # Login admin, update password
    client.post("/login", data={"username": "admin", "password": "admin"})
    client.post(
        "/change-password",
        data={
            "current_password": "admin",
            "new_password": "Password123456!",
            "confirm_password": "Password123456!",
        },
    )


def test_user_repository_crud(test_app_and_db: tuple[Flask, sessionmaker[Session]]) -> None:
    _, session_factory = test_app_and_db
    with session_factory() as db:
        # List users
        users = UserRepository.list_users(db)
        assert len(users) == 1
        assert users[0].username == "admin"

        # List roles
        roles = UserRepository.list_roles(db)
        assert len(roles) == 3
        role_map = {r.name.lower(): r for r in roles}
        assert "admin" in role_map or "administrator" in role_map
        assert "operator" in role_map
        assert "viewer" in role_map

        # Create user
        new_user = UserRepository.create_user(
            db,
            username="test_op",
            password="TestPassword123!",
            role_id=role_map["operator"].id,
            must_change_password=True,
            actor_user_id=None,
        )
        assert new_user.id is not None
        assert new_user.username == "test_op"
        assert new_user.role_id == role_map["operator"].id
        assert new_user.must_change_password is True
        assert verify_password(new_user.password_hash or "", "TestPassword123!") is True

        # Check audit log was created
        audit_logs = UserRepository.list_audit_logs(db)
        assert any(log.action == "user.create" for log in audit_logs)

        # Update user
        updated = UserRepository.update_user(
            db,
            user_id=new_user.id,
            role_id=role_map["viewer"].id,
            is_active=False,
            actor_user_id=None,
        )
        assert updated is not None
        assert updated.role_id == role_map["viewer"].id
        assert updated.is_active is False

        # Attempt to delete last admin should fail
        admin_user = UserRepository.get_user_by_username(db, "admin")
        assert admin_user is not None
        with pytest.raises(ValueError, match="Impossibile eliminare"):
            UserRepository.delete_user(db, admin_user.id, actor_user_id=admin_user.id)

        # Attempt to deactivate last admin should fail
        with pytest.raises(ValueError, match="Impossibile disattivare"):
            UserRepository.update_user(db, admin_user.id, is_active=False)

        # Add MFA factor and recovery codes to new_user to verify cascade on deletion
        from embervault_db.models.auth import UserMfaFactor, UserRecoveryCode
        from embervault_db.models.base import utc_now

        mfa = UserMfaFactor(
            user_id=new_user.id,
            type="totp",
            secret_encrypted=b"encrypted_totp_secret",
            label="Authenticator App",
            confirmed_at=utc_now(),
        )
        rc = UserRecoveryCode(
            user_id=new_user.id,
            code_hash="recovery_code_hash",
        )
        db.add(mfa)
        db.add(rc)
        db.flush()

        # Delete new_user with MFA attached (should cascade and delete without NotNullViolation)
        success = UserRepository.delete_user(db, new_user.id, actor_user_id=None)
        assert success is True
        assert UserRepository.get_user_by_id(db, new_user.id) is None
        assert db.scalar(select(UserMfaFactor).where(UserMfaFactor.user_id == new_user.id)) is None
        assert (
            db.scalar(select(UserRecoveryCode).where(UserRecoveryCode.user_id == new_user.id))
            is None
        )


def test_users_api_endpoints_rbac(test_app_and_db: tuple[Flask, sessionmaker[Session]]) -> None:
    app, session_factory = test_app_and_db
    client = app.test_client()

    _setup_active_admin(client)

    # 1. Admin creates an operator user
    with session_factory() as db:
        op_role = UserRepository.get_role_by_name(db, "operator")
        viewer_role = UserRepository.get_role_by_name(db, "viewer")
        assert op_role is not None
        assert viewer_role is not None
        op_role_id = str(op_role.id)
        viewer_role_id = str(viewer_role.id)

    res = client.post(
        "/api/ui/users",
        json={
            "username": "operator1",
            "password": "OperatorPass123!",
            "role_id": op_role_id,
            "must_change_password": False,
        },
    )
    assert res.status_code == 201
    created_op = res.json["user"]
    op_user_id = created_op["id"]

    # 2. Admin creates a viewer user
    res = client.post(
        "/api/ui/users",
        json={
            "username": "viewer1",
            "password": "ViewerPass123!",
            "role_id": viewer_role_id,
            "must_change_password": False,
        },
    )
    assert res.status_code == 201

    # 3. List users as Admin
    list_res = client.get("/api/ui/users")
    assert list_res.status_code == 200
    usernames = [u["username"] for u in list_res.json["users"]]
    assert "admin" in usernames
    assert "operator1" in usernames
    assert "viewer1" in usernames

    # 4. Logout admin and login as viewer1
    client.get("/logout")
    _login(client, "viewer1", "ViewerPass123!")

    # Viewer CANNOT access user management API (requires user.read / user.manage)
    # Viewer does NOT have user.manage or user.read
    v_users = client.get("/api/ui/users")
    assert v_users.status_code == 403

    v_post = client.post(
        "/api/ui/users",
        json={
            "username": "hacker",
            "password": "HackerPass123!",
            "role_id": viewer_role_id,
        },
    )
    assert v_post.status_code == 403

    # Viewer CAN view dashboard and runs (has job.read)
    v_runs = client.get("/runs")
    assert v_runs.status_code == 200

    # Viewer CANNOT trigger a run or write remote (requires job.write / remote.write)
    v_new_remote = client.get("/remotes/new")
    assert v_new_remote.status_code == 403

    # 5. Logout and login as operator1
    client.get("/logout")
    _login(client, "operator1", "OperatorPass123!")

    # Operator has job.read, job.run, job.write, remote.read, remote.write, proxy.read, proxy.manage, user.read, audit.read
    # Operator CAN view remotes and create new remotes
    op_remotes = client.get("/remotes")
    assert op_remotes.status_code == 200

    op_new_remote = client.get("/remotes/new")
    assert op_new_remote.status_code == 200

    # Operator CAN view and run jobs
    op_jobs = client.get("/jobs")
    assert op_jobs.status_code == 200

    # Operator CAN view users list (has user.read)
    op_users = client.get("/api/ui/users")
    assert op_users.status_code == 200

    # Operator CAN edit their own user profile
    op_self_edit_page = client.get(f"/users/{op_user_id}/edit")
    assert op_self_edit_page.status_code == 200

    op_self_update = client.put(
        f"/api/ui/users/{op_user_id}",
        json={"display_name": "Updated Operator Name"},
    )
    assert op_self_update.status_code == 200

    # Operator CANNOT edit OTHER users
    with session_factory() as db:
        admin_id = str(UserRepository.get_user_by_username(db, "admin").id)
    op_edit_admin = client.get(f"/users/{admin_id}/edit")
    assert op_edit_admin.status_code == 403

    op_update_admin = client.put(
        f"/api/ui/users/{admin_id}",
        json={"display_name": "Hacked Name"},
    )
    assert op_update_admin.status_code == 403

    # Operator does NOT have user.manage (cannot delete user or create new user)
    op_del_user = client.delete(f"/api/ui/users/{op_user_id}")
    assert op_del_user.status_code == 403

    op_new_user = client.get("/users/new")
    assert op_new_user.status_code == 403

    # Operator does NOT have settings.read or settings.write
    with session_factory() as db:
        user_op = UserRepository.get_user_by_username(db, "operator1")
        op_perm_codes = {p.code for p in user_op.role.permissions}
        assert "settings.read" not in op_perm_codes
        assert "settings.write" not in op_perm_codes

    # Operator cannot access /settings (menu hidden and route forbidden)
    op_settings_res = client.get("/settings")
    assert op_settings_res.status_code == 403


def test_user_password_complexity_and_duplicate(
    test_app_and_db: tuple[Flask, sessionmaker[Session]],
) -> None:
    app, session_factory = test_app_and_db
    client = app.test_client()
    _setup_active_admin(client)

    with session_factory() as db:
        role = UserRepository.get_role_by_name(db, "viewer")
        assert role is not None
        role_id = str(role.id)

    # Short password
    res = client.post(
        "/api/ui/users",
        json={
            "username": "shorty",
            "password": "123",
            "role_id": role_id,
        },
    )
    assert res.status_code == 400
    assert "almeno 8 caratteri" in res.json["message"]

    # Valid user creation
    res = client.post(
        "/api/ui/users",
        json={
            "username": "valid_user",
            "password": "ValidPassword123!",
            "role_id": role_id,
        },
    )
    assert res.status_code == 201

    # Duplicate username
    res_dup = client.post(
        "/api/ui/users",
        json={
            "username": "valid_user",
            "password": "AnotherPassword123!",
            "role_id": role_id,
        },
    )
    assert res_dup.status_code == 400
    assert "già esistente" in res_dup.json["message"]


def test_user_theme_crud_and_propagation(
    test_app_and_db: tuple[Flask, sessionmaker[Session]],
) -> None:
    app, session_factory = test_app_and_db
    client = app.test_client()
    _setup_active_admin(client)

    with session_factory() as db:
        role = UserRepository.get_role_by_name(db, "operator")
        assert role is not None
        role_id = str(role.id)

    # 1. Create user with default theme (embervault)
    res = client.post(
        "/api/ui/users",
        json={
            "username": "theme_user_default",
            "password": "ValidPassword123!",
            "role_id": role_id,
        },
    )
    assert res.status_code == 201
    user_data = res.json["user"]
    assert user_data["theme"] == "embervault"
    user_id = user_data["id"]

    # 2. Update user with each of the 4 new themes: theeame, acrovault, emberxp, iembervault
    for theme_name in ["theeame", "acrovault", "emberxp", "iembervault"]:
        res_update = client.put(
            f"/api/ui/users/{user_id}",
            json={
                "theme": theme_name,
            },
        )
        assert res_update.status_code == 200
        assert res_update.json["user"]["theme"] == theme_name

    # 3. Invalid theme should return 400
    res_invalid = client.put(
        f"/api/ui/users/{user_id}",
        json={
            "theme": "invalid_theme_xyz",
        },
    )
    assert res_invalid.status_code == 400
    assert "non valido" in res_invalid.json["message"]

    # 4. Login with the user whose theme is now 'iembervault', verify session & base template attribute
    # First disable must_change_password for theme_user_default
    with session_factory() as db:
        u = UserRepository.get_user_by_username(db, "theme_user_default")
        assert u is not None
        UserRepository.update_user(db, user_id=u.id, must_change_password=False)

    user_client = app.test_client()
    login_res = user_client.post(
        "/login",
        data={"username": "theme_user_default", "password": "ValidPassword123!"},
        follow_redirects=True,
    )
    assert login_res.status_code == 200

    # Inspect rendered HTML to confirm data-color-theme="iembervault" is present
    dashboard_res = user_client.get("/")
    assert dashboard_res.status_code == 200
    html_text = dashboard_res.data.decode("utf-8")
    assert 'data-color-theme="iembervault"' in html_text


def test_emberxp_and_iembervault_dark_mode_and_theme_toggle(
    test_app_and_db: tuple[Flask, sessionmaker[Session]],
) -> None:
    """EmberXP and iEmberVault expose the theme switcher and dark-mode CSS/SVG assets."""
    import re
    from embervault_db.models import User

    app, session_factory = test_app_and_db
    client = app.test_client()
    _setup_active_admin(client)

    for theme_name in ("emberxp", "iembervault"):
        with session_factory() as db:
            admin = db.scalar(select(User).where(User.username == "admin"))
            assert admin is not None
            admin.theme = theme_name
            db.commit()

        # Dark mode (explicit cookie) renders theme without data-theme="light" and keeps #theme-toggle
        client.set_cookie("embervault_mode", "dark")
        dark_res = client.get("/")
        assert dark_res.status_code == 200
        dark_html = dark_res.data.decode("utf-8")
        assert f'data-color-theme="{theme_name}"' in dark_html
        assert 'data-theme="light"' not in dark_html
        assert 'id="theme-toggle"' in dark_html

        # Light mode cookie renders data-theme="light" and keeps #theme-toggle
        client.set_cookie("embervault_mode", "light")
        light_res = client.get("/")
        assert light_res.status_code == 200
        light_html = light_res.data.decode("utf-8")
        assert f'data-color-theme="{theme_name}"' in light_html
        assert 'data-theme="light"' in light_html
        assert 'id="theme-toggle"' in light_html

    # Login page serves dark rules for both EmberXP and iEmberVault
    anon_client = app.test_client()
    login_res = anon_client.get("/login")
    assert login_res.status_code == 200
    login_html = login_res.data.decode("utf-8")
    assert 'html[data-color-theme="emberxp"]:not([data-theme="light"])' in login_html
    assert 'html[data-color-theme="iembervault"]:not([data-theme="light"])' in login_html
    assert "/static/img/bliss-dark.svg" in login_html
    assert "/static/img/aqua-wallpaper-dark.svg" in login_html

    # App stylesheet restores #theme-toggle visibility and serves dark-mode rules/assets
    css_res = client.get("/static/css/app.css")
    assert css_res.status_code == 200
    css_text = css_res.data.decode("utf-8")
    assert not re.search(
        r'html\[data-color-theme="(?:emberxp|iembervault)"\]\s*#theme-toggle\s*\{[^}]*display:\s*none',
        css_text,
    )
    assert 'html[data-color-theme="emberxp"]:not([data-theme="light"])' in css_text
    assert "/static/img/bliss-dark.svg" in css_text
    assert 'html[data-color-theme="iembervault"]:not([data-theme="light"])' in css_text
    assert "/static/img/aqua-wallpaper-dark.svg" in css_text
    assert "/static/img/aqua-traffic-lights-inactive-dark.svg" in css_text

    for svg_path, marker in (
        ("/static/img/bliss-dark.svg", "skyGrad"),
        ("/static/img/aqua-wallpaper-dark.svg", "waveGrad1"),
        ("/static/img/aqua-traffic-lights-inactive-dark.svg", "darkGumdrop"),
    ):
        asset_res = client.get(svg_path)
        assert asset_res.status_code == 200
        svg_text = asset_res.data.decode("utf-8")
        assert "<svg" in svg_text
        assert marker in svg_text
