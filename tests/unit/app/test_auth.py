"""Unit tests for M1.1 Local Authentication, Session Management, and RBAC."""

from __future__ import annotations

import pytest
from flask import Flask
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.auth import (
    LoginRateLimiter,
    authenticate_user,
)
from embervault_app.factory import create_app
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_common.security.passwords import verify_password
from embervault_db.models import Base, User
from embervault_db.seed import seed_initial_data


@pytest.fixture
def test_app_and_db() -> tuple[Flask, sessionmaker[Session]]:
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    # Seed roles, permissions, and admin user
    with session_factory() as db:
        seed_initial_data(db)

    settings = AppSettings(app_port=8080, dev_noauth=False)
    app = create_app(settings=settings, session_factory=session_factory)
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False  # Tested separately
    return app, session_factory


def test_authenticate_user_success(test_app_and_db: tuple[Flask, sessionmaker[Session]]) -> None:
    app, session_factory = test_app_and_db
    with app.app_context(), session_factory() as db:
        user, err = authenticate_user(db, "admin", "admin")
        assert err is None
        assert user is not None
        assert user.username == "admin"
        assert user.last_login_at is not None


def test_authenticate_user_failure(test_app_and_db: tuple[Flask, sessionmaker[Session]]) -> None:
    app, session_factory = test_app_and_db
    with app.app_context(), session_factory() as db:
        # Wrong password
        user, err = authenticate_user(db, "admin", "wrong_password")
        assert user is None
        assert err in ("Nome utente o password non validi.", "Invalid username or password.")

        # Non-existent username
        user, err = authenticate_user(db, "nobody", "password")
        assert user is None
        assert err in ("Nome utente o password non validi.", "Invalid username or password.")


def test_login_rate_limiter() -> None:
    limiter = LoginRateLimiter(max_attempts=3, window_seconds=60)
    key = "127.0.0.1:test_user"

    assert limiter.is_locked(key)[0] is False
    limiter.record_failure(key)
    limiter.record_failure(key)
    assert limiter.is_locked(key)[0] is False

    limiter.record_failure(key)  # 3rd failure = locked
    is_locked, remaining = limiter.is_locked(key)
    assert is_locked is True
    assert remaining > 0

    # Reset on success
    limiter.record_success(key)
    assert limiter.is_locked(key)[0] is False


def test_login_get_form(test_app_and_db: tuple[Flask, sessionmaker[Session]]) -> None:
    app, _ = test_app_and_db
    client = app.test_client()

    res = client.get("/login")
    assert res.status_code == 200
    assert "EmberVault" in res.text
    assert 'name="username"' in res.text
    assert 'name="password"' in res.text


def test_login_post_success_and_logout(
    test_app_and_db: tuple[Flask, sessionmaker[Session]],
) -> None:
    app, session_factory = test_app_and_db
    client = app.test_client()

    # Admin was seeded with must_change_password=True, so login should redirect to /change-password
    login_res = client.post("/login", data={"username": "admin", "password": "admin"})
    assert login_res.status_code == 302
    assert "/change-password" in login_res.headers["Location"]

    # Verify session cookie was set
    with client.session_transaction() as sess:
        assert "auth_token" in sess
        assert "user_id" in sess

    # Logout
    logout_res = client.post("/logout")
    assert logout_res.status_code == 302
    assert "/login" in logout_res.headers["Location"]

    with client.session_transaction() as sess:
        assert "auth_token" not in sess


def test_login_json_api(test_app_and_db: tuple[Flask, sessionmaker[Session]]) -> None:
    app, _ = test_app_and_db
    client = app.test_client()

    # Success JSON
    res = client.post(
        "/login",
        json={"username": "admin", "password": "admin"},
        headers={"Content-Type": "application/json"},
    )
    assert res.status_code == 200
    data = res.json
    assert data is not None
    assert data["status"] == "success"
    assert data["user"]["username"] == "admin"
    assert "token" in data

    # Failure JSON
    fail_res = client.post(
        "/login",
        json={"username": "admin", "password": "bad"},
        headers={"Content-Type": "application/json"},
    )
    assert fail_res.status_code == 401
    fail_data = fail_res.json
    assert fail_data is not None
    assert fail_data["status"] == "error"


def test_change_password_flow(test_app_and_db: tuple[Flask, sessionmaker[Session]]) -> None:
    app, session_factory = test_app_and_db
    client = app.test_client()

    # 1. Login as admin
    client.post("/login", data={"username": "admin", "password": "admin"})

    # 2. Change password with mismatch -> 400
    mismatch_res = client.post(
        "/change-password",
        data={
            "current_password": "admin",
            "new_password": "NewSecretPassword123!",
            "confirm_password": "DifferentPassword123!",
        },
    )
    assert mismatch_res.status_code == 400

    # 3. Change password with too short password -> 400
    short_res = client.post(
        "/change-password",
        data={
            "current_password": "admin",
            "new_password": "short",
            "confirm_password": "short",
        },
    )
    assert short_res.status_code == 400

    # 4. Valid password change
    success_res = client.post(
        "/change-password",
        data={
            "current_password": "admin",
            "new_password": "NewSecretPassword123!",
            "confirm_password": "NewSecretPassword123!",
        },
    )
    assert success_res.status_code == 302
    assert success_res.headers["Location"].endswith("/")

    # 5. Verify new password in DB
    with session_factory() as db:
        admin = db.scalar(select(User).where(User.username == "admin"))
        assert admin is not None
        assert admin.must_change_password is False
        assert verify_password(admin.password_hash or "", "NewSecretPassword123!") is True
        assert verify_password(admin.password_hash or "", "admin") is False


def test_require_auth_redirects_unauthenticated(
    test_app_and_db: tuple[Flask, sessionmaker[Session]],
) -> None:
    app, _ = test_app_and_db
    client = app.test_client()

    # Direct access to protected dashboard should redirect to /login
    res = client.get("/")
    assert res.status_code == 302
    assert "/login" in res.headers["Location"]
    assert "next=" in res.headers["Location"]

    # Direct access to protected JSON API returns 401
    json_res = client.get("/api/ui/status", headers={"Accept": "application/json"})
    assert json_res.status_code in (302, 401)


def test_authenticated_admin_can_probe_and_register_in_prod(
    test_app_and_db: tuple[Flask, sessionmaker[Session]],
) -> None:
    app, session_factory = test_app_and_db
    client = app.test_client()

    # Login as admin
    client.post("/login", data={"username": "admin", "password": "admin"})

    # Update password so must_change_password is False
    client.post(
        "/change-password",
        data={
            "current_password": "admin",
            "new_password": "Password123456!",
            "confirm_password": "Password123456!",
        },
    )

    # Now in prod mode (dev_noauth=False), authenticated admin CAN register proxy!
    reg_res = client.post(
        "/api/ui/proxies/register",
        json={
            "name": "prod-proxy-alpha",
            "host": "192.168.1.100",
            "port": 8443,
            "token": "secret_token_at_least_32_characters_long",
            "cert_fingerprint_sha256": "c" * 64,
        },
    )
    assert reg_res.status_code == 201
    reg_data = reg_res.json
    assert reg_data is not None
    assert reg_data["status"] == "created"


def test_dev_noauth_logout_prevents_auto_login() -> None:
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    with session_factory() as db:
        seed_initial_data(db)

    settings = AppSettings(app_port=8080, dev_noauth=True)
    app = create_app(settings=settings, session_factory=session_factory)
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    client = app.test_client()

    # 1. Unauthenticated request in dev_noauth auto-authenticates as admin
    res1 = client.get("/")
    assert res1.status_code == 200
    assert "banner-security-admin" in res1.text

    # 2. Explicit logout
    logout_res = client.post("/logout")
    assert logout_res.status_code == 302
    assert "/login" in logout_res.headers["Location"]

    # 3. Subsequent request to /login should NOT auto-redirect to dashboard because logged_out=True
    login_get_res = client.get("/login")
    assert login_get_res.status_code == 200

    # 4. Subsequent request to protected route redirects to /login
    protected_res = client.get("/")
    assert protected_res.status_code == 302
    assert "/login" in protected_res.headers["Location"]

    # 5. Logging in again clears logged_out flag
    login_post = client.post("/login", data={"username": "admin", "password": "admin"})
    assert login_post.status_code == 302
    res_after_login = client.get("/")
    assert res_after_login.status_code == 200


def test_login_page_styling_and_labels(
    test_app_and_db: tuple[Flask, sessionmaker[Session]],
) -> None:
    """Verify login page labels, absence of subtitle, and footer branding."""
    app, session_factory = test_app_and_db
    client = app.test_client()

    # Enable LDAP in settings to test LDAP/AD tab
    from embervault_app.ldap_service import save_ldap_config

    save_ldap_config(
        session=app.config["SETTINGS_STORE"],
        data={"ldap_enabled": True, "ldap_server_url": "ldaps://dc.test.local:636"},
    )

    res = client.get("/login")
    assert res.status_code == 200
    # Must NOT have old subtitle
    assert "Autenticazione richiesta per accedere alla piattaforma" not in res.text
    # Label should be shortened to LDAP/AD
    assert "<span>LDAP/AD</span>" in res.text
    assert "Directory LDAP / AD" not in res.text
    # Footer should be shortened to EmberVault © 2026
    assert "EmberVault &copy; 2026" in res.text
    assert "Distributed Backup Platform" not in res.text
    # Without custom bg, has-custom-bg should not be in body class
    assert 'class="login-page has-custom-bg"' not in res.text


def test_login_custom_background_api_and_rendering(
    test_app_and_db: tuple[Flask, sessionmaker[Session]],
) -> None:
    """Verify upload, retrieval, deletion of custom login background, and template integration."""
    app, session_factory = test_app_and_db
    client = app.test_client()

    # 1. Initially no custom background -> 404
    bg_res = client.get("/api/ui/settings/login-background")
    assert bg_res.status_code == 404

    # 2. Login as admin to upload
    with session_factory() as db:
        user = db.scalar(select(User).where(User.username == "admin"))
        user.must_change_password = False
        db.commit()

    login_res = client.post("/login", data={"username": "admin", "password": "admin"})
    assert login_res.status_code == 302

    # 3. Upload background via POST (JSON data URI)
    dummy_png_data_uri = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
    post_res = client.post("/api/ui/settings/login-background", json={"image": dummy_png_data_uri})
    assert post_res.status_code == 200
    assert post_res.json["status"] == "ok"

    # 4. GET /api/ui/settings/login-background returns 200 and image/png
    get_res = client.get("/api/ui/settings/login-background")
    assert get_res.status_code == 200
    assert get_res.headers["Content-Type"] == "image/png"
    assert len(get_res.data) > 0

    # 5. /login now has has-custom-bg in body class
    client.post("/logout")
    login_page_res = client.get("/login")
    assert 'class="login-page has-custom-bg"' in login_page_res.text

    # 6. Re-login and DELETE background
    client.post("/login", data={"username": "admin", "password": "admin"})
    del_res = client.delete("/api/ui/settings/login-background")
    assert del_res.status_code == 200
    assert del_res.json["status"] == "ok"

    # 7. GET /api/ui/settings/login-background returns 404 again
    assert client.get("/api/ui/settings/login-background").status_code == 404

    # 8. /login now lacks has-custom-bg in body class
    client.post("/logout")
    assert 'class="login-page has-custom-bg"' not in client.get("/login").text
