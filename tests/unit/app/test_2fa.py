"""Unit tests for Two-Factor Authentication (2FA/TOTP), recovery codes, and role enforcement (Milestone M3)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from flask import Flask
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.factory import create_app
from embervault_common.config import AppSettings
from embervault_common.security import (
    generate_recovery_codes,
    generate_totp_qr_svg,
    generate_totp_secret,
    hash_recovery_code,
    normalize_recovery_code,
    verify_totp_code,
)
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


if TYPE_CHECKING:
    pass


def _login(client: Any, username: str, password: str) -> Any:
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


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


def test_totp_generation_and_verification():
    """Verify standard TOTP generation, SVG QR output, and verification logic."""
    secret = generate_totp_secret()
    assert len(secret) == 32

    # SVG QR code generation
    svg = generate_totp_qr_svg(secret=secret, username="test_user")
    assert "<svg" in svg
    assert "</svg>" in svg

    # Generate current code using pyotp
    import pyotp

    totp = pyotp.TOTP(secret)
    valid_code = totp.now()

    assert verify_totp_code(secret, valid_code) is True
    assert verify_totp_code(secret, "000000") is False
    assert verify_totp_code(secret, "invalid") is False


def test_recovery_codes_generation_and_hashing():
    """Verify recovery codes formatting, normalization, and hashing."""
    codes = generate_recovery_codes(10)
    assert len(codes) == 10
    for c in codes:
        assert len(c) == 12  # format: 'xxxx-xxxx-xx'
        assert "-" in c

    code = codes[0]
    norm = normalize_recovery_code(code)
    assert "-" not in norm
    assert " " not in norm

    hash1 = hash_recovery_code(code)
    hash2 = hash_recovery_code(norm)
    assert hash1 == hash2


def test_2fa_full_lifecycle_and_login_flow(
    test_app_and_db: tuple[Flask, sessionmaker[Session]],
):
    """Test full 2FA lifecycle: setup -> confirm -> 2FA login challenge -> recovery code fallback -> disable."""
    app, session_factory = test_app_and_db
    client = app.test_client()

    # 1. Admin login & password change
    _setup_active_admin(client)

    # 2. Check initial 2FA status
    status_resp = client.get("/api/ui/2fa/status")
    assert status_resp.status_code == 200
    status_data = status_resp.get_json()
    assert status_data["totp_enabled"] is False

    # 3. Setup TOTP (generates pending secret)
    setup_resp = client.post("/api/ui/2fa/setup")
    assert setup_resp.status_code == 200
    setup_data = setup_resp.get_json()
    raw_secret = setup_data["secret"]
    assert "<svg" in setup_data["qr_svg"]

    # 4. Confirm with invalid code fails
    fail_confirm = client.post("/api/ui/2fa/confirm", json={"code": "000000"})
    assert fail_confirm.status_code == 400

    # 5. Confirm with valid code succeeds and gives recovery codes
    import pyotp

    valid_code = pyotp.TOTP(raw_secret).now()
    confirm_resp = client.post("/api/ui/2fa/confirm", json={"code": valid_code})
    assert confirm_resp.status_code == 200
    confirm_data = confirm_resp.get_json()
    assert confirm_data["status"] == "confirmed"
    recovery_codes = confirm_data["recovery_codes"]
    assert len(recovery_codes) == 10

    # 6. Verify status now reports totp_enabled
    status_resp = client.get("/api/ui/2fa/status")
    assert status_resp.get_json()["totp_enabled"] is True
    assert status_resp.get_json()["remaining_recovery_codes"] == 10

    # 7. Logout
    client.get("/logout")

    # 8. Attempt login: should redirect to 2FA challenge
    login_resp = _login(client, "admin", "SuperAdminPass123!")
    assert login_resp.status_code == 302
    assert "/login/2fa" in login_resp.headers["Location"]

    # Attempting to access protected resource before completing 2FA must fail / redirect
    prot_resp = client.get("/remotes")
    assert prot_resp.status_code == 302
    assert "/login" in prot_resp.headers["Location"]

    # 9. Verify 2FA challenge with valid TOTP code
    code2 = pyotp.TOTP(raw_secret).now()
    mfa_verify_resp = client.post("/login/2fa", data={"code": code2}, follow_redirects=False)
    assert mfa_verify_resp.status_code == 302
    assert "/" in mfa_verify_resp.headers["Location"]

    # Now remotes is accessible
    remotes_resp = client.get("/remotes")
    assert remotes_resp.status_code == 200

    # 10. Logout and test login using a Recovery Code
    client.get("/logout")
    _login(client, "admin", "SuperAdminPass123!")

    # Use first recovery code
    used_rec_code = recovery_codes[0]
    rec_login_resp = client.post("/login/2fa", data={"code": used_rec_code}, follow_redirects=False)
    assert rec_login_resp.status_code == 302

    # Check recovery codes count reduced to 9
    status_resp = client.get("/api/ui/2fa/status")
    assert status_resp.get_json()["remaining_recovery_codes"] == 9

    # Re-using the same recovery code must fail
    client.get("/logout")
    _login(client, "admin", "SuperAdminPass123!")
    fail_reuse = client.post("/login/2fa", data={"code": used_rec_code}, follow_redirects=False)
    assert fail_reuse.status_code == 401

    # Login with valid TOTP again
    code3 = pyotp.TOTP(raw_secret).now()
    client.post("/login/2fa", data={"code": code3}, follow_redirects=False)

    # 10. Reconfiguring active 2FA without credentials fails
    fail_reconfig_no_creds = client.post("/api/ui/2fa/setup", json={})
    assert fail_reconfig_no_creds.status_code == 400
    assert "password" in fail_reconfig_no_creds.get_json()["message"].lower()

    # Reconfiguring active 2FA with wrong password fails
    fail_reconfig_wrong_pwd = client.post(
        "/api/ui/2fa/setup",
        json={"password": "WrongPassword", "code": pyotp.TOTP(raw_secret).now()},
    )
    assert fail_reconfig_wrong_pwd.status_code == 400

    # Reconfiguring active 2FA with correct password and valid TOTP code succeeds
    ok_reconfig = client.post(
        "/api/ui/2fa/setup",
        json={"password": "SuperAdminPass123!", "code": pyotp.TOTP(raw_secret).now()},
    )
    assert ok_reconfig.status_code == 200
    assert "qr_png" in ok_reconfig.get_json()
    new_secret = ok_reconfig.get_json()["secret"]

    # Re-confirming with new secret works
    client.post("/api/ui/2fa/confirm", json={"code": pyotp.TOTP(new_secret).now()})
    raw_secret = new_secret

    # 11. Disable 2FA with incorrect password fails
    fail_disable = client.post(
        "/api/ui/2fa/disable",
        json={"password": "WrongPassword", "code": pyotp.TOTP(raw_secret).now()},
    )
    assert fail_disable.status_code == 400

    # 12. Disable 2FA without code fails
    fail_no_code = client.post("/api/ui/2fa/disable", json={"password": "SuperAdminPass123!"})
    assert fail_no_code.status_code == 400
    assert any(w in fail_no_code.get_json()["message"].lower() for w in ["codice", "code"])

    # 13. Disable 2FA with correct password and code succeeds
    ok_disable = client.post(
        "/api/ui/2fa/disable",
        json={"password": "SuperAdminPass123!", "code": pyotp.TOTP(raw_secret).now()},
    )
    assert ok_disable.status_code == 200
    assert ok_disable.get_json()["status"] == "disabled"

    # Status is now disabled
    status_resp = client.get("/api/ui/2fa/status")
    assert status_resp.get_json()["totp_enabled"] is False


def test_role_2fa_enforcement(
    test_app_and_db: tuple[Flask, sessionmaker[Session]],
):
    """Test role-level mandatory 2FA enforcement."""
    app, session_factory = test_app_and_db
    client = app.test_client()

    _setup_active_admin(client)

    # Create an operator user
    with session_factory() as db:
        op_role = UserRepository.get_role_by_name(db, "operator")
        assert op_role is not None
        op_role_id = op_role.id

    create_user_resp = client.post(
        "/api/ui/users",
        json={
            "username": "op_enforce_test",
            "password": "OperatorPass123!",
            "role_id": str(op_role_id),
            "is_active": True,
            "must_change_password": False,
        },
    )
    assert create_user_resp.status_code == 201

    # Admin enforces 2FA on operator role
    enforce_resp = client.post(
        f"/api/ui/roles/{op_role_id}/enforce-2fa",
        json={"enforce_2fa": True},
    )
    assert enforce_resp.status_code == 200
    assert enforce_resp.get_json()["enforce_2fa"] is True

    # Logout admin and login as operator
    client.get("/logout")
    op_login = _login(client, "op_enforce_test", "OperatorPass123!")
    assert op_login.status_code == 302

    # Operator accessing /remotes or /jobs must be redirected to /2fa/setup because 2FA is enforced
    op_remotes = client.get("/remotes", follow_redirects=False)
    assert op_remotes.status_code == 302
    assert "/2fa/setup" in op_remotes.headers["Location"]

    # Operator setup page is accessible
    op_setup_page = client.get("/2fa/setup")
    assert op_setup_page.status_code == 200

    # Operator cannot disable 2FA once role enforces it
    # First setup 2FA for operator
    setup_resp = client.post("/api/ui/2fa/setup")
    secret = setup_resp.get_json()["secret"]
    import pyotp

    client.post("/api/ui/2fa/confirm", json={"code": pyotp.TOTP(secret).now()})

    # Now operator tries to disable 2FA -> Forbidden because role enforces it
    disable_resp = client.post(
        "/api/ui/2fa/disable",
        json={"password": "OperatorPass123!"},
    )
    assert disable_resp.status_code == 400
    assert any(
        w in disable_resp.get_json()["message"].lower() for w in ["obbligatoria", "enforced"]
    )
