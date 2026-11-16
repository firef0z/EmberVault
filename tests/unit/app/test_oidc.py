"""Unit tests for OpenID Connect (OIDC) / PocketID authentication (Milestone M5)."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from sqlalchemy import select

from embervault_common.security.oidc import (
    OidcConfig,
    build_authorization_url,
    extract_user_info_from_claims,
    generate_pkce_pair,
    parse_jwt_payload_unverified,
    resolve_oidc_role,
)
from embervault_common.security.passwords import hash_password, verify_password
from embervault_db.models.auth import User


def test_pkce_pair_generation() -> None:
    """Verify PKCE RFC 7636 verifier and S256 challenge generation."""
    verifier, challenge = generate_pkce_pair()
    assert len(verifier) >= 43
    assert len(challenge) >= 43

    # Manually compute SHA256 of verifier and compare with challenge
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    expected_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    assert challenge == expected_challenge


def test_build_authorization_url() -> None:
    """Verify authorization URL formatting with PKCE parameters."""
    config = OidcConfig(
        client_id="embervault-client",
        scopes="openid profile email groups",
    )
    url = build_authorization_url(
        config=config,
        redirect_uri="https://embervault.local/auth/oidc/callback",
        state="random_state_123",
        code_challenge="test_challenge_abc",
        authorization_endpoint="https://pocketid.local/authorize",
    )
    assert url.startswith("https://pocketid.local/authorize?")
    assert "client_id=embervault-client" in url
    assert "response_type=code" in url
    assert "state=random_state_123" in url
    assert "code_challenge=test_challenge_abc" in url
    assert "code_challenge_method=S256" in url


def test_resolve_oidc_role_hierarchy() -> None:
    """Verify role resolution priority: admin > operator > viewer."""
    # When user has both admin and operator groups, admin wins
    role, err = resolve_oidc_role(
        user_groups=["ember_operators", "ember_admins"],
        admin_group="ember_admins",
        operator_group="ember_operators",
        viewer_group="ember_viewers",
    )
    assert role == "admin"
    assert err is None

    # Operator role
    role, err = resolve_oidc_role(
        user_groups=["ember_operators"],
        admin_group="ember_admins",
        operator_group="ember_operators",
        viewer_group="ember_viewers",
    )
    assert role == "operator"
    assert err is None

    # Viewer role
    role, err = resolve_oidc_role(
        user_groups=["ember_viewers"],
        admin_group="ember_admins",
        operator_group="ember_operators",
        viewer_group="ember_viewers",
    )
    assert role == "viewer"
    assert err is None

    # When groups are configured and user has none: access denied
    role, err = resolve_oidc_role(
        user_groups=["unrelated_group"],
        admin_group="ember_admins",
        operator_group="ember_operators",
        viewer_group="ember_viewers",
    )
    assert role is None
    assert err is not None
    assert "contatta il tuo amministratore OIDC" in err

    # When no groups are configured on EmberVault, default to viewer
    role, err = resolve_oidc_role(
        user_groups=["any_group"],
        admin_group="",
        operator_group="",
        viewer_group="",
    )
    assert role == "viewer"
    assert err is None


def test_parse_jwt_payload_unverified() -> None:
    """Verify JWT payload decoding without signature verification."""
    claims = {"sub": "user_123", "preferred_username": "mario", "groups": ["admin"]}
    payload_json = json.dumps(claims).encode("utf-8")
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode("ascii").rstrip("=")
    fake_jwt = f"eyJhbGciOiJSUzI1NiJ9.{payload_b64}.signature"

    decoded = parse_jwt_payload_unverified(fake_jwt)
    assert decoded["sub"] == "user_123"
    assert decoded["preferred_username"] == "mario"
    assert decoded["groups"] == ["admin"]


def test_extract_user_info_from_claims() -> None:
    """Verify claim extraction and fallback resolution."""
    config = OidcConfig(
        username_claim="preferred_username",
        groups_claim="roles",
        admin_group="AdminRole",
    )
    claims = {
        "sub": "sub-987",
        "preferred_username": "luigi",
        "email": "luigi@example.com",
        "name": "Luigi Verdi",
        "roles": ["AdminRole", "UserRole"],
    }
    ok, err, info = extract_user_info_from_claims(claims, config)
    assert ok is True
    assert err == ""
    assert info is not None
    assert info.sub == "sub-987"
    assert info.username == "luigi"
    assert info.email == "luigi@example.com"
    assert info.display_name == "Luigi Verdi"
    assert info.role_name == "admin"


@pytest.fixture
def test_app_and_db():
    """Create isolated SQLite in-memory test database and test Flask application."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from embervault_app.factory import create_app
    from embervault_common.config import AppSettings
    from embervault_common.security.crypto import KeyRing, set_default_key_ring
    from embervault_db.models import Base
    from embervault_db.repositories.user_repository import UserRepository
    from embervault_db.seed import seed_initial_data

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)

    kr = KeyRing({"v1": b"0" * 32})
    set_default_key_ring(kr)

    with session_factory() as session:
        seed_initial_data(session)
        admin = UserRepository.get_user_by_username(session, "admin")
        if admin:
            admin.password_hash = hash_password("InitialAdminPass123!")
            admin.must_change_password = False
        session.commit()

    settings = AppSettings(
        env="dev",
        port=8080,
        trusted_proxy_count=0,
        session_cookie_secure=False,
        secret_key="test-secret-key-for-oidc-testing",
    )
    app = create_app(settings=settings, session_factory=session_factory)
    app.config["WTF_CSRF_ENABLED"] = False
    return app, session_factory


def test_login_page_renders_oidc_button(test_app_and_db) -> None:
    """Verify login page displays 'Accedi con PocketID' and 'oppure' when OIDC is enabled."""
    app, session_factory = test_app_and_db
    from embervault_app.oidc_service import save_oidc_config

    with session_factory() as db:
        save_oidc_config(
            session=db,
            data={
                "oidc_enabled": True,
                "oidc_provider_name": "PocketID",
                "oidc_issuer_url": "https://pocketid.azienda.local",
                "oidc_client_id": "embervault",
            },
        )
        db.commit()

    client = app.test_client()
    resp = client.get("/login")
    assert resp.status_code == 200
    html = resp.data.decode("utf-8")
    assert "oppure" in html.lower() or "or" in html.lower()
    assert (
        "Accedi con PocketID" in html
        or "Sign in with PocketID" in html
        or "Log in with PocketID" in html
    )
    assert "/auth/oidc/login" in html


def test_oidc_login_redirect_initiates_pkce_flow(test_app_and_db) -> None:
    """Verify GET /auth/oidc/login fetches discovery and redirects to authorization endpoint."""
    app, session_factory = test_app_and_db
    from embervault_app.oidc_service import save_oidc_config

    with session_factory() as db:
        save_oidc_config(
            session=db,
            data={
                "oidc_enabled": True,
                "oidc_provider_name": "PocketID",
                "oidc_issuer_url": "https://pocketid.azienda.local",
                "oidc_client_id": "embervault",
            },
        )
        db.commit()

    mock_discovery = {
        "authorization_endpoint": "https://pocketid.azienda.local/authorize",
        "token_endpoint": "https://pocketid.azienda.local/api/oidc/token",
        "userinfo_endpoint": "https://pocketid.azienda.local/api/oidc/userinfo",
    }

    client = app.test_client()
    with patch(
        "embervault_common.security.oidc.fetch_oidc_discovery",
        return_value=(True, "", mock_discovery),
    ):
        resp = client.get("/auth/oidc/login")
        assert resp.status_code == 302
        location = resp.headers.get("Location", "")
        assert location.startswith("https://pocketid.azienda.local/authorize?")
        assert "client_id=embervault" in location
        assert "code_challenge=" in location
        assert "code_challenge_method=S256" in location

        # Check session state stored
        with client.session_transaction() as sess:
            assert "oidc_state" in sess
            assert "oidc_verifier" in sess


def test_oidc_callback_account_linking_overwrites_role_and_keeps_local_password(
    test_app_and_db,
) -> None:
    """Verify that an existing local user with matching username is linked to OIDC,

    its role is overwritten by the OIDC claim, and its password_hash is preserved
    for offline/emergency local access.
    """
    app, session_factory = test_app_and_db
    from embervault_app.oidc_service import save_oidc_config
    from embervault_db.repositories.user_repository import UserRepository

    with session_factory() as db:
        save_oidc_config(
            session=db,
            data={
                "oidc_enabled": True,
                "oidc_provider_name": "PocketID",
                "oidc_issuer_url": "https://pocketid.azienda.local",
                "oidc_client_id": "embervault",
                "oidc_admin_group": "pocket_admins",
                "oidc_operator_group": "pocket_ops",
                "oidc_viewer_group": "pocket_viewers",
            },
        )

        # 1. Create a pre-existing local user with role 'viewer' and local password
        viewer_role = UserRepository.get_role_by_name(db, "viewer")
        assert viewer_role is not None

        local_pw = "LocalEmergencyPassword123!"
        existing_local_user = User(
            username="mario.rossi",
            email="mario.old@local.it",
            display_name="Mario Locale",
            auth_source="local",
            external_subject=None,
            password_hash=hash_password(local_pw),
            role_id=viewer_role.id,
            is_active=True,
        )
        db.add(existing_local_user)
        db.commit()

    client = app.test_client()

    # 2. Simulate user initiating OIDC login
    state = "valid_state_456"
    verifier = "valid_pkce_verifier_789"
    with client.session_transaction() as sess:
        sess["oidc_state"] = state
        sess["oidc_verifier"] = verifier

    # 3. Mock OIDC discovery, token exchange, and userinfo
    mock_discovery = {
        "authorization_endpoint": "https://pocketid.azienda.local/authorize",
        "token_endpoint": "https://pocketid.azienda.local/api/oidc/token",
        "userinfo_endpoint": "https://pocketid.azienda.local/api/oidc/userinfo",
    }
    mock_tokens = {
        "access_token": "mock_access_token_123",
        "token_type": "Bearer",
    }
    mock_userinfo = {
        "sub": "oidc-sub-mario-uuid-999",
        "preferred_username": "mario.rossi",
        "email": "mario.rossi@azienda.it",
        "name": "Mario Rossi OIDC",
        "groups": ["pocket_admins"],  # OIDC groups map to admin!
    }

    with (
        patch(
            "embervault_common.security.oidc.fetch_oidc_discovery",
            return_value=(True, "", mock_discovery),
        ),
        patch(
            "embervault_common.security.oidc.exchange_code_for_tokens",
            return_value=(True, "", mock_tokens),
        ),
        patch(
            "embervault_common.security.oidc.fetch_userinfo",
            return_value=(True, "", mock_userinfo),
        ),
    ):
        resp = client.get(f"/auth/oidc/callback?code=mock_auth_code&state={state}")
        assert resp.status_code == 302
        assert resp.headers.get("Location") == "/"

    # 4. Verify account was linked and permissions updated
    with session_factory() as db:
        updated_user = db.scalar(select(User).where(User.username == "mario.rossi"))
        assert updated_user is not None
        # Linked to OIDC subject
        assert updated_user.external_subject == "oidc-sub-mario-uuid-999"
        # Role overwritten from viewer to admin / Administrator
        assert updated_user.role.name in ("Administrator", "admin")
        assert updated_user.email == "mario.rossi@azienda.it"
        assert updated_user.display_name == "Mario Rossi OIDC"

        # Local password hash MUST be preserved for emergency offline access!
        assert updated_user.password_hash is not None
        assert verify_password(updated_user.password_hash, local_pw) is True


def test_oidc_jit_user_provisioning_for_new_user(
    test_app_and_db,
) -> None:
    """Verify JIT user creation when logging in via OIDC for a previously unknown user."""
    app, session_factory = test_app_and_db
    from embervault_app.oidc_service import save_oidc_config

    with session_factory() as db:
        save_oidc_config(
            session=db,
            data={
                "oidc_enabled": True,
                "oidc_provider_name": "PocketID",
                "oidc_issuer_url": "https://pocketid.azienda.local",
                "oidc_client_id": "embervault",
                "oidc_admin_group": "admin",
                "oidc_operator_group": "operator",
                "oidc_viewer_group": "viewer",
            },
        )
        db.commit()

    client = app.test_client()
    state = "state_new_user_123"
    verifier = "verifier_new_user_456"
    with client.session_transaction() as sess:
        sess["oidc_state"] = state
        sess["oidc_verifier"] = verifier

    mock_discovery = {
        "authorization_endpoint": "https://pocketid.azienda.local/authorize",
        "token_endpoint": "https://pocketid.azienda.local/api/oidc/token",
        "userinfo_endpoint": "https://pocketid.azienda.local/api/oidc/userinfo",
    }
    mock_tokens = {"access_token": "token_abc"}
    mock_userinfo = {
        "sub": "sub-new-user-001",
        "preferred_username": "giulia.bianchi",
        "email": "giulia@azienda.it",
        "name": "Giulia Bianchi",
        "groups": ["operator"],
    }

    with (
        patch(
            "embervault_common.security.oidc.fetch_oidc_discovery",
            return_value=(True, "", mock_discovery),
        ),
        patch(
            "embervault_common.security.oidc.exchange_code_for_tokens",
            return_value=(True, "", mock_tokens),
        ),
        patch(
            "embervault_common.security.oidc.fetch_userinfo",
            return_value=(True, "", mock_userinfo),
        ),
    ):
        resp = client.get(f"/auth/oidc/callback?code=mock_code&state={state}")
        assert resp.status_code == 302

    with session_factory() as db:
        new_user = db.scalar(select(User).where(User.username == "giulia.bianchi"))
        assert new_user is not None
        assert new_user.auth_source == "oidc"
        assert new_user.external_subject == "sub-new-user-001"
        assert new_user.role.name in ("Operator", "operator")
        assert new_user.email == "giulia@azienda.it"
        assert new_user.display_name == "Giulia Bianchi"
        assert new_user.is_active is True


def test_oidc_settings_api(test_app_and_db) -> None:
    """Verify OIDC settings GET, PUT, and test endpoints."""
    app, session_factory = test_app_and_db
    client = app.test_client()

    from embervault_app.auth import create_user_session
    from embervault_db.repositories.user_repository import UserRepository

    with session_factory() as db:
        admin = UserRepository.get_user_by_username(db, "admin")
        assert admin is not None
        admin_id = str(admin.id)
        token = create_user_session(db, admin)

    with client.session_transaction() as sess:
        sess["auth_token"] = token
        sess["user_id"] = admin_id

    # 1. GET config
    res = client.get("/api/ui/oidc/config")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "ok"
    assert "oidc_enabled" in data

    # 2. PUT config
    res = client.put(
        "/api/ui/oidc/config",
        json={
            "oidc_enabled": True,
            "oidc_provider_name": "PocketID Test",
            "oidc_issuer_url": "https://pocketid.example.com",
            "oidc_client_id": "test-client",
            "oidc_client_secret": "secret123",
            "oidc_admin_group": "pocket_admin",
        },
    )
    assert res.status_code == 200
    assert res.get_json()["status"] == "updated"

    # 3. GET config again
    res = client.get("/api/ui/oidc/config")
    assert res.status_code == 200
    data2 = res.get_json()
    assert data2["oidc_enabled"] is True
    assert data2["oidc_provider_name"] == "PocketID Test"
    assert data2["oidc_client_secret_set"] is True
    assert data2["oidc_enforce_mfa"] is True

    # Toggle oidc_enforce_mfa to False
    res_mfa = client.put(
        "/api/ui/oidc/config",
        json={"oidc_enforce_mfa": False},
    )
    assert res_mfa.status_code == 200
    res_mfa_get = client.get("/api/ui/oidc/config")
    assert res_mfa_get.get_json()["oidc_enforce_mfa"] is False

    # 4. POST test
    mock_disc = {
        "issuer": "https://pocketid.example.com",
        "authorization_endpoint": "https://pocketid.example.com/authorize",
        "token_endpoint": "https://pocketid.example.com/api/oidc/token",
        "userinfo_endpoint": "https://pocketid.example.com/api/oidc/userinfo",
    }
    with patch(
        "embervault_common.security.oidc.fetch_oidc_discovery",
        return_value=(True, "", mock_disc),
    ):
        res = client.post("/api/ui/oidc/test", json={})
        assert res.status_code == 200
        assert res.get_json()["status"] == "ok"


def test_oidc_2fa_enforce_mfa_switch_behavior(test_app_and_db) -> None:
    """Verify that when 2FA is active:
    - If oidc_enforce_mfa is True: user is redirected to 2FA verification.
    - If oidc_enforce_mfa is False: 2FA is skipped and user is logged in directly.
    """
    app, session_factory = test_app_and_db
    from embervault_app.oidc_service import save_oidc_config
    from embervault_db.models.auth import UserMfaFactor
    from embervault_db.repositories.user_repository import UserRepository

    save_oidc_config(
        session=app.config["SETTINGS_STORE"],
        data={
            "oidc_enabled": True,
            "oidc_provider_name": "PocketID",
            "oidc_issuer_url": "https://pocketid.test.local",
            "oidc_client_id": "client-2fa-test",
            "oidc_enforce_mfa": True,
        },
    )
    with session_factory() as db:
        viewer_role = UserRepository.get_role_by_name(db, "viewer")
        user = User(
            username="user_with_2fa",
            email="user2fa@test.it",
            display_name="User 2FA",
            auth_source="oidc",
            external_subject="sub-2fa-12345",
            role_id=viewer_role.id,
            is_active=True,
        )
        db.add(user)
        db.flush()

        # Add active confirmed TOTP factor
        mfa = UserMfaFactor(
            user_id=user.id,
            type="totp",
            label="Authenticator",
            secret_encrypted=b"secret",
            confirmed_at=datetime.now(UTC),
        )
        db.add(mfa)
        db.commit()

    client = app.test_client()

    mock_discovery = {
        "authorization_endpoint": "https://pocketid.test.local/authorize",
        "token_endpoint": "https://pocketid.test.local/api/oidc/token",
        "userinfo_endpoint": "https://pocketid.test.local/api/oidc/userinfo",
    }
    mock_tokens = {"access_token": "token_abc"}
    mock_userinfo = {
        "sub": "sub-2fa-12345",
        "preferred_username": "user_with_2fa",
        "name": "User 2FA",
    }

    # Case A: oidc_enforce_mfa is True -> redirected to /auth/two-factor
    with client.session_transaction() as sess:
        sess["oidc_state"] = "state_a"
        sess["oidc_verifier"] = "verifier_a"

    with (
        patch(
            "embervault_common.security.oidc.fetch_oidc_discovery",
            return_value=(True, "", mock_discovery),
        ),
        patch(
            "embervault_common.security.oidc.exchange_code_for_tokens",
            return_value=(True, "", mock_tokens),
        ),
        patch(
            "embervault_common.security.oidc.fetch_userinfo", return_value=(True, "", mock_userinfo)
        ),
    ):
        resp_a = client.get("/auth/oidc/callback?code=code_a&state=state_a")
        assert resp_a.status_code == 302
        assert "/login/2fa" in resp_a.headers["Location"]
        with client.session_transaction() as sess:
            assert "2fa_pending_user_id" in sess

    # Case B: oidc_enforce_mfa is False -> skips 2FA, redirects to /
    save_oidc_config(session=app.config["SETTINGS_STORE"], data={"oidc_enforce_mfa": False})

    with client.session_transaction() as sess:
        sess["oidc_state"] = "state_b"
        sess["oidc_verifier"] = "verifier_b"

    with (
        patch(
            "embervault_common.security.oidc.fetch_oidc_discovery",
            return_value=(True, "", mock_discovery),
        ),
        patch(
            "embervault_common.security.oidc.exchange_code_for_tokens",
            return_value=(True, "", mock_tokens),
        ),
        patch(
            "embervault_common.security.oidc.fetch_userinfo", return_value=(True, "", mock_userinfo)
        ),
    ):
        resp_b = client.get("/auth/oidc/callback?code=code_b&state=state_b")
        assert resp_b.status_code == 302
        assert resp_b.headers["Location"] == "/"
        with client.session_transaction() as sess:
            assert "auth_token" in sess
            assert "2fa_pending_user_id" not in sess
