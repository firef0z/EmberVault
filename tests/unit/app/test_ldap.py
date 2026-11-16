"""Unit tests for LDAP / Active Directory authentication, group mapping, and UI controls (Milestone M4)."""

from __future__ import annotations

from typing import Any

import pytest
from flask import Flask
from ldap3 import MOCK_SYNC, Server
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.auth import authenticate_user
from embervault_app.factory import create_app
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_common.security.ldap import (
    LdapConfig,
    authenticate_ldap_user,
    resolve_ldap_role,
    test_ldap_connection,
)
from embervault_db.models import Base
from embervault_db.repositories.user_repository import UserRepository


@pytest.fixture
def test_app_and_db() -> tuple[Flask, sessionmaker[Session]]:
    """Create isolated SQLite in-memory test database and test Flask application."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)

    # Initialize key ring for testing
    kr = KeyRing({"v1": b"0" * 32})
    set_default_key_ring(kr)

    # Seed roles, permissions, and admin user
    from embervault_common.security.passwords import hash_password
    from embervault_db.seed import seed_initial_data

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
        secret_key="test-secret-key-for-ldap-testing",
    )
    app = create_app(settings=settings, session_factory=session_factory)
    app.config["WTF_CSRF_ENABLED"] = False
    return app, session_factory


@pytest.fixture
def mock_ldap_server() -> Server:
    """Create an ldap3 MockServer populated with users and groups."""
    server = Server("mock_ldap_server:636")
    return server


def _populate_mock_entries(connection: Any) -> None:
    """Add test entries to an ldap3 MockServer connection."""
    # Add organizational units
    connection.add("dc=azienda,dc=local", ["top", "domain"])
    connection.add("ou=users,dc=azienda,dc=local", ["top", "organizationalUnit"])
    connection.add("ou=groups,dc=azienda,dc=local", ["top", "organizationalUnit"])

    # User 1: Admin member
    connection.add(
        "cn=mario.rossi,ou=users,dc=azienda,dc=local",
        ["top", "person", "organizationalPerson", "inetOrgPerson"],
        {
            "uid": "m.rossi",
            "sAMAccountName": "m.rossi",
            "userPassword": "LdapPassword123!",
            "mail": "mario.rossi@azienda.local",
            "displayName": "Mario Rossi",
            "memberOf": ["CN=EmberAdmins,OU=groups,DC=azienda,DC=local"],
        },
    )

    # User 2: Operator member
    connection.add(
        "cn=luigi.verdi,ou=users,dc=azienda,dc=local",
        ["top", "person", "organizationalPerson", "inetOrgPerson"],
        {
            "uid": "l.verdi",
            "sAMAccountName": "l.verdi",
            "userPassword": "OperatorPass123!",
            "mail": "luigi.verdi@azienda.local",
            "displayName": "Luigi Verdi",
            "memberOf": ["CN=EmberOperators,OU=groups,DC=azienda,DC=local"],
        },
    )

    # User 3: Viewer (member of EmberViewers)
    connection.add(
        "cn=anna.bianchi,ou=users,dc=azienda,dc=local",
        ["top", "person", "organizationalPerson", "inetOrgPerson"],
        {
            "uid": "a.bianchi",
            "sAMAccountName": "a.bianchi",
            "userPassword": "ViewerPass123!",
            "mail": "anna.bianchi@azienda.local",
            "displayName": "Anna Bianchi",
            "memberOf": ["CN=EmberViewers,OU=groups,DC=azienda,DC=local"],
        },
    )

    # User 4: Unauthorized (not in admin, operator, or viewer group)
    connection.add(
        "cn=giuseppe.neri,ou=users,dc=azienda,dc=local",
        ["top", "person", "organizationalPerson", "inetOrgPerson"],
        {
            "uid": "g.neri",
            "sAMAccountName": "g.neri",
            "userPassword": "NeriPassword123!",
            "mail": "giuseppe.neri@azienda.local",
            "displayName": "Giuseppe Neri",
            "memberOf": ["CN=UnrelatedGroup,OU=groups,DC=azienda,DC=local"],
        },
    )

    # User 5: admin in LDAP
    connection.add(
        "cn=admin,ou=users,dc=azienda,dc=local",
        ["top", "person", "organizationalPerson", "inetOrgPerson"],
        {
            "uid": "admin",
            "sAMAccountName": "admin",
            "userPassword": "LdapAdminPass123!",
            "mail": "admin@azienda.local",
            "displayName": "Domain Admin",
            "memberOf": ["CN=EmberAdmins,OU=groups,DC=azienda,DC=local"],
        },
    )


def test_resolve_ldap_role():
    """Test group-to-role resolution logic and priority hierarchy."""
    config = LdapConfig(
        admin_group="CN=EmberAdmins,OU=groups,DC=azienda,DC=local",
        operator_group="EmberOperators",
        viewer_group="EmberViewers",
    )

    # Admin matches full DN
    assert resolve_ldap_role(["CN=EmberAdmins,OU=groups,DC=azienda,DC=local"], config) == "admin"
    # Admin matches by CN extraction
    assert resolve_ldap_role(["CN=EmberAdmins,OU=Other,DC=azienda,DC=local"], config) == "admin"
    # Operator matches plain name
    assert (
        resolve_ldap_role(["CN=EmberOperators,OU=groups,DC=azienda,DC=local"], config) == "operator"
    )
    # Viewer matches plain name
    assert resolve_ldap_role(["CN=EmberViewers,OU=groups,DC=azienda,DC=local"], config) == "viewer"

    # Priority hierarchy: Administrator > Operator > Viewer
    assert (
        resolve_ldap_role(
            [
                "CN=EmberAdmins,OU=groups,DC=azienda,DC=local",
                "CN=EmberOperators,OU=groups,DC=azienda,DC=local",
                "CN=EmberViewers,OU=groups,DC=azienda,DC=local",
            ],
            config,
        )
        == "admin"
    )
    assert (
        resolve_ldap_role(
            [
                "CN=EmberOperators,OU=groups,DC=azienda,DC=local",
                "CN=EmberViewers,OU=groups,DC=azienda,DC=local",
            ],
            config,
        )
        == "operator"
    )

    # Not in any of the 3 groups -> access denied (returns None)
    assert resolve_ldap_role(["CN=OtherGroup,DC=azienda,DC=local"], config) is None
    assert resolve_ldap_role([], config) is None


def test_ldap_url_and_tls_validation():
    """Verify URL scheme validation."""
    invalid_config = LdapConfig(server_url="http://insecure.ldap.local:389")
    ok, msg, _ = test_ldap_connection(invalid_config)
    assert ok is False
    assert "ldap://" in msg or "ldaps://" in msg


def test_authenticate_ldap_user_mock(mock_ldap_server: Server):
    """Test full LDAP authentication flow using ldap3 MockServer."""
    from ldap3 import Connection

    conn = Connection(mock_ldap_server, client_strategy=MOCK_SYNC)
    conn.open()
    _populate_mock_entries(conn)

    config = LdapConfig(
        server_url="ldaps://mock_ldap_server:636",
        base_dn="dc=azienda,dc=local",
        admin_group="CN=EmberAdmins,OU=groups,DC=azienda,DC=local",
        operator_group="EmberOperators",
        viewer_group="EmberViewers",
    )

    # 1. Success Admin
    ok, err, info = authenticate_ldap_user(
        config=config,
        username="m.rossi",
        password="LdapPassword123!",
        custom_server=mock_ldap_server,
        client_strategy=MOCK_SYNC,
    )
    assert ok is True
    assert err is None
    assert info is not None
    assert info.username == "m.rossi"
    assert info.role_name == "admin"
    assert info.email == "mario.rossi@azienda.local"
    assert info.display_name == "Mario Rossi"

    # 2. Success Operator
    ok, err, info = authenticate_ldap_user(
        config=config,
        username="l.verdi",
        password="OperatorPass123!",
        custom_server=mock_ldap_server,
        client_strategy=MOCK_SYNC,
    )
    assert ok is True
    assert info.role_name == "operator"

    # 3. Success Viewer
    ok, err, info = authenticate_ldap_user(
        config=config,
        username="a.bianchi",
        password="ViewerPass123!",
        custom_server=mock_ldap_server,
        client_strategy=MOCK_SYNC,
    )
    assert ok is True
    assert info.role_name == "viewer"

    # 4. Unauthorized User (not in any mapped group) -> Rejected with explicit message
    ok_unauth, err_unauth, info_unauth = authenticate_ldap_user(
        config=config,
        username="g.neri",
        password="NeriPassword123!",
        custom_server=mock_ldap_server,
        client_strategy=MOCK_SYNC,
    )
    assert ok_unauth is False
    assert info_unauth is None
    assert (
        err_unauth
        == "Non hai i diritti per accedere ad EmberVault, contatta il tuo amministratore di dominio LDAP."
    )

    # 5. Wrong password
    ok_fail, err_fail, info_fail = authenticate_ldap_user(
        config=config,
        username="m.rossi",
        password="WrongPassword!",
        custom_server=mock_ldap_server,
        client_strategy=MOCK_SYNC,
    )
    assert ok_fail is False
    assert "non valida" in err_fail.lower()
    assert info_fail is None

    # 6. Non-existent user
    ok_absent, err_absent, _ = authenticate_ldap_user(
        config=config,
        username="non.existent",
        password="Password123!",
        custom_server=mock_ldap_server,
        client_strategy=MOCK_SYNC,
    )
    assert ok_absent is False
    assert "non trovato" in err_absent.lower()


def test_explicit_auth_source_separation(
    test_app_and_db: tuple[Flask, sessionmaker[Session]],
    mock_ldap_server: Server,
):
    """Verify that user choosing local vs ldap can authenticate with the respective method."""
    _, session_factory = test_app_and_db

    from ldap3 import Connection

    conn = Connection(mock_ldap_server, client_strategy=MOCK_SYNC)
    conn.open()
    _populate_mock_entries(conn)

    config = LdapConfig(
        server_url="ldaps://mock_ldap_server:636",
        base_dn="dc=azienda,dc=local",
        admin_group="EmberAdmins",
    )

    with session_factory() as db:
        # A. Local admin authenticating with auth_source='local' using local password succeeds
        user_local, err_local = authenticate_user(
            db=db,
            username="admin",
            password="InitialAdminPass123!",
            auth_source="local",
        )
        assert err_local is None
        assert user_local is not None
        assert user_local.username == "admin"
        assert user_local.auth_source == "local"

        # B. Same username ('admin') authenticating with auth_source='ldap' using domain password succeeds!
        user_ldap_admin, err_ldap_admin = authenticate_user(
            db=db,
            username="admin",
            password="LdapAdminPass123!",
            auth_source="ldap",
            ldap_config_override=config,
            custom_ldap_server=mock_ldap_server,
            ldap_client_strategy=MOCK_SYNC,
        )
        assert err_ldap_admin is None
        assert user_ldap_admin is not None
        assert user_ldap_admin.username == "admin"
        assert user_ldap_admin.role.name in ("Administrator", "admin")
        assert user_ldap_admin.external_subject == "cn=admin,ou=users,dc=azienda,dc=local"

        # C. Local admin authenticating with auth_source='ldap' using WRONG password fails
        user_bad_pwd, err_bad_pwd = authenticate_user(
            db=db,
            username="admin",
            password="WrongPassword123!",
            auth_source="ldap",
            ldap_config_override=config,
            custom_ldap_server=mock_ldap_server,
            ldap_client_strategy=MOCK_SYNC,
        )
        assert user_bad_pwd is None
        assert (
            "password ldap non valida" in err_bad_pwd.lower()
            or "invalid ldap" in err_bad_pwd.lower()
            or "invalid credentials" in err_bad_pwd.lower()
        )

        # D. Pure LDAP user ('m.rossi') JIT provisions via LDAP
        ldap_user, err_ldap = authenticate_user(
            db=db,
            username="m.rossi",
            password="LdapPassword123!",
            auth_source="ldap",
            ldap_config_override=config,
            custom_ldap_server=mock_ldap_server,
            ldap_client_strategy=MOCK_SYNC,
        )
        assert err_ldap is None
        assert ldap_user is not None
        assert ldap_user.auth_source == "ldap"
        assert ldap_user.role.name in ("Administrator", "admin")

        # E. Pure LDAP user trying to log in with auth_source='local' fails because no local password is set
        user_rej_local, err_rej_local = authenticate_user(
            db=db,
            username="m.rossi",
            password="LdapPassword123!",
            auth_source="local",
        )
        assert user_rej_local is None
        assert (
            "non ha una password locale configurata" in err_rej_local.lower()
            or "does not have a local password configured" in err_rej_local.lower()
        )


def test_ldap_api_configuration_and_testing(
    test_app_and_db: tuple[Flask, sessionmaker[Session]],
):
    """Test /api/ui/ldap/config and /api/ui/ldap/test endpoints."""
    app, session_factory = test_app_and_db
    client = app.test_client()

    # Login as local admin
    client.post(
        "/login",
        data={"username": "admin", "password": "InitialAdminPass123!", "auth_source": "local"},
    )

    # 1. Get initial config
    cfg_resp = client.get("/api/ui/ldap/config")
    assert cfg_resp.status_code == 200
    cfg = cfg_resp.get_json()
    assert cfg["ldap_enabled"] is False
    assert "ldap_server_url" in cfg

    # 2. Update config with TLS certificate parameters
    fake_ca_pem = (
        "-----BEGIN CERTIFICATE-----\nMIIDtestFakeCACertificate\n-----END CERTIFICATE-----"
    )
    update_resp = client.put(
        "/api/ui/ldap/config",
        json={
            "ldap_enabled": True,
            "ldap_server_url": "ldaps://dc1.azienda.local:636",
            "ldap_base_dn": "DC=azienda,DC=local",
            "ldap_bind_dn": "CN=svc,DC=azienda,DC=local",
            "ldap_bind_password": "NewSecretPassword123!",
            "ldap_admin_group": "CN=Admins,DC=azienda,DC=local",
            "ldap_viewer_group": "CN=Viewers,DC=azienda,DC=local",
            "ldap_validate_cert": False,
            "ldap_ca_cert_pem": fake_ca_pem,
        },
    )
    assert update_resp.status_code == 200

    # 3. Verify updated config
    cfg_resp2 = client.get("/api/ui/ldap/config")
    cfg2 = cfg_resp2.get_json()
    assert cfg2["ldap_enabled"] is True
    assert cfg2["ldap_server_url"] == "ldaps://dc1.azienda.local:636"
    assert cfg2["ldap_bind_password_set"] is True
    assert cfg2["ldap_viewer_group"] == "CN=Viewers,DC=azienda,DC=local"
    assert cfg2["ldap_validate_cert"] is False
    assert cfg2["ldap_ca_cert_pem"] == fake_ca_pem

    # 4. Test connection endpoint with invalid host (should return 400 with descriptive error)
    test_resp = client.post(
        "/api/ui/ldap/test",
        json={
            "ldap_server_url": "ldaps://invalid.nonexistent.domain.local:636",
            "ldap_connect_timeout_s": 1,
            "ldap_validate_cert": False,
        },
    )
    assert test_resp.status_code == 400
    assert "error" in test_resp.get_json()["status"]


def test_ldap_tls_ca_cert_pem_handling() -> None:
    """Verify that LdapConfig properly passes ca_cert_pem and validate_cert to Server Tls."""
    from embervault_common.security.ldap import _build_server

    fake_ca = "-----BEGIN CERTIFICATE-----\nTEST_CA_DATA\n-----END CERTIFICATE-----"
    cfg = LdapConfig(
        server_url="ldaps://dc.azienda.local:636",
        validate_cert=False,
        ca_cert_pem=fake_ca,
    )
    server, is_ldap, is_ldaps = _build_server(cfg)
    assert is_ldaps is True
    assert server.tls is not None
    assert server.tls.validate == 0  # ssl.CERT_NONE
    assert server.tls.ca_certs_data == fake_ca


def test_parse_ad_diagnostic() -> None:
    """Verify parsing of Active Directory Win32 / NTSTATUS error subcodes."""
    from embervault_common.security.ldap import parse_ad_diagnostic

    msg = "80090308: LdapErr: DSID-0C090447, comment: AcceptSecurityContext error, data 52e, v3839"
    diag = parse_ad_diagnostic(msg)
    assert diag is not None
    assert "data 52e" in diag
    assert "Credenziali non valide" in diag

    user_not_found = (
        "80090308: LdapErr: DSID-0C090447, comment: AcceptSecurityContext error, data 525, v3839"
    )
    diag_525 = parse_ad_diagnostic(user_not_found)
    assert diag_525 is not None
    assert "data 525" in diag_525
    assert "Utente non trovato" in diag_525

    assert parse_ad_diagnostic(None) is None
    assert parse_ad_diagnostic("unrelated message") is None
