"""Unit tests for CSP nonces, strict security headers, and CSRF protection."""

from __future__ import annotations

import re

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from embervault_app.factory import create_app
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models.base import Base


@pytest.fixture
def app_instance() -> Flask:
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    settings = AppSettings(app_port=8080, dev_noauth=True)
    app = create_app(settings=settings, session_factory=session_factory)
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = True
    return app


@pytest.fixture
def client(app_instance: Flask) -> FlaskClient:
    return app_instance.test_client()


def test_security_headers_present(client: FlaskClient) -> None:
    """Verify that strict security headers are applied to all responses."""
    res = client.get("/")
    assert res.status_code == 200

    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert res.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "geolocation=()" in res.headers.get("Permissions-Policy", "")


def test_csp_header_and_nonce_matching(client: FlaskClient) -> None:
    """Verify that CSP header contains a cryptographic nonce matching script tags."""
    res = client.get("/")
    assert res.status_code == 200

    csp = res.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self' 'nonce-" in csp
    assert "frame-ancestors 'none'" in csp

    # Extract nonce from CSP header
    match = re.search(r"'nonce-([a-f0-9]+)'", csp)
    assert match is not None
    nonce_val = match.group(1)
    assert len(nonce_val) == 32  # 16 bytes hex

    # Verify that the rendered HTML contains <script nonce="<nonce_val>">
    html = res.data.decode("utf-8")
    assert f'nonce="{nonce_val}"' in html


def test_csrf_protection_blocks_post_without_token(client: FlaskClient) -> None:
    """Verify that POST mutating requests without CSRF token are blocked with HTTP 400."""
    res = client.post(
        "/api/ui/proxies/register",
        json={
            "name": "proxy-csrf-test",
            "host": "192.168.1.10",
            "port": 8443,
            "token": "a" * 32,
            "cert_fingerprint_sha256": "b" * 64,
        },
    )
    # Flask-WTF returns 400 Bad Request when CSRF token is missing
    assert res.status_code == 400


def test_csrf_token_injected_and_accepted(client: FlaskClient) -> None:
    """Verify that CSRF token in meta tag can be used to authenticate POST requests."""
    # 1. Fetch dashboard to get session and CSRF token
    get_res = client.get("/")
    html = get_res.data.decode("utf-8")

    csrf_match = re.search(r'<meta name="csrf-token" content="([^"]+)">', html)
    assert csrf_match is not None
    csrf_token = csrf_match.group(1)
    assert len(csrf_token) > 20

    # 2. Perform POST with X-CSRFToken header
    post_res = client.post(
        "/api/ui/proxies/register",
        headers={"X-CSRFToken": csrf_token},
        json={
            "name": "proxy-csrf-valid",
            "host": "192.168.1.100",
            "port": 8443,
            "token": "x" * 32,
            "cert_fingerprint_sha256": "c" * 64,
        },
    )
    # Passed CSRF check and created the proxy
    assert post_res.status_code == 201
    assert post_res.json is not None and post_res.json["status"] == "created"
