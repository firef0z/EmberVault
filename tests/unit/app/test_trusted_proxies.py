"""Unit tests for trusted proxies configuration, validation, API, and client IP resolution."""

from __future__ import annotations

import pytest
from flask import Flask, jsonify, request
from flask.testing import FlaskClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from embervault_app.factory import create_app
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models.base import Base
from embervault_db.settings_store import InvalidSettingValueError, SettingsStore


@pytest.fixture
def test_app_and_store() -> tuple[Flask, FlaskClient, SettingsStore]:
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    store = SettingsStore(session_factory)
    settings = AppSettings(app_port=8080, dev_noauth=True)
    app = create_app(
        settings=settings,
        session_factory=session_factory,
        settings_store=store,
    )
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    # Test route echoing request.remote_addr
    @app.route("/test-ip")
    def test_ip():
        return jsonify({"remote_addr": request.remote_addr})

    return app, app.test_client(), store


def test_trusted_proxies_validation(test_app_and_store):
    _, _, store = test_app_and_store

    # Valid IP and CIDR list
    store.set_setting("trusted_proxies", "192.168.1.1, 10.0.0.0/8, 172.16.0.1")
    assert store.get_setting("trusted_proxies") == "192.168.1.1, 10.0.0.0/8, 172.16.0.1"

    # Empty is valid (trusted proxies disabled)
    store.set_setting("trusted_proxies", "")
    assert store.get_setting("trusted_proxies") == ""

    # Invalid entry raises InvalidSettingValueError
    with pytest.raises(InvalidSettingValueError):
        store.set_setting("trusted_proxies", "192.168.1.1, not_an_ip, 10.0.0.1")


def test_trusted_proxies_api_get_and_put(test_app_and_store):
    _, client, store = test_app_and_store

    # Initial GET
    res = client.get("/api/ui/settings/trusted-proxies")
    assert res.status_code == 200
    assert res.json["trusted_proxies"] == ""

    # Invalid PUT
    res = client.put(
        "/api/ui/settings/trusted-proxies",
        json={"trusted_proxies": "invalid-ip-format"},
    )
    assert res.status_code == 400
    assert (
        "non è un indirizzo IP" in res.json["message"] or "is not a valid IP" in res.json["message"]
    )

    # Valid PUT with multiple entries
    res = client.put(
        "/api/ui/settings/trusted-proxies",
        json={"trusted_proxies": "192.168.121.2, 10.0.0.0/24"},
    )
    assert res.status_code == 200
    assert res.json["trusted_proxies"] == "192.168.121.2,10.0.0.0/24"
    assert store.get_setting("trusted_proxies") == "192.168.121.2,10.0.0.0/24"

    # Clear via PUT with empty string
    res = client.put(
        "/api/ui/settings/trusted-proxies",
        json={"trusted_proxies": ""},
    )
    assert res.status_code == 200
    assert res.json["trusted_proxies"] == ""
    assert store.get_setting("trusted_proxies") == ""


def test_untrusted_proxy_does_not_forward_ip(test_app_and_store):
    """When trusted_proxies is empty, remote_addr is NOT overwritten from X-Forwarded-For."""
    _, client, store = test_app_and_store
    store.set_setting("trusted_proxies", "")

    res = client.get(
        "/test-ip",
        environ_overrides={"REMOTE_ADDR": "192.168.121.2"},
        headers={"X-Forwarded-For": "203.0.113.195"},
    )
    assert res.status_code == 200
    # Must remain the immediate peer IP, ignoring spoofed or proxied header
    assert res.json["remote_addr"] == "192.168.121.2"


def test_trusted_proxy_resolves_real_client_ip(test_app_and_store):
    """When request comes from trusted proxy, remote_addr is resolved from X-Forwarded-For."""
    _, client, store = test_app_and_store
    store.set_setting("trusted_proxies", "192.168.121.2, 10.0.0.0/8")

    # 1. Single hop from trusted proxy
    res = client.get(
        "/test-ip",
        environ_overrides={"REMOTE_ADDR": "192.168.121.2"},
        headers={"X-Forwarded-For": "203.0.113.195"},
    )
    assert res.status_code == 200
    assert res.json["remote_addr"] == "203.0.113.195"

    # 2. Multi-hop chain: client (198.51.100.42) -> internal proxy (10.0.1.5) -> ingress proxy (192.168.121.2)
    res = client.get(
        "/test-ip",
        environ_overrides={"REMOTE_ADDR": "192.168.121.2"},
        headers={"X-Forwarded-For": "198.51.100.42, 10.0.1.5"},
    )
    assert res.status_code == 200
    assert res.json["remote_addr"] == "198.51.100.42"

    # 3. Connection from an untrusted peer even if trusted_proxies is configured
    res = client.get(
        "/test-ip",
        environ_overrides={"REMOTE_ADDR": "172.20.0.100"},
        headers={"X-Forwarded-For": "203.0.113.195"},
    )
    assert res.status_code == 200
    assert res.json["remote_addr"] == "172.20.0.100"


def test_settings_view_contains_trusted_proxies_card(test_app_and_store):
    """Verify that /settings renders the 'Proxy Affidabili' card and input."""
    _, client, store = test_app_and_store
    store.set_setting("trusted_proxies", "192.168.1.1,10.0.0.0/8")

    res = client.get("/settings")
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert "Proxy Affidabili" in html
    assert "trusted_proxies_input" in html
    assert "192.168.1.1,10.0.0.0/8" in html
    assert "btn-save-trusted-proxies" in html
    assert "btn-clear-trusted-proxies" in html
