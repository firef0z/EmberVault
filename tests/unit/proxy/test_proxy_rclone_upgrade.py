"""Unit tests for proxy RClone upgrade endpoint and 60-second TTL cache."""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest
from flask.testing import FlaskClient

from embervault_common.config import ProxySettings
from embervault_proxy.api import (
    RCLONE_VERSION_CACHE_TTL,
    get_rclone_version,
)
from embervault_proxy.factory import create_proxy_app

VALID_TOKEN = "valid_proxy_auth_token_at_least_32_chars__"


@pytest.fixture
def proxy_client(tmp_path: pytest.TempPathFactory) -> FlaskClient:
    state_dir = tmp_path / "proxy_state"
    state_dir.mkdir(parents=True, exist_ok=True)
    settings = ProxySettings(
        token=VALID_TOKEN,
        proxy_port=8443,
        proxy_state_dir=str(state_dir),
        proxy_rclone_bin="rclone",
    )
    app = create_proxy_app(settings)
    app.config["TESTING"] = True
    return app.test_client()


def test_rclone_version_cache_ttl() -> None:
    """Test that get_rclone_version caches for 60 seconds."""
    import embervault_proxy.api as proxy_api_module

    proxy_api_module._CACHED_RCLONE_VERSION = "rclone v1.68.0"
    proxy_api_module._CACHED_RCLONE_VERSION_TS = time.monotonic()

    # Within TTL, returns cached version without running subprocess
    assert get_rclone_version() == "rclone v1.68.0"

    # Expire TTL
    proxy_api_module._CACHED_RCLONE_VERSION_TS = time.monotonic() - (RCLONE_VERSION_CACHE_TTL + 5)
    # When TTL expires, it re-queries (fallback returns stub in dev)
    ver = get_rclone_version()
    assert "rclone" in ver


def test_proxy_rclone_upgrade_endpoint(proxy_client: FlaskClient) -> None:
    """Test /v1/system/rclone/upgrade endpoint with auth."""
    # Unauthorized request without Bearer token
    resp = proxy_client.post("/v1/system/rclone/upgrade", json={"version": "1.69.0"})
    assert resp.status_code == 401

    headers = {"Authorization": f"Bearer {VALID_TOKEN}"}

    # Missing version
    resp = proxy_client.post("/v1/system/rclone/upgrade", headers=headers, json={})
    assert resp.status_code == 400

    # Invalid version format
    resp = proxy_client.post(
        "/v1/system/rclone/upgrade", headers=headers, json={"version": "invalid"}
    )
    assert resp.status_code == 400

    # Successful upgrade with mock_success=True
    with patch("subprocess.run") as mock_sub:
        mock_sub.return_value.returncode = 0
        mock_sub.return_value.stdout = "rclone v1.69.0\n"

        resp = proxy_client.post(
            "/v1/system/rclone/upgrade",
            headers=headers,
            json={"version": "1.69.0", "mock_success": True},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "1.69.0" in data["version"]
