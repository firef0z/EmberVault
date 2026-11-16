"""Unit tests for proxy Bearer token authentication, protocol headers, and endpoints."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from flask.testing import FlaskClient
from pydantic import SecretStr, ValidationError

from embervault_common.config import ProxySettings
from embervault_common.contracts import (
    EMBERVAULT_PROTOCOL_VERSION,
    PROTOCOL_HEADER,
    REQUEST_ID_HEADER,
)
from embervault_proxy.factory import create_proxy_app

CANARY_PROXY_TOKEN = "CANARY_SECRET_PROXY_TOKEN_32_CHARACTERS_MINIMUM_DEV"


@pytest.fixture
def proxy_client(tmp_path: Path) -> FlaskClient:
    settings = ProxySettings(
        token=SecretStr(CANARY_PROXY_TOKEN),
        proxy_state_dir=tmp_path / "proxy_state",
        proxy_tls_auto_self_signed=True,
    )
    app = create_proxy_app(settings)
    app.config["TESTING"] = True
    return app.test_client()


class TestProxyTokenValidation:
    """Test validation of proxy token at startup."""

    def test_short_token_rejected_at_settings(self) -> None:
        with pytest.raises(ValidationError):
            ProxySettings(token=SecretStr("too_short"))


class TestProxyAuthenticationAndEndpoints:
    """Test unauthenticated and authenticated requests to proxy."""

    def test_healthz_unauthenticated(self, proxy_client: FlaskClient) -> None:
        resp = proxy_client.get("/healthz")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ok"
        # Check protocol header
        assert resp.headers.get(PROTOCOL_HEADER) == str(EMBERVAULT_PROTOCOL_VERSION)
        assert resp.headers.get(REQUEST_ID_HEADER) is not None

    def test_readyz_unauthenticated(self, proxy_client: FlaskClient) -> None:
        resp = proxy_client.get("/readyz")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ready"

    def test_v1_health_missing_bearer_fails(self, proxy_client: FlaskClient) -> None:
        resp = proxy_client.get("/v1/health")
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "unauthorized"

    def test_v1_health_invalid_bearer_fails(self, proxy_client: FlaskClient) -> None:
        resp = proxy_client.get(
            "/v1/health",
            headers={"Authorization": "Bearer wrong_token_that_does_not_match_32_chars"},
        )
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "unauthorized"

    def test_v1_health_malformed_header_fails(self, proxy_client: FlaskClient) -> None:
        resp = proxy_client.get(
            "/v1/health",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "unauthorized"

    def test_v1_health_valid_bearer_succeeds(self, proxy_client: FlaskClient) -> None:
        resp = proxy_client.get(
            "/v1/health",
            headers={"Authorization": f"Bearer {CANARY_PROXY_TOKEN}"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        from embervault_proxy import __version__

        assert data["proxy_version"] == __version__
        assert "rclone" in data["rclone_version"].lower()
        assert data["capacity"] >= 1
        assert data["running_tasks"] == 0

    def test_metrics_requires_auth(self, proxy_client: FlaskClient) -> None:
        # Without auth: 401
        resp_unauth = proxy_client.get("/metrics")
        assert resp_unauth.status_code == 401

        # With auth: 200
        resp_auth = proxy_client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {CANARY_PROXY_TOKEN}"},
        )
        assert resp_auth.status_code == 200

    def test_tasks_endpoints(self, proxy_client: FlaskClient) -> None:
        auth_header = {"Authorization": f"Bearer {CANARY_PROXY_TOKEN}"}
        attempt_id = str(uuid4())

        # POST /v1/tasks without auth -> 401
        assert proxy_client.post("/v1/tasks").status_code == 401

        # POST /v1/tasks with auth but empty body -> 400 Bad Request
        post_resp = proxy_client.post("/v1/tasks", headers=auth_header)
        assert post_resp.status_code == 400

        # GET /v1/tasks/{id} with nonexistent attempt -> 404
        get_resp = proxy_client.get(f"/v1/tasks/{attempt_id}", headers=auth_header)
        assert get_resp.status_code == 404

        # GET /v1/tasks/{id}/logs with nonexistent attempt -> 404
        logs_resp = proxy_client.get(f"/v1/tasks/{attempt_id}/logs", headers=auth_header)
        assert logs_resp.status_code == 404

        # POST /v1/tasks/{id}/cancel with nonexistent attempt -> 404
        cancel_resp = proxy_client.post(f"/v1/tasks/{attempt_id}/cancel", headers=auth_header)
        assert cancel_resp.status_code == 404

        # DELETE /v1/tasks/{id} with nonexistent attempt -> 404
        del_resp = proxy_client.delete(f"/v1/tasks/{attempt_id}", headers=auth_header)
        assert del_resp.status_code == 404

        # GET /v1/tasks -> 200
        list_resp = proxy_client.get("/v1/tasks", headers=auth_header)
        assert list_resp.status_code == 200
        assert "tasks" in list_resp.get_json()

    def test_canary_token_never_leaked(self, proxy_client: FlaskClient) -> None:
        """Verify the canary token does not appear in responses or error payloads."""
        resp = proxy_client.get(
            "/v1/health",
            headers={"Authorization": f"Bearer {CANARY_PROXY_TOKEN}"},
        )
        assert CANARY_PROXY_TOKEN not in resp.get_data(as_text=True)

        resp_invalid = proxy_client.get(
            "/v1/health",
            headers={"Authorization": f"Bearer {CANARY_PROXY_TOKEN}_invalid"},
        )
        assert CANARY_PROXY_TOKEN not in resp_invalid.get_data(as_text=True)

    def test_discover_endpoint_accepts_timeout_s(self, proxy_client: FlaskClient) -> None:
        auth_header = {"Authorization": f"Bearer {CANARY_PROXY_TOKEN}"}
        resp = proxy_client.post(
            "/v1/discover",
            headers=auth_header,
            json={
                "backend_type": "local",
                "config": {"path": "/tmp"},
                "timeout_s": 45,
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "subfolders" in data

    def test_download_endpoint_single_file_stream(self, proxy_client: FlaskClient) -> None:
        auth_header = {"Authorization": f"Bearer {CANARY_PROXY_TOKEN}"}
        resp = proxy_client.post(
            "/v1/remotes/download",
            headers=auth_header,
            json={
                "backend_type": "local",
                "config": {"path": "/tmp"},
                "base_path": "docs",
                "items": [{"name": "report.pdf", "type": "file"}],
            },
        )
        assert resp.status_code == 200
        assert "application/" in resp.headers.get("Content-Type", "")
        assert 'attachment; filename="report.pdf"' in resp.headers.get("Content-Disposition", "")
        assert len(resp.data) > 0

    def test_download_endpoint_zip_archive_stream(self, proxy_client: FlaskClient) -> None:
        import io
        import zipfile

        auth_header = {"Authorization": f"Bearer {CANARY_PROXY_TOKEN}"}
        resp = proxy_client.post(
            "/v1/remotes/download",
            headers=auth_header,
            json={
                "backend_type": "local",
                "config": {"path": "/tmp"},
                "base_path": "vault",
                "items": [
                    {"name": "folderA", "type": "directory"},
                    {"name": "fileB.txt", "type": "file"},
                ],
            },
        )
        assert resp.status_code == 200
        assert resp.headers.get("Content-Type") == "application/zip"
        assert ".zip" in resp.headers.get("Content-Disposition", "")

        # Verify it is a valid zip archive
        zf = zipfile.ZipFile(io.BytesIO(resp.data))
        names = zf.namelist()
        assert len(names) > 0
        assert any("fileB.txt" in n for n in names)
