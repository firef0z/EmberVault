"""Unit tests for OrchestratorClient."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from embervault_app.orchestrator_client import (
    OrchestratorAuthError,
    OrchestratorClient,
    OrchestratorClientError,
    OrchestratorUnreachableError,
)
from embervault_common.contracts import ProxyProbeResponse


def test_probe_proxy_success() -> None:
    """Test successful probe_proxy call."""
    mock_session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "cert_fingerprint_sha256": "1234" * 16,
        "status": "ok",
        "latency_ms": 22.5,
        "proxy_version": "0.1.0",
        "rclone_version": "rclone v1.68.2",
    }
    mock_session.post.return_value = mock_resp

    client = OrchestratorClient(
        base_url="http://orchestrator:8081",
        internal_api_token="internal-secret-token",
        session=mock_session,
    )

    probe = client.probe_proxy("192.168.1.10", 8443, "t" * 32)
    assert isinstance(probe, ProxyProbeResponse)
    assert probe.cert_fingerprint_sha256 == "1234" * 16
    assert probe.status == "ok"
    assert probe.latency_ms == 22.5

    mock_session.post.assert_called_once_with(
        "http://orchestrator:8081/internal/v1/proxies/probe",
        json={"host": "192.168.1.10", "port": 8443, "token": "t" * 32},
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": "Bearer internal-secret-token",
        },
        timeout=20.0,
    )


def test_probe_proxy_auth_error() -> None:
    """Test probe_proxy raises OrchestratorAuthError on HTTP 401 when body is not proxy unauthorized."""
    mock_session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.json.side_effect = ValueError("Not JSON")
    mock_session.post.return_value = mock_resp

    client = OrchestratorClient(base_url="http://orchestrator:8081", session=mock_session)

    with pytest.raises(OrchestratorAuthError):
        client.probe_proxy("192.168.1.10", 8443, "t" * 32)


def test_probe_proxy_unauthorized_from_target_proxy() -> None:
    """Test probe_proxy raises OrchestratorClientError with specific message when proxy rejects token."""
    mock_session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.json.return_value = {
        "error": "unauthorized",
        "status": "unauthorized",
        "message": "Proxy 192.168.1.10:8443 rejected authentication token (HTTP 401).",
    }
    mock_session.post.return_value = mock_resp

    client = OrchestratorClient(base_url="http://orchestrator:8081", session=mock_session)

    with pytest.raises(OrchestratorClientError) as exc_info:
        client.probe_proxy("192.168.1.10", 8443, "t" * 32)

    assert "rejected authentication token" in str(exc_info.value)


def test_probe_proxy_unreachable() -> None:
    """Test probe_proxy raises OrchestratorUnreachableError on connection failure."""
    mock_session = MagicMock()
    mock_session.post.side_effect = requests.ConnectionError("Connection refused")

    client = OrchestratorClient(base_url="http://orchestrator:8081", session=mock_session)

    with pytest.raises(OrchestratorUnreachableError):
        client.probe_proxy("192.168.1.10", 8443, "t" * 32)


def test_check_health() -> None:
    """Test check_health endpoint helper."""
    mock_session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "ok", "service": "orchestrator"}
    mock_session.get.return_value = mock_resp

    client = OrchestratorClient(session=mock_session)
    health = client.check_health()
    assert health["status"] == "ok"


def test_trigger_job_run_timeout_sufficient_for_discovery() -> None:
    """Verify that trigger_job_run uses a timeout >= 60s to accommodate discovery phase."""
    import uuid

    mock_session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "dispatched", "run_id": str(uuid.uuid4())}
    mock_session.post.return_value = mock_resp

    client = OrchestratorClient(base_url="http://orchestrator:8081", session=mock_session)
    job_id = uuid.uuid4()
    resp = client.trigger_job_run(job_id=job_id)

    assert resp["status"] == "dispatched"
    _, kwargs = mock_session.post.call_args
    assert kwargs["timeout"] >= 60.0  # Must be at least 60s, NOT the previous buggy 15.0s!


def test_trigger_job_run_respects_custom_timeout() -> None:
    """Verify that trigger_job_run respects an explicit timeout override."""
    import uuid

    mock_session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"status": "dispatched"}
    mock_session.post.return_value = mock_resp

    client = OrchestratorClient(base_url="http://orchestrator:8081", session=mock_session)
    client.trigger_job_run(job_id=uuid.uuid4(), timeout=120.0)

    _, kwargs = mock_session.post.call_args
    assert kwargs["timeout"] == 120.0
