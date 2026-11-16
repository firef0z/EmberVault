"""Unit tests for embervault-orchestrator factory and endpoints."""

from embervault_common.config import OrchestratorSettings
from embervault_orchestrator.factory import create_orchestrator_app


def test_orchestrator_endpoints() -> None:
    """Test healthz, readyz, and metrics endpoints for Orchestrator."""
    settings = OrchestratorSettings(orch_port=8081, log_level="INFO")
    app = create_orchestrator_app(settings, enable_background_services=False)
    client = app.test_client()

    # /healthz
    res = client.get("/healthz")
    assert res.status_code == 200
    assert res.json == {"status": "ok", "service": "orchestrator"}

    # /readyz
    res = client.get("/readyz")
    assert res.status_code == 200
    assert res.json == {"status": "ready", "service": "orchestrator"}

    # /metrics
    res = client.get("/metrics")
    assert res.status_code == 200
    assert (
        b'embervault_service_info{milestone="M9",service="orchestrator",version="1.0.0"}'
        in res.data
        or b'embervault_service_info{service="orchestrator",version="1.0.0",milestone="M9"}'
        in res.data
    )
