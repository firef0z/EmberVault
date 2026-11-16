"""Unit tests for embervault-proxy factory and endpoints."""

from pydantic import SecretStr

from embervault_common.config import ProxySettings
from embervault_proxy.factory import create_proxy_app


def test_proxy_endpoints() -> None:
    """Test healthz, readyz, and metrics endpoints for Proxy."""
    token = SecretStr("x" * 32)
    settings = ProxySettings(token=token, proxy_port=8443, log_level="INFO")
    app = create_proxy_app(settings)
    client = app.test_client()

    # /healthz
    res = client.get("/healthz")
    assert res.status_code == 200
    assert res.json == {"status": "ok", "service": "proxy"}

    # /readyz
    res = client.get("/readyz")
    assert res.status_code == 200
    assert res.json == {"status": "ready", "service": "proxy"}

    # /metrics requires Bearer token authentication
    res_unauth = client.get("/metrics")
    assert res_unauth.status_code == 401

    res = client.get("/metrics", headers={"Authorization": f"Bearer {'x' * 32}"})
    assert res.status_code == 200
    assert (
        b'embervault_service_info{milestone="M9",service="proxy",version="1.0.0"}' in res.data
        or b'embervault_service_info{service="proxy",version="1.0.0",milestone="M9"}' in res.data
    )
