"""Live end-to-end integration tests against running Docker Compose stack."""

import shutil
import subprocess
import time
import urllib.error
import urllib.request

import pytest

DOCKER_AVAILABLE = shutil.which("docker") is not None


def is_compose_stack_running() -> bool:
    """Check if the EmberVault Docker Compose stack is currently running."""
    if not DOCKER_AVAILABLE:
        return False
    try:
        res = subprocess.run(
            [
                "docker",
                "compose",
                "-f",
                "deploy/compose/docker-compose.yml",
                "ps",
                "-q",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        return bool(res.stdout.strip())
    except Exception:
        return False


@pytest.mark.skipif(
    not is_compose_stack_running(),
    reason="Docker compose stack is not currently running. Run 'make up' to test live.",
)
def test_live_app_endpoints_and_isolation() -> None:
    """Verify live readiness and container network isolation when compose is running."""
    # 1. Poll /readyz on host published port
    max_wait_seconds = 30
    start_time = time.monotonic()
    ready = False

    while time.monotonic() - start_time < max_wait_seconds:
        try:
            req = urllib.request.Request("http://127.0.0.1:8080/readyz")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.getcode() == 200:
                    ready = True
                    break
        except Exception:
            time.sleep(1.0)

    assert ready, "Timed out waiting for http://127.0.0.1:8080/readyz to become healthy"

    # 2. Check /metrics
    req_metrics = urllib.request.Request("http://127.0.0.1:8080/metrics")
    with urllib.request.urlopen(req_metrics, timeout=5.0) as resp:
        assert resp.getcode() == 200
        content = resp.read()
        assert b"embervault_service_info" in content

    # 3. Test Network Isolation from inside app container:
    # app is on (edge, backend) and must NOT be able to resolve or connect to proxy-1 (on proxy_net)
    res = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "deploy/compose/docker-compose.yml",
            "exec",
            "-T",
            "app",
            "python3",
            "-c",
            "import socket; socket.gethostbyname('proxy-1')",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode != 0, (
        "Security isolation violation: 'app' container was able to resolve 'proxy-1'!"
    )
