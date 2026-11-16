"""Unit tests for Bash Hook Executor (Milestone M8)."""

from __future__ import annotations

import os

import pytest

from embervault_common.hooks.executor import HookExecutor


def test_hook_executor_sha256_hash() -> None:
    executor = HookExecutor()
    script1 = "#!/bin/bash\necho 'hello world'\n"
    script2 = "echo 'hello world'"
    hash1 = executor.calculate_script_hash(script1)
    hash2 = executor.calculate_script_hash(script2)
    assert len(hash1) == 64
    assert len(hash2) == 64
    # Different contents have different hashes
    assert hash1 != hash2
    # Same content trimmed has same hash
    assert executor.calculate_script_hash(script1.strip()) == hash1


def test_hook_executor_empty_script_skipped() -> None:
    executor = HookExecutor()
    res = executor.execute("", context={})
    assert res.status == "skipped"
    assert res.exit_code == 0
    assert "Nessuno script fornito" in res.output


def test_hook_executor_sanitized_environment() -> None:
    executor = HookExecutor()
    # Inject sensitive env var in current ambient process
    os.environ["DATABASE_URL"] = "postgresql://user:super_secret@localhost/db"
    os.environ["EMBERVAULT_MASTER_KEY"] = "super_secret_master_key_12345678"

    context = {
        "EMBERVAULT_JOB_NAME": "test-job",
        "EMBERVAULT_RUN_ID": "11111111-1111-1111-1111-111111111111",
    }
    clean_env = executor.build_sanitized_environment(context)

    # Ambient secrets must NOT be in clean_env
    assert "DATABASE_URL" not in clean_env
    assert "EMBERVAULT_MASTER_KEY" not in clean_env
    # Explicit context must be in clean_env
    assert clean_env["EMBERVAULT_JOB_NAME"] == "test-job"
    assert clean_env["EMBERVAULT_RUN_ID"] == "11111111-1111-1111-1111-111111111111"


def test_hook_executor_successful_run() -> None:
    executor = HookExecutor(default_timeout_s=10)
    script = "echo Hello from hook"
    res = executor.execute(
        script,
        context={"EMBERVAULT_JOB_NAME": "backup-daily"},
    )
    assert res.status == "succeeded"
    assert res.exit_code == 0
    assert "Hello from hook" in res.output
    assert res.duration_ms >= 0


def test_hook_executor_failing_exit_code() -> None:
    executor = HookExecutor(default_timeout_s=10)
    script = "exit 42"
    res = executor.execute(script, context={})
    assert res.status == "failed"
    assert res.exit_code != 0


def test_hook_executor_timeout() -> None:
    executor = HookExecutor(default_timeout_s=1)
    # Run a script that sleeps longer than timeout
    # Use python one-liner inside batch/shell for cross-platform sleep
    import sys

    python_bin = sys.executable
    script = f'"{python_bin}" -c "import time; time.sleep(5)"'
    res = executor.execute(script, context={}, timeout_s=1)
    assert res.status == "timeout"
    assert "[TIMEOUT]" in res.output


def test_hook_runner_service_app() -> None:
    """Test Flask hook runner app endpoint execution and token validation."""
    from embervault_common.hooks.runner_service import create_hook_runner_app

    app = create_hook_runner_app(auth_token="secret_token_123")
    client = app.test_client()

    # Healthz without auth
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}

    # Unauthorized execute
    resp = client.post("/execute", json={"script": "echo test"})
    assert resp.status_code == 401

    # Authorized execute
    headers = {"Authorization": "Bearer secret_token_123"}
    resp = client.post(
        "/execute",
        headers=headers,
        json={"script": "echo 'sidecar running'", "context": {"JOB": "1"}},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "succeeded"
    assert data["exit_code"] == 0
    assert "sidecar running" in data["output"]


def test_hook_executor_remote_delegation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test HookExecutor remote mode delegating via HTTP."""
    from unittest.mock import MagicMock

    executor = HookExecutor(
        default_timeout_s=10,
        runner_url="http://mock-hook-runner:8082",
        auth_token="test_token",
    )

    fake_response_data = (
        b'{"status": "succeeded", "exit_code": 0, "duration_ms": 15.2, '
        b'"script_hash": "testhash", "output": "remote success"}'
    )

    mock_resp = MagicMock()
    mock_resp.read.return_value = fake_response_data
    mock_resp.__enter__.return_value = mock_resp

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout: mock_resp)

    res = executor.execute(
        script_content="echo 123",
        context={"JOB": "test"},
    )

    assert res.status == "succeeded"
    assert res.output == "remote success"
    assert res.duration_ms == 15.2
    assert res.script_hash == "testhash"
