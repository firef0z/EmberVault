"""Unit tests for Proxy TaskRunner and task endpoints (Milestone M1.5)."""

from __future__ import annotations

import time
import uuid
from pathlib import Path

import pytest
from flask.testing import FlaskClient
from pydantic import SecretStr

from embervault_common.config import ProxySettings
from embervault_proxy.factory import create_proxy_app
from embervault_proxy.runner import TaskRunner, set_task_runner

TEST_TOKEN = "a" * 32


@pytest.fixture
def proxy_client(tmp_path: Path) -> FlaskClient:
    settings = ProxySettings(
        token=SecretStr(TEST_TOKEN),
        proxy_port=8443,
        proxy_state_dir=tmp_path / "proxy_state",
        proxy_tls_auto_self_signed=True,
        log_level="DEBUG",
    )
    runner = TaskRunner(rclone_bin="non_existent_rclone_binary_for_test")
    set_task_runner(runner)

    app = create_proxy_app(settings=settings)
    app.config["TESTING"] = True
    return app.test_client()


def test_proxy_task_dispatch_lifecycle(proxy_client: FlaskClient) -> None:
    attempt_id = uuid.uuid4()
    task_id = uuid.uuid4()
    run_id = uuid.uuid4()

    payload = {
        "attempt_id": str(attempt_id),
        "task_id": str(task_id),
        "run_id": str(run_id),
        "kind": "transfer",
        "operation": "copy",
        "timeout_s": 60,
        "source": {
            "alias": "src",
            "backend_type": "s3",
            "config": {"access_key_id": "SUPER_SECRET_KEY", "bucket": "src-bkt"},
            "path": "/data",
        },
        "destination": {
            "alias": "dst",
            "backend_type": "b2",
            "config": {"account": "B2_ACCOUNT_SECRET", "bucket": "dst-bkt"},
            "path": "/backup",
        },
        "secret_fields": ["access_key_id", "account"],
    }

    # 1. Dispatch task -> 202 Accepted
    disp_resp = proxy_client.post(
        "/v1/tasks",
        json=payload,
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )
    assert disp_resp.status_code == 202
    assert disp_resp.get_json()["status"] == "accepted"

    # 2. Re-dispatch same attempt_id -> 200 already_known (idempotent)
    disp_again = proxy_client.post(
        "/v1/tasks",
        json=payload,
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )
    assert disp_again.status_code == 200
    assert disp_again.get_json()["status"] == "already_known"

    # 3. Query status while running / waiting
    status_resp = proxy_client.get(
        f"/v1/tasks/{attempt_id}",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )
    assert status_resp.status_code == 200
    st_data = status_resp.get_json()
    assert st_data["attempt_id"] == str(attempt_id)
    assert st_data["status"] in ("assigned", "running", "succeeded")

    # 4. Wait for simulated completion (takes ~0.6s)
    time.sleep(0.8)

    status_after = proxy_client.get(
        f"/v1/tasks/{attempt_id}",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )
    assert status_after.status_code == 200
    st_done = status_after.get_json()
    assert st_done["status"] == "succeeded"
    assert st_done["progress"]["percentage"] == 100.0
    assert st_done["progress"]["checks_completed"] == 1
    assert st_done["progress"]["checks_total"] == 1
    assert st_done["progress"]["files_transferred"] == 4
    assert st_done["progress"]["files_total"] == 4

    # 5. Query logs and verify secret redaction
    logs_resp = proxy_client.get(
        f"/v1/tasks/{attempt_id}/logs",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )
    assert logs_resp.status_code == 200
    logs_data = logs_resp.get_json()
    assert len(logs_data["lines"]) >= 4

    all_logs_text = " ".join(line["message"] for line in logs_data["lines"])
    assert "SUPER_SECRET_KEY" not in all_logs_text
    assert "B2_ACCOUNT_SECRET" not in all_logs_text

    # 6. List tasks
    list_resp = proxy_client.get(
        "/v1/tasks",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )
    assert list_resp.status_code == 200
    tasks_list = list_resp.get_json()["tasks"]
    assert len(tasks_list) == 1

    # 7. Acknowledge task -> 200
    ack_resp = proxy_client.delete(
        f"/v1/tasks/{attempt_id}",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )
    assert ack_resp.status_code == 200
    assert ack_resp.get_json()["status"] == "acknowledged"


def test_proxy_task_cancellation(proxy_client: FlaskClient) -> None:
    attempt_id = uuid.uuid4()
    payload = {
        "attempt_id": str(attempt_id),
        "task_id": str(uuid.uuid4()),
        "run_id": str(uuid.uuid4()),
        "kind": "transfer",
        "operation": "copy",
        "timeout_s": 60,
        "source": {
            "alias": "src",
            "backend_type": "local",
            "config": {"path": "/tmp/a"},
            "path": "/a",
        },
    }

    proxy_client.post(
        "/v1/tasks",
        json=payload,
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )

    # Cancel immediately
    cancel_resp = proxy_client.post(
        f"/v1/tasks/{attempt_id}/cancel",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )
    assert cancel_resp.status_code == 200
    assert cancel_resp.get_json()["status"] == "cancelled"

    # Query status
    status_resp = proxy_client.get(
        f"/v1/tasks/{attempt_id}",
        headers={"Authorization": f"Bearer {TEST_TOKEN}"},
    )
    assert status_resp.get_json()["status"] == "cancelled"


def test_proxy_task_options_and_files_from(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Verify that options (max_depth, transfers, etc.) and files_from are passed to rclone."""
    from typing import Any
    from unittest.mock import MagicMock

    settings = ProxySettings(
        token=SecretStr(TEST_TOKEN),
        proxy_port=8443,
        proxy_state_dir=tmp_path / "proxy_state",
        proxy_tls_auto_self_signed=True,
    )
    runner = TaskRunner(rclone_bin="rclone")
    set_task_runner(runner)

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/rclone")

    captured_cmds: list[list[str]] = []

    def mock_popen(cmd: list[str], **_kwargs: Any) -> MagicMock:
        captured_cmds.append(cmd)
        proc = MagicMock()
        proc.poll.return_value = 0
        proc.returncode = 0
        proc.stdout = []
        proc.wait.return_value = 0
        return proc

    monkeypatch.setattr("subprocess.Popen", mock_popen)

    app = create_proxy_app(settings=settings)
    app.config["TESTING"] = True
    client = app.test_client()

    attempt_id = uuid.uuid4()
    payload = {
        "attempt_id": str(attempt_id),
        "task_id": str(uuid.uuid4()),
        "run_id": str(uuid.uuid4()),
        "kind": "transfer",
        "operation": "copy",
        "source": {
            "alias": "src",
            "backend_type": "local",
            "config": {},
            "path": "/source",
        },
        "destination": {
            "alias": "dst",
            "backend_type": "local",
            "config": {},
            "path": "/dest",
        },
        "options": {
            "max_depth": 1,
            "transfers": 4,
            "bwlimit": "10M",
            "filters": ["+ */**"],
        },
        "files_from": ["file1.txt", "file2.txt"],
    }

    resp = client.post("/v1/tasks", json=payload, headers={"Authorization": f"Bearer {TEST_TOKEN}"})
    assert resp.status_code == 202

    time.sleep(0.2)

    assert len(captured_cmds) == 1
    cmd = captured_cmds[0]
    assert "--max-depth" in cmd
    assert cmd[cmd.index("--max-depth") + 1] == "1"
    assert "--transfers" in cmd
    assert cmd[cmd.index("--transfers") + 1] == "4"
    assert "--bwlimit" in cmd
    assert cmd[cmd.index("--bwlimit") + 1] == "10M"
    assert "--files-from" in cmd
    assert "--filter" not in cmd


def test_proxy_task_additional_args(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Verify that additional_args from options are sanitized, split, and passed to rclone."""
    from typing import Any
    from unittest.mock import MagicMock

    settings = ProxySettings(
        token=SecretStr(TEST_TOKEN),
        proxy_port=8443,
        proxy_state_dir=tmp_path / "proxy_state",
        proxy_tls_auto_self_signed=True,
    )
    runner = TaskRunner(rclone_bin="rclone")
    set_task_runner(runner)

    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/rclone")

    captured_cmds: list[list[str]] = []

    def mock_popen(cmd: list[str], **_kwargs: Any) -> MagicMock:
        captured_cmds.append(cmd)
        proc = MagicMock()
        proc.poll.return_value = 0
        proc.returncode = 0
        proc.stdout = []
        proc.wait.return_value = 0
        return proc

    monkeypatch.setattr("subprocess.Popen", mock_popen)

    app = create_proxy_app(settings=settings)
    app.config["TESTING"] = True
    client = app.test_client()

    attempt_id = uuid.uuid4()
    payload = {
        "attempt_id": str(attempt_id),
        "task_id": str(uuid.uuid4()),
        "run_id": str(uuid.uuid4()),
        "kind": "transfer",
        "operation": "copy",
        "source": {
            "alias": "src",
            "backend_type": "local",
            "config": {},
            "path": "/source",
        },
        "destination": {
            "alias": "dst",
            "backend_type": "local",
            "config": {},
            "path": "/dest",
        },
        "options": {
            "transfers": 4,
            "check_first": True,
            "additional_args": [
                "--fast-list",
                "--min-size 10M",
                "-u",
                "--rc",  # forbidden - should be excluded
            ],
        },
    }

    resp = client.post("/v1/tasks", json=payload, headers={"Authorization": f"Bearer {TEST_TOKEN}"})
    assert resp.status_code == 202

    time.sleep(0.2)

    assert len(captured_cmds) == 1
    cmd = captured_cmds[0]
    # Standard managed flags
    assert "--transfers" in cmd
    assert cmd[cmd.index("--transfers") + 1] == "4"
    assert "--check-first" in cmd
    # Custom additional arguments
    assert "--fast-list" in cmd
    assert "--min-size" in cmd
    assert cmd[cmd.index("--min-size") + 1] == "10M"
    assert "-u" in cmd
    # Forbidden flag must not be included
    assert "--rc" not in cmd


def test_proxy_task_dispatch_with_referenced_remotes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify that referenced remotes (e.g. underlying SMB for Alias) are injected into rclone environment."""
    captured_envs: list[dict[str, str]] = []

    def fake_which(cmd: str) -> str:
        return "/usr/bin/rclone"

    class FakePopen:
        def __init__(self, cmd: list[str], **kwargs: Any) -> None:
            if "env" in kwargs:
                captured_envs.append(kwargs["env"])
            self.stdout = None
            self.stderr = None
            self.pid = 99999

        def poll(self) -> int | None:
            return 0

        def wait(self, timeout: float | None = None) -> int:
            return 0

    monkeypatch.setattr("shutil.which", fake_which)
    monkeypatch.setattr("subprocess.Popen", FakePopen)

    settings = ProxySettings(
        token=SecretStr(TEST_TOKEN),
        proxy_port=8443,
        proxy_state_dir=tmp_path / "proxy_state",
        proxy_tls_auto_self_signed=True,
    )
    runner = TaskRunner(rclone_bin="rclone")
    set_task_runner(runner)
    app = create_proxy_app(settings=settings)
    client = app.test_client()

    attempt_id = uuid.uuid4()
    payload = {
        "attempt_id": str(attempt_id),
        "task_id": str(uuid.uuid4()),
        "run_id": str(uuid.uuid4()),
        "kind": "transfer",
        "operation": "copy",
        "source": {
            "alias": "src",
            "backend_type": "alias",
            "config": {"remote": "my_smb:shared/folder"},
            "path": "",
        },
        "destination": {
            "alias": "dst",
            "backend_type": "local",
            "config": {},
            "path": "/dest",
        },
        "referenced_remotes": [
            {
                "alias": "my_smb",
                "backend_type": "smb",
                "config": {"host": "192.168.1.100", "user": "smbuser", "pass": "secret123"},
                "path": "",
            }
        ],
    }

    resp = client.post("/v1/tasks", json=payload, headers={"Authorization": f"Bearer {TEST_TOKEN}"})
    assert resp.status_code == 202

    time.sleep(0.2)

    assert len(captured_envs) == 1
    env = captured_envs[0]
    # Verify alias configuration
    assert env.get("RCLONE_CONFIG_SRC_TYPE") == "alias"
    assert env.get("RCLONE_CONFIG_SRC_REMOTE") == "my_smb:shared/folder"
    # Verify underlying referenced SMB configuration
    assert env.get("RCLONE_CONFIG_MY_SMB_TYPE") == "smb"
    assert "RCLONE_CONFIG_MY_SMB_PASS" in env


def test_proxy_test_remote_crypt_obscures_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify that Crypt remote passwords are obscured so rclone can reveal them."""
    captured_envs: list[dict[str, str]] = []

    def fake_which(cmd: str) -> str:
        return "/usr/bin/rclone"

    def fake_run(cmd: list[str], **kwargs: Any) -> Any:
        if "env" in kwargs:
            captured_envs.append(kwargs["env"])

        class FakeProc:
            returncode = 0
            stdout = ""
            stderr = ""

        return FakeProc()

    monkeypatch.setattr("shutil.which", fake_which)
    monkeypatch.setattr("subprocess.run", fake_run)

    settings = ProxySettings(
        token=SecretStr(TEST_TOKEN),
        proxy_port=8443,
        proxy_state_dir=tmp_path / "proxy_state",
        proxy_tls_auto_self_signed=True,
    )
    runner = TaskRunner(rclone_bin="rclone")
    set_task_runner(runner)
    app = create_proxy_app(settings=settings)
    client = app.test_client()

    payload = {
        "backend_type": "crypt",
        "config": {
            "remote": "my_smb:encrypted_data",
            "password": "cleartext_password_1",
            "password2": "cleartext_password_2",
        },
        "path": "",
        "referenced_remotes": [
            {
                "alias": "my_smb",
                "backend_type": "smb",
                "config": {"host": "192.168.1.100", "user": "smbuser", "pass": "smbpass"},
            }
        ],
    }

    resp = client.post(
        "/v1/remotes/test", json=payload, headers={"Authorization": f"Bearer {TEST_TOKEN}"}
    )
    assert resp.status_code == 200

    assert len(captured_envs) == 1
    env = captured_envs[0]
    # Check that crypt passwords were obscured
    assert env.get("RCLONE_CONFIG_REMOTE_TEST_TYPE") == "crypt"
    pw1_obs = env.get("RCLONE_CONFIG_REMOTE_TEST_PASSWORD")
    pw2_obs = env.get("RCLONE_CONFIG_REMOTE_TEST_PASSWORD2")
    assert pw1_obs is not None and pw1_obs != "cleartext_password_1"
    assert pw2_obs is not None and pw2_obs != "cleartext_password_2"

    # Also check referenced smb pass was obscured
    smb_pass_obs = env.get("RCLONE_CONFIG_MY_SMB_PASS")
    assert smb_pass_obs is not None and smb_pass_obs != "smbpass"
