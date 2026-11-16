"""Unit tests for Proxy /v1/remotes/browse endpoint with lsjson support."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import MagicMock, patch

from pydantic import SecretStr

from embervault_common.config import ProxySettings
from embervault_proxy.factory import create_proxy_app


def test_proxy_browse_with_lsjson_returns_size_and_mod_time() -> None:
    token = SecretStr("t" * 32)
    settings = ProxySettings(token=token, proxy_port=8443, log_level="INFO")
    app = create_proxy_app(settings)
    client = app.test_client()

    fake_lsjson_stdout = json.dumps(
        [
            {
                "Path": "folder_docs",
                "Name": "folder_docs",
                "Size": -1,
                "MimeType": "inode/directory",
                "ModTime": "2026-11-02T14:30:00Z",
                "IsDir": True,
            },
            {
                "Path": "report.pdf",
                "Name": "report.pdf",
                "Size": 1048576,
                "MimeType": "application/pdf",
                "ModTime": "2026-11-03T09:15:00.123456789Z",
                "IsDir": False,
            },
        ]
    )

    fake_proc = MagicMock()
    fake_proc.returncode = 0
    fake_proc.stdout = fake_lsjson_stdout
    fake_proc.stderr = ""

    with (
        patch("shutil.which", return_value="/usr/bin/rclone"),
        patch("subprocess.run", return_value=fake_proc) as mock_run,
    ):
        res = client.post(
            "/v1/remotes/browse",
            headers={"Authorization": f"Bearer {'t' * 32}"},
            json={
                "backend_type": "s3",
                "config": {"provider": "AWS", "endpoint": "http://minio:9000"},
                "path": "test-bucket",
            },
        )

        assert res.status_code == 200
        data = res.json
        assert data["status"] == "ok"
        assert data["directories"] == ["folder_docs"]
        assert data["directory_details"] == [
            {"name": "folder_docs", "mod_time": "2026-11-02T14:30:00Z"}
        ]
        assert data["files"] == [
            {
                "name": "report.pdf",
                "size": 1048576,
                "mod_time": "2026-11-03T09:15:00.123456789Z",
            }
        ]

        # Verify rclone was called with lsjson
        call_args = mock_run.call_args[0][0]
        assert "lsjson" in call_args
        assert "--max-depth" in call_args


def test_proxy_browse_fallback_stub_has_size_and_mod_time() -> None:
    token = SecretStr("t" * 32)
    settings = ProxySettings(token=token, proxy_port=8443, log_level="INFO")
    app = create_proxy_app(settings)
    client = app.test_client()

    with patch("shutil.which", return_value=None):
        res = client.post(
            "/v1/remotes/browse",
            headers={"Authorization": f"Bearer {'t' * 32}"},
            json={
                "backend_type": "s3",
                "config": {},
                "path": "",
            },
        )

        assert res.status_code == 200
        data = res.json
        assert data["status"] == "ok"
        assert len(data["directories"]) > 0
        assert len(data["files"]) > 0
        assert data["files"][0]["size"] > 0
        assert "mod_time" in data["files"][0]
        assert data["files"][0]["mod_time"] is not None
