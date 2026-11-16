"""Contract tests validating Pydantic models against exported JSON schemas and schema integrity."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from pydantic import BaseModel, ValidationError

from embervault_common.contracts import (
    CreateDiscoveryRequest,
    DiscoverTaskResultPayload,
    DiscoveryResponse,
    DiscoveryStatus,
    DiscoveryStatusLevel,
    ErrorClass,
    ErrorCode,
    ProxyHealthResponse,
    ProxyProbeRequest,
    ProxyProbeResponse,
    RemoteConfigPayload,
    TaskCancelResponse,
    TaskDispatchPayload,
    TaskDispatchResponse,
    TaskListResponse,
    TaskLogsResponse,
    TaskOperation,
    TaskProgress,
    TaskState,
    TaskStatusResponse,
)

SCHEMAS_DIR = Path(__file__).parent / "schemas"

CONTRACT_MODELS: dict[str, type[BaseModel]] = {
    "proxy_health_response.json": ProxyHealthResponse,
    "remote_config_payload.json": RemoteConfigPayload,
    "task_dispatch_payload.json": TaskDispatchPayload,
    "task_dispatch_response.json": TaskDispatchResponse,
    "task_progress.json": TaskProgress,
    "task_status_response.json": TaskStatusResponse,
    "task_logs_response.json": TaskLogsResponse,
    "task_cancel_response.json": TaskCancelResponse,
    "task_list_response.json": TaskListResponse,
    "discover_task_result_payload.json": DiscoverTaskResultPayload,
    "create_discovery_request.json": CreateDiscoveryRequest,
    "discovery_response.json": DiscoveryResponse,
    "proxy_probe_request.json": ProxyProbeRequest,
    "proxy_probe_response.json": ProxyProbeResponse,
}


def test_export_and_verify_json_schemas() -> None:
    """Ensure JSON Schema files exist and match the Pydantic models."""
    SCHEMAS_DIR.mkdir(parents=True, exist_ok=True)

    for filename, model in CONTRACT_MODELS.items():
        schema_path = SCHEMAS_DIR / filename
        current_schema = model.model_json_schema()

        # If file doesn't exist, create it
        if not schema_path.exists():
            schema_path.write_text(json.dumps(current_schema, indent=2) + "\n", encoding="utf-8")

        stored_schema = json.loads(schema_path.read_text(encoding="utf-8"))
        assert stored_schema == current_schema, f"Schema mismatch in {filename}"


class TestContractValidation:
    """Test valid and invalid instances of contracts."""

    def test_proxy_health_response_valid(self) -> None:
        payload = {
            "status": "ok",
            "proxy_version": "0.1.0",
            "rclone_version": "rclone v1.68.2",
            "uptime_s": 123.45,
            "capacity": 2,
            "running_tasks": 1,
            "server_time": "2026-10-16T18:00:00Z",
        }
        res = ProxyHealthResponse.model_validate(payload)
        assert res.capacity == 2
        assert res.running_tasks == 1

    def test_proxy_health_response_invalid(self) -> None:
        # Negative capacity not allowed
        with pytest.raises(ValidationError):
            ProxyHealthResponse.model_validate(
                {
                    "proxy_version": "0.1.0",
                    "rclone_version": "rclone v1.68.2",
                    "uptime_s": 10.0,
                    "capacity": 0,
                    "running_tasks": 0,
                }
            )

    def test_task_dispatch_payload_valid(self) -> None:
        payload: dict[str, Any] = {
            "attempt_id": str(uuid4()),
            "task_id": str(uuid4()),
            "run_id": str(uuid4()),
            "kind": "transfer",
            "operation": "copy",
            "timeout_s": 1800,
            "source": {
                "alias": "src",
                "backend_type": "drive",
                "config": {"scope": "drive.readonly"},
                "path": "backups/2026",
            },
            "destination": {
                "alias": "dst",
                "backend_type": "s3",
                "config": {"provider": "AWS"},
                "path": "vault-bucket/backups",
            },
            "options": {"transfers": 4},
            "secret_fields": ["access_key_id", "secret_access_key"],
        }
        dispatch = TaskDispatchPayload.model_validate(payload)
        assert dispatch.kind == "transfer"
        assert dispatch.operation == TaskOperation.COPY
        assert dispatch.timeout_s == 1800
        assert dispatch.destination is not None
        assert dispatch.destination.alias == "dst"

    def test_discover_task_result_payload(self) -> None:
        subfolders = ["dir_alpha", "dir_beta", "dir_gamma"]
        root_files = ["readme.txt", "archive.zip"]
        discover_res = DiscoverTaskResultPayload(
            subfolders=subfolders,
            root_files=root_files,
            total_subfolders=len(subfolders),
            total_root_files=len(root_files),
            truncated=False,
            task_count_estimate=1 + len(subfolders),  # 1 root_files + 3 subfolders = 4
            status_level=DiscoveryStatusLevel.OK,
        )
        assert discover_res.total_subfolders == 3
        assert discover_res.task_count_estimate == 4
        assert discover_res.status_level == DiscoveryStatusLevel.OK

    def test_discovery_response_internal(self) -> None:
        disc_id = uuid4()
        remote_id = uuid4()
        resp = DiscoveryResponse(
            id=disc_id,
            source_remote_id=remote_id,
            source_path="photos/2026",
            status=DiscoveryStatus.VERIFIED,
            subfolders=["january", "february"],
            root_files=["index.html"],
            total_subfolders=2,
            total_root_files=1,
            task_count_estimate=3,
            status_level=DiscoveryStatusLevel.OK,
        )
        assert resp.id == disc_id
        assert resp.status == DiscoveryStatus.VERIFIED

    def test_proxy_probe_request_and_response(self) -> None:
        req = ProxyProbeRequest(
            host="proxy-1.internal",
            port=8443,
            token="secret_token_1234567890_abcdefghij",  # type: ignore[arg-type]
        )
        assert req.port == 8443

        resp = ProxyProbeResponse(
            cert_fingerprint_sha256="aa" * 32,
            status="ok",
            latency_ms=12.5,
            proxy_version="0.1.0",
        )
        assert len(resp.cert_fingerprint_sha256) == 64

    def test_task_status_response_error(self) -> None:
        status_resp = TaskStatusResponse(
            attempt_id=uuid4(),
            status=TaskState.FAILED,
            exit_code=1,
            error_code=ErrorCode.SOURCE_NOT_FOUND,
            error_class=ErrorClass.PERMANENT,
            error_message="Directory 'photos/2026' was not found on remote",
        )
        assert status_resp.status == TaskState.FAILED
        assert status_resp.error_code == ErrorCode.SOURCE_NOT_FOUND
        assert status_resp.error_class == ErrorClass.PERMANENT
