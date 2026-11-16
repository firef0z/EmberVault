"""Internal API contracts for communication between Web App and Orchestrator."""

from __future__ import annotations

import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from embervault_common.contracts.enums import DiscoveryStatus, DiscoveryStatusLevel
from embervault_common.contracts.proxy import BaseContract


class CreateDiscoveryRequest(BaseContract):
    """Payload for POST /internal/v1/discoveries."""

    source_remote_id: UUID = Field(..., description="ID of source remote to inspect")
    source_path: str = Field(..., description="Path/folder to discover inside the remote")
    assigned_proxy_ids: list[UUID] | None = Field(
        default=None,
        description="Optional list of proxy IDs permitted to perform the discovery",
    )


class DiscoveryResponse(BaseContract):
    """Payload for GET /internal/v1/discoveries/{id}."""

    id: UUID = Field(..., description="Discovery task UUID")
    source_remote_id: UUID = Field(..., description="Source remote UUID")
    source_path: str = Field(..., description="Source path inspected")
    status: DiscoveryStatus = Field(..., description="Current discovery status")
    subfolders: list[str] = Field(
        default_factory=list,
        description="First-level subfolder names discovered",
    )
    root_files: list[str] = Field(
        default_factory=list,
        description="Root file names discovered",
    )
    total_subfolders: int = Field(default=0, ge=0, description="Total subfolders count")
    total_root_files: int = Field(default=0, ge=0, description="Total root files count")
    truncated: bool = Field(default=False, description="Whether directory listing was capped")
    task_count_estimate: int = Field(
        default=0, ge=0, description="Estimated tasks (1 + subfolders)"
    )
    status_level: DiscoveryStatusLevel = Field(
        default=DiscoveryStatusLevel.OK,
        description="Threshold evaluation (ok, warn, blocked)",
    )
    error_message: str | None = Field(default=None, description="Error details if discovery failed")
    created_at: datetime.datetime = Field(
        default_factory=lambda: datetime.datetime.now(datetime.UTC),
        description="Creation timestamp (UTC)",
    )
    completed_at: datetime.datetime | None = Field(
        default=None,
        description="Completion timestamp (UTC)",
    )


class ProxyProbeRequest(BaseModel):
    """Payload for POST /internal/v1/proxies/probe."""

    model_config = ConfigDict(
        populate_by_name=True,
        extra="forbid",
    )

    host: str = Field(..., description="Proxy hostname or IP address")
    port: int = Field(default=8443, ge=1, le=65535, description="Proxy HTTPS port")
    token: SecretStr = Field(..., description="Proxy authentication Bearer token")


class ProxyProbeResponse(BaseContract):
    """Response returned by POST /internal/v1/proxies/probe."""

    cert_fingerprint_sha256: str = Field(
        ...,
        description="Canonical 64-char lowercase SHA-256 fingerprint of the proxy's TLS certificate",
    )
    status: str = Field(default="ok", description="Probe status: 'ok' or error code")
    latency_ms: float | None = Field(
        default=None, ge=0, description="Observed round-trip latency in ms"
    )
    proxy_version: str | None = Field(default=None, description="Remote proxy software version")
    rclone_version: str | None = Field(default=None, description="Remote proxy rclone version")
    cert_expires_at: datetime.datetime | None = Field(
        default=None, description="Expiration date (UTC) of the proxy TLS certificate"
    )


class ProxyRenewCertResponse(BaseContract):
    """Response returned by POST /internal/v1/proxies/<id>/renew-cert."""

    status: str = Field(default="ok", description="Status string: 'ok' or error code")
    message: str = Field(..., description="Human-readable outcome message")
    fingerprint: str = Field(..., description="Canonical 64-char lowercase SHA-256 fingerprint")
    fingerprint_formatted: str = Field(..., description="Formatted SHA-256 fingerprint (XX:XX:...)")
    cert_expires_at: datetime.datetime | None = Field(
        default=None, description="Expiration date (UTC) of the newly generated certificate"
    )


class RemoteTestRequest(BaseModel):
    """Payload for POST /internal/v1/remotes/test."""

    model_config = ConfigDict(
        populate_by_name=True,
        extra="forbid",
    )

    backend_type: str = Field(..., description="RClone backend provider type")
    config: dict[str, Any] = Field(
        default_factory=dict, description="Decrypted remote configuration"
    )
    path: str = Field(default="", description="Path or bucket inside the remote to test")
    proxy_id: UUID | None = Field(
        default=None, description="Optional specific proxy ID to execute test on"
    )
    referenced_remotes: dict[str, dict[str, Any]] | None = Field(
        default=None,
        description="Configurations of upstream/referenced remotes for wrapper backends (alias, crypt, etc.)",
    )


class RemoteTestResponse(BaseContract):
    """Response returned by POST /internal/v1/remotes/test."""

    status: str = Field(..., description="'ok' or 'error'")
    message: str = Field(..., description="Human-readable result or error description")
    latency_ms: float | None = Field(
        default=None, ge=0, description="Round-trip probe latency in ms"
    )
    items_found: int | None = Field(
        default=None, ge=0, description="Number of items or directories listed"
    )
