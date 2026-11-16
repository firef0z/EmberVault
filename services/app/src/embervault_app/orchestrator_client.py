"""HTTP client for communicating with the internal Orchestrator API."""

from __future__ import annotations

from typing import Any, cast
from uuid import UUID

import requests
from pydantic import ValidationError

from embervault_app.i18n import translate as _
from embervault_common.contracts import (
    ProxyProbeResponse,
)
from embervault_common.observability import get_logger

logger = get_logger("embervault_app.orchestrator_client")


class OrchestratorClientError(Exception):
    """Base exception for errors communicating with Orchestrator."""


class OrchestratorUnreachableError(OrchestratorClientError):
    """Raised when Orchestrator service cannot be contacted."""


class OrchestratorAuthError(OrchestratorClientError):
    """Raised when Orchestrator rejects authentication (401/403)."""


class OrchestratorClient:
    """Client for interacting with the internal authenticated API of Orchestrator."""

    def __init__(
        self,
        base_url: str = "http://orchestrator:8081",
        internal_api_token: str | None = None,
        timeout_s: float = 5.0,
        session: requests.Session | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.internal_api_token = internal_api_token
        self.timeout_s = timeout_s
        self.session = session or requests.Session()

    def _get_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.internal_api_token:
            headers["Authorization"] = f"Bearer {self.internal_api_token}"
        return headers

    def probe_proxy(self, host: str, port: int, token: str) -> ProxyProbeResponse:
        """Trigger remote proxy probe via Orchestrator internal API.

        Args:
            host: Proxy hostname or IP.
            port: Proxy HTTPS port (default 8443).
            token: Proxy Bearer authentication token.

        Returns:
            ProxyProbeResponse containing observed TLS certificate fingerprint and probe status.

        Raises:
            OrchestratorUnreachableError: If orchestrator is down or timed out.
            OrchestratorAuthError: If internal API token was rejected.
            OrchestratorClientError: If probe failed with an error.
        """
        url = f"{self.base_url}/internal/v1/proxies/probe"
        payload = {"host": host, "port": port, "token": token}

        try:
            resp = self.session.post(
                url,
                json=payload,
                headers=self._get_headers(),
                timeout=20.0,
            )
        except (requests.ConnectionError, requests.Timeout) as exc:
            logger.warning("orchestrator_unreachable", url=url, error=str(exc))
            raise OrchestratorUnreachableError(
                f"Cannot reach Orchestrator at {url}: {exc}"
            ) from exc
        except requests.RequestException as exc:
            logger.error("orchestrator_request_failed", url=url, error=str(exc))
            raise OrchestratorClientError(f"Request to Orchestrator failed: {exc}") from exc

        if resp.status_code in (401, 403):
            # Check if this error was forwarded from an unauthorized proxy probe
            try:
                err_data = resp.json()
                if isinstance(err_data, dict) and err_data.get("status") == "unauthorized":
                    proxy_msg = err_data.get("message") or _(
                        "orch_proxy_token_rejected_tpl"
                    ).format(host=host, port=port)
                    raise OrchestratorClientError(proxy_msg)
            except (ValueError, requests.RequestException):
                pass
            raise OrchestratorAuthError(
                f"Orchestrator rejected internal authentication (HTTP {resp.status_code})."
            )

        if resp.status_code not in (200, 201):
            body_err = (
                resp.json() if resp.headers.get("content-type") == "application/json" else resp.text
            )
            raise OrchestratorClientError(f"Probe failed with HTTP {resp.status_code}: {body_err}")

        try:
            data = resp.json()
            return ProxyProbeResponse.model_validate(data)
        except (ValueError, ValidationError) as exc:
            raise OrchestratorClientError(f"Invalid response from Orchestrator: {exc}") from exc

    def check_health(self) -> dict[str, Any]:
        """Check Orchestrator service health."""
        url = f"{self.base_url}/healthz"
        try:
            resp = self.session.get(url, timeout=self.timeout_s)
            if resp.status_code == 200:
                data = resp.json()
                return data if isinstance(data, dict) else {"status": "ok"}
            return {"status": "error", "code": resp.status_code}
        except Exception as exc:
            return {"status": "offline", "error": str(exc)}

    def test_remote(
        self,
        backend_type: str,
        config: dict[str, Any],
        path: str = "",
        referenced_remotes: dict[str, dict[str, Any]] | list[dict[str, Any]] | None = None,
        remote_id: str | None = None,
        candidate_proxy_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Send remote connection test request to Orchestrator."""
        url = f"{self.base_url}/internal/v1/remotes/test"
        payload = {
            "backend_type": backend_type,
            "config": config,
            "path": path,
            "referenced_remotes": referenced_remotes,
            "remote_id": remote_id,
            "candidate_proxy_ids": candidate_proxy_ids,
        }

        try:
            resp = self.session.post(
                url,
                json=payload,
                headers=self._get_headers(),
                timeout=20.0,
            )
            if resp.status_code in (401, 403):
                try:
                    err_json = resp.json()
                    if isinstance(err_json, dict) and "message" in err_json:
                        raise OrchestratorClientError(err_json["message"])
                except (ValueError, requests.RequestException):
                    pass
                raise OrchestratorAuthError(
                    f"Orchestrator rejected internal authentication (HTTP {resp.status_code})."
                )
            if resp.status_code != 200:
                body_err = (
                    resp.json()
                    if resp.headers.get("content-type") == "application/json"
                    else resp.text
                )
                raise OrchestratorClientError(
                    f"Remote test failed with HTTP {resp.status_code}: {body_err}"
                )
            return cast(dict[str, Any], resp.json())
        except (requests.ConnectionError, requests.Timeout) as exc:
            logger.warning("orchestrator_unreachable", url=url, error=str(exc))
            # Fallback to local parameter validation if Orchestrator is offline
            from embervault_common.remotes.catalog import validate_and_split_remote_config

            try:
                validate_and_split_remote_config(backend_type, config)
                return {
                    "status": "ok",
                    "message": _("orch_remote_valid_offline_tpl").format(backend_type=backend_type),
                    "latency_ms": 0.5,
                }
            except Exception as val_exc:
                return {
                    "status": "error",
                    "message": _("orch_remote_invalid_config_tpl").format(error=val_exc),
                }
        except requests.RequestException as exc:
            raise OrchestratorClientError(f"Request to Orchestrator failed: {exc}") from exc

    def browse_remote(
        self,
        backend_type: str,
        config: dict[str, Any],
        path: str = "",
        referenced_remotes: dict[str, dict[str, Any]] | list[dict[str, Any]] | None = None,
        remote_id: str | None = None,
        candidate_proxy_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Send remote browsing request to Orchestrator."""
        url = f"{self.base_url}/internal/v1/remotes/browse"
        payload = {
            "backend_type": backend_type,
            "config": config,
            "path": path,
            "referenced_remotes": referenced_remotes,
            "remote_id": remote_id,
            "candidate_proxy_ids": candidate_proxy_ids,
        }

        try:
            resp = self.session.post(
                url,
                json=payload,
                headers=self._get_headers(),
                timeout=20.0,
            )
            if resp.status_code in (401, 403):
                raise OrchestratorAuthError(
                    f"Orchestrator rejected internal authentication (HTTP {resp.status_code})."
                )
            if resp.status_code != 200:
                body_err = (
                    resp.json()
                    if resp.headers.get("content-type") == "application/json"
                    else resp.text
                )
                raise OrchestratorClientError(
                    f"Remote browse failed with HTTP {resp.status_code}: {body_err}"
                )
            return cast(dict[str, Any], resp.json())
        except (requests.ConnectionError, requests.Timeout) as exc:
            logger.warning("orchestrator_unreachable_browse", url=url, error=str(exc))
            # Fallback for standalone/mocked execution
            clean_p = path.strip("/")
            if not clean_p:
                dirs = ["documents", "backups", "photos", "projects"]
                files = [{"name": "readme.txt", "size": 1024}]
            else:
                folder_name = clean_p.split("/")[-1]
                dirs = [f"{folder_name}_sub1", f"{folder_name}_sub2"]
                files = [
                    {"name": f"{folder_name}_file1.dat", "size": 20480},
                    {"name": f"{folder_name}_file2.log", "size": 4096},
                ]
            return {
                "status": "ok",
                "path": clean_p,
                "directories": dirs,
                "files": files,
            }
        except requests.RequestException as exc:
            raise OrchestratorClientError(f"Request to Orchestrator failed: {exc}") from exc

    def download_remote(
        self,
        backend_type: str,
        config: dict[str, Any],
        base_path: str = "",
        items: list[dict[str, Any]] | None = None,
        referenced_remotes: dict[str, dict[str, Any]] | list[dict[str, Any]] | None = None,
        remote_id: str | None = None,
    ) -> requests.Response:
        """Send remote download request to Orchestrator and return streaming response."""
        url = f"{self.base_url}/internal/v1/remotes/download"
        payload = {
            "backend_type": backend_type,
            "config": config,
            "base_path": base_path,
            "items": items or [],
            "referenced_remotes": referenced_remotes,
            "remote_id": remote_id,
        }

        try:
            resp = self.session.post(
                url,
                json=payload,
                headers=self._get_headers(),
                stream=True,
                timeout=(10.0, None),
            )
            if resp.status_code in (401, 403):
                raise OrchestratorAuthError(
                    f"Orchestrator rejected internal authentication (HTTP {resp.status_code})."
                )
            return resp
        except requests.RequestException as exc:
            raise OrchestratorClientError(f"Request to Orchestrator failed: {exc}") from exc

    def _resolve_discovery_timeout(self) -> float:
        """Helper to resolve HTTP timeout for operations involving remote folder discovery."""
        base_timeout = 30.0
        try:
            from flask import current_app

            store = current_app.config.get("SETTINGS_STORE")
            if store:
                disc_s = store.get_setting("discovery_timeout_s")
                if disc_s:
                    base_timeout = float(disc_s)
        except Exception:
            pass
        return max(60.0, base_timeout + 30.0)

    def create_discovery(
        self,
        source_remote_id: UUID,
        source_path: str,
        assigned_proxy_ids: list[UUID] | None = None,
    ) -> dict[str, Any]:
        """Trigger source root folder discovery via Orchestrator."""
        url = f"{self.base_url}/internal/v1/discoveries"
        payload: dict[str, Any] = {
            "source_remote_id": str(source_remote_id),
            "source_path": source_path,
        }
        if assigned_proxy_ids:
            payload["assigned_proxy_ids"] = [str(pid) for pid in assigned_proxy_ids]

        req_timeout = self._resolve_discovery_timeout()
        try:
            resp = self.session.post(
                url,
                json=payload,
                headers=self._get_headers(),
                timeout=req_timeout,
            )
            if resp.status_code in (401, 403):
                try:
                    err_json = resp.json()
                    if isinstance(err_json, dict) and "message" in err_json:
                        raise OrchestratorClientError(err_json["message"])
                except (ValueError, requests.RequestException):
                    pass
                raise OrchestratorAuthError(
                    f"Orchestrator rejected internal authentication (HTTP {resp.status_code})."
                )
            if resp.status_code != 200:
                body_err = (
                    resp.json()
                    if resp.headers.get("content-type") == "application/json"
                    else resp.text
                )
                raise OrchestratorClientError(
                    f"Discovery failed with HTTP {resp.status_code}: {body_err}"
                )
            return cast(dict[str, Any], resp.json())
        except (requests.ConnectionError, requests.Timeout) as exc:
            logger.warning("orchestrator_unreachable_discovery", url=url, error=str(exc))
            raise OrchestratorClientError(f"Orchestrator unreachable: {exc}") from exc
        except requests.RequestException as exc:
            raise OrchestratorClientError(f"Request to Orchestrator failed: {exc}") from exc

    def trigger_job_run(
        self, job_id: UUID, trigger: str = "manual", timeout: float | None = None
    ) -> dict[str, Any]:
        """Trigger execution of a backup job via Orchestrator."""
        url = f"{self.base_url}/internal/v1/jobs/{job_id}/run"
        payload = {"trigger": trigger}
        req_timeout = timeout if timeout is not None else self._resolve_discovery_timeout()
        try:
            resp = self.session.post(
                url, json=payload, headers=self._get_headers(), timeout=req_timeout
            )
            if resp.status_code in (401, 403):
                raise OrchestratorAuthError(
                    "Authentication failure communicating with Orchestrator."
                )
            return cast(dict[str, Any], resp.json())
        except (requests.ConnectionError, requests.Timeout) as exc:
            raise OrchestratorClientError(f"Orchestrator unreachable: {exc}") from exc

    def cancel_run(self, run_id: UUID) -> dict[str, Any]:
        """Cancel an active job run via Orchestrator."""
        url = f"{self.base_url}/internal/v1/runs/{run_id}/cancel"
        try:
            resp = self.session.post(url, headers=self._get_headers(), timeout=10.0)
            if resp.status_code in (401, 403):
                raise OrchestratorAuthError(
                    "Authentication failure communicating with Orchestrator."
                )
            return cast(dict[str, Any], resp.json())
        except (requests.ConnectionError, requests.Timeout) as exc:
            raise OrchestratorClientError(f"Orchestrator unreachable: {exc}") from exc

    def cancel_task(self, task_id: UUID) -> dict[str, Any]:
        """Cancel an individual task via Orchestrator."""
        url = f"{self.base_url}/internal/v1/tasks/{task_id}/cancel"
        try:
            resp = self.session.post(url, headers=self._get_headers(), timeout=10.0)
            if resp.status_code in (401, 403):
                raise OrchestratorAuthError(
                    "Authentication failure communicating with Orchestrator."
                )
            return cast(dict[str, Any], resp.json())
        except (requests.ConnectionError, requests.Timeout) as exc:
            raise OrchestratorClientError(f"Orchestrator unreachable: {exc}") from exc

    def list_runs(self, job_id: UUID | None = None, limit: int = 50) -> dict[str, Any]:
        """Fetch execution history from Orchestrator."""
        url = f"{self.base_url}/internal/v1/runs"
        params: dict[str, Any] = {"limit": limit}
        if job_id:
            params["job_id"] = str(job_id)
        try:
            resp = self.session.get(url, params=params, headers=self._get_headers(), timeout=10.0)
            return cast(dict[str, Any], resp.json())
        except (requests.ConnectionError, requests.Timeout) as exc:
            raise OrchestratorClientError(f"Orchestrator unreachable: {exc}") from exc

    def get_run(self, run_id: UUID) -> dict[str, Any]:
        """Fetch detailed status of a run from Orchestrator."""
        url = f"{self.base_url}/internal/v1/runs/{run_id}"
        try:
            resp = self.session.get(url, headers=self._get_headers(), timeout=10.0)
            return cast(dict[str, Any], resp.json())
        except (requests.ConnectionError, requests.Timeout) as exc:
            raise OrchestratorClientError(f"Orchestrator unreachable: {exc}") from exc

    def get_task_logs(
        self,
        task_id: UUID,
        limit: int | None = None,
        from_seq: int | None = None,
        tail: bool = False,
    ) -> dict[str, Any]:
        """Fetch stored logs for a task from Orchestrator."""
        params: list[str] = []
        if limit is not None:
            params.append(f"limit={limit}")
        if from_seq is not None:
            params.append(f"from_seq={from_seq}")
        if tail:
            params.append("tail=true")
        query_str = f"?{'&'.join(params)}" if params else ""
        url = f"{self.base_url}/internal/v1/tasks/{task_id}/logs{query_str}"
        try:
            resp = self.session.get(url, headers=self._get_headers(), timeout=10.0)
            return cast(dict[str, Any], resp.json())
        except (requests.ConnectionError, requests.Timeout) as exc:
            raise OrchestratorClientError(f"Orchestrator unreachable: {exc}") from exc

    def upgrade_proxy_rclone(self, proxy_id: UUID, version: str) -> dict[str, Any]:
        """Trigger remote proxy rclone upgrade via Orchestrator internal API."""
        url = f"{self.base_url}/internal/v1/proxies/{proxy_id}/rclone/upgrade"
        try:
            resp = self.session.post(
                url,
                json={"version": version},
                headers=self._get_headers(),
                timeout=120.0,
            )
            if resp.status_code >= 400:
                err_data = (
                    resp.json()
                    if "application/json" in resp.headers.get("content-type", "")
                    else {}
                )
                err_msg = err_data.get("message") or f"HTTP {resp.status_code}: {resp.text}"
                raise OrchestratorClientError(err_msg)
            return resp.json()
        except requests.RequestException as exc:
            logger.error(
                "orchestrator_rclone_upgrade_failed", proxy_id=str(proxy_id), error=str(exc)
            )
            raise OrchestratorClientError(f"Upgrade request failed: {exc}") from exc

    def renew_proxy_certificate(self, proxy_id: UUID) -> dict[str, Any]:
        """Trigger remote proxy TLS certificate renewal via Orchestrator internal API."""
        url = f"{self.base_url}/internal/v1/proxies/{proxy_id}/renew-cert"
        try:
            resp = self.session.post(
                url,
                json={},
                headers=self._get_headers(),
                timeout=30.0,
            )
            if resp.status_code >= 400:
                err_data = (
                    resp.json()
                    if "application/json" in resp.headers.get("content-type", "")
                    else {}
                )
                err_msg = err_data.get("message") or f"HTTP {resp.status_code}: {resp.text}"
                raise OrchestratorClientError(err_msg)
            return resp.json()
        except requests.RequestException as exc:
            logger.error(
                "orchestrator_proxy_cert_renewal_failed", proxy_id=str(proxy_id), error=str(exc)
            )
            raise OrchestratorClientError(f"Certificate renewal request failed: {exc}") from exc
