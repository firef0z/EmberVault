"""HTTPS client for communicating with EmberVault Proxy workers with TLS certificate pinning."""

from __future__ import annotations

import socket
import ssl
import time
import uuid
from typing import Any, cast

import requests
import urllib3.exceptions
from requests.adapters import HTTPAdapter

from embervault_common.contracts import (
    EMBERVAULT_PROTOCOL_VERSION,
    PROTOCOL_HEADER,
    REQUEST_ID_HEADER,
    ProxyHealthResponse,
    ProxyProbeResponse,
)
from embervault_common.observability import get_logger
from embervault_common.security import (
    TLSFingerprintError,
    TLSFingerprintMismatchError,
    compute_cert_fingerprint,
    extract_cert_expiration,
    normalize_fingerprint,
)

logger = get_logger("embervault_orchestrator.proxy_client")


class ProxyClientError(Exception):
    """Base exception for proxy client communication failures."""


class ProxyUnreachableError(ProxyClientError):
    """Raised when proxy cannot be reached (connection refused, timeout, network error)."""


class ProxyUnauthorizedError(ProxyClientError):
    """Raised when proxy returns HTTP 401 Unauthorized (invalid or revoked token)."""


class FingerprintAdapter(HTTPAdapter):
    """Custom requests HTTPAdapter that binds a specific SHA-256 certificate fingerprint."""

    def __init__(self, fingerprint: str, **kwargs: Any) -> None:
        self.fingerprint = normalize_fingerprint(fingerprint)
        super().__init__(**kwargs)

    def init_poolmanager(
        self,
        connections: int,
        maxsize: int,
        block: bool = False,
        **pool_kwargs: Any,
    ) -> Any:
        pool_kwargs["assert_fingerprint"] = self.fingerprint
        pool_kwargs["cert_reqs"] = "CERT_NONE"
        return super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def cert_verify(self, conn: Any, _url: str, _verify: Any, _cert: Any) -> None:
        conn.assert_fingerprint = self.fingerprint
        conn.cert_reqs = "CERT_NONE"


class ProxyClient:
    """Client for querying Proxy nodes with strict TLS certificate pinning."""

    def __init__(self, session: requests.Session | None = None) -> None:
        self._session = session or requests.Session()

    @staticmethod
    def probe_tls_cert_info(host: str, port: int, timeout: float = 5.0) -> tuple[str, Any]:
        """Connect via TLS handshake to extract the peer certificate, its fingerprint, and expiration date."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with (
                socket.create_connection((host, port), timeout=timeout) as sock,
                ctx.wrap_socket(sock, server_hostname=host) as sslobj,
            ):
                der_bytes = sslobj.getpeercert(binary_form=True)
                if not der_bytes:
                    raise TLSFingerprintError(
                        f"Remote proxy {host}:{port} presented no TLS certificate."
                    )
                fp = compute_cert_fingerprint(der_bytes)
                exp = extract_cert_expiration(der_bytes)
                return fp, exp
        except TimeoutError as exc:
            raise ProxyUnreachableError(f"Connection timeout probing {host}:{port}: {exc}") from exc
        except OSError as exc:
            raise ProxyUnreachableError(f"Failed to connect to proxy {host}:{port}: {exc}") from exc

    @staticmethod
    def probe_tls_certificate(host: str, port: int, timeout: float = 5.0) -> str:
        """Connect via TLS handshake to extract the peer certificate and calculate its fingerprint.

        Used during proxy registration and probe before pinning is confirmed.
        """
        fp, _ = ProxyClient.probe_tls_cert_info(host, port, timeout=timeout)
        return fp

    def get_health(
        self,
        host: str,
        port: int,
        token: str,
        expected_fingerprint: str,
        timeout: tuple[float, float] = (5.0, 10.0),
    ) -> tuple[ProxyHealthResponse, int]:
        """Poll GET /v1/health with TLS certificate pinning and Bearer authentication.

        Args:
            host: Proxy hostname or IP.
            port: Proxy port.
            token: Bearer token.
            expected_fingerprint: Pinned SHA-256 fingerprint.
            timeout: Tuple of (connect_timeout_s, read_timeout_s).

        Returns:
            Tuple of (ProxyHealthResponse, observed_latency_ms).

        Raises:
            TLSFingerprintMismatchError: If the certificate does not match the pinned fingerprint.
            ProxyUnauthorizedError: If HTTP 401 is received.
            ProxyUnreachableError: On timeout or connection failure.
        """
        url = f"https://{host}:{port}/v1/health"
        headers = {
            "Authorization": f"Bearer {token}",
            PROTOCOL_HEADER: str(EMBERVAULT_PROTOCOL_VERSION),
            REQUEST_ID_HEADER: str(uuid.uuid4()),
        }

        # Create session with pinned adapter
        req_session = requests.Session()
        clean_fp = normalize_fingerprint(expected_fingerprint)
        req_session.mount(f"https://{host}:{port}", FingerprintAdapter(clean_fp))

        start_time = time.monotonic()
        try:
            resp = req_session.get(url, headers=headers, timeout=timeout, verify=False)
            latency_ms = int((time.monotonic() - start_time) * 1000)

            if resp.status_code == 401:
                raise ProxyUnauthorizedError(
                    f"Proxy {host}:{port} rejected authentication token (HTTP 401)."
                )

            if resp.status_code != 200:
                raise ProxyUnreachableError(
                    f"Proxy {host}:{port} returned unexpected HTTP {resp.status_code} on health check."
                )

            data = resp.json()
            health_model = ProxyHealthResponse.model_validate(data)
            return health_model, latency_ms

        except (urllib3.exceptions.SSLError, requests.exceptions.SSLError) as exc:
            exc_str = str(exc).lower()
            if "fingerprints did not match" in exc_str or "fingerprint" in exc_str:
                logger.error(
                    "proxy_cert_fingerprint_mismatch",
                    host=host,
                    port=port,
                    expected=clean_fp,
                    error=str(exc),
                )
                raise TLSFingerprintMismatchError(
                    f"Certificate fingerprint mismatch on proxy {host}:{port}."
                ) from exc
            raise ProxyUnreachableError(f"TLS error connecting to {host}:{port}: {exc}") from exc

        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as exc:
            raise ProxyUnreachableError(f"Timeout querying {host}:{port}: {exc}") from exc
        except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as exc:
            raise ProxyUnreachableError(f"Failed to connect to proxy {host}:{port}: {exc}") from exc

    def probe(
        self,
        host: str,
        port: int,
        token: str,
        timeout: tuple[float, float] = (5.0, 10.0),
    ) -> ProxyProbeResponse:
        """Perform full probe: read TLS certificate, verify authentication and query health."""
        fingerprint, cert_expires_at = self.probe_tls_cert_info(host, port, timeout=timeout[0])
        health, latency_ms = self.get_health(
            host=host,
            port=port,
            token=token,
            expected_fingerprint=fingerprint,
            timeout=timeout,
        )

        return ProxyProbeResponse(
            cert_fingerprint_sha256=fingerprint,
            status="ok",
            latency_ms=float(latency_ms),
            proxy_version=health.proxy_version,
            rclone_version=health.rclone_version,
            cert_expires_at=cert_expires_at,
        )

    def renew_certificate(
        self,
        host: str,
        port: int,
        token: str,
        expected_fingerprint: str,
        timeout: tuple[float, float] = (5.0, 15.0),
    ) -> dict[str, Any]:
        """Send certificate renewal command to proxy worker."""
        clean_fp = normalize_fingerprint(expected_fingerprint)
        base_url = f"https://{host}:{port}"
        url = f"{base_url}/v1/tls/renew"
        headers = {
            "Authorization": f"Bearer {token}",
            PROTOCOL_HEADER: str(EMBERVAULT_PROTOCOL_VERSION),
            REQUEST_ID_HEADER: str(uuid.uuid4()),
        }

        req_session = requests.Session()
        req_session.mount(base_url, FingerprintAdapter(clean_fp))
        try:
            resp = req_session.post(url, headers=headers, timeout=timeout, verify=False)
            if resp.status_code == 401:
                raise ProxyUnauthorizedError(f"Proxy rejected token renewing TLS cert: {resp.text}")
            if resp.status_code != 200:
                raise ProxyUnreachableError(
                    f"Proxy TLS renewal failed with status {resp.status_code}: {resp.text}"
                )
            return resp.json()
        except requests.exceptions.SSLError as exc:
            raise TLSFingerprintMismatchError(
                f"TLS fingerprint error during renewal: {exc}"
            ) from exc
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            raise ProxyUnreachableError(
                f"Failed to connect to proxy for TLS renewal: {exc}"
            ) from exc

    def test_remote(
        self,
        host: str,
        port: int,
        token: str,
        expected_fingerprint: str,
        backend_type: str,
        config: dict[str, Any],
        path: str = "",
        referenced_remotes: dict[str, dict[str, Any]] | list[dict[str, Any]] | None = None,
        timeout: tuple[float, float] = (5.0, 20.0),
    ) -> dict[str, Any]:
        """Send remote connectivity test request to proxy worker."""
        clean_fp = normalize_fingerprint(expected_fingerprint)
        base_url = f"https://{host}:{port}"
        url = f"{base_url}/v1/remotes/test"

        sess = requests.Session()
        sess.mount(f"https://{host}", FingerprintAdapter(fingerprint=clean_fp))

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            PROTOCOL_HEADER: str(EMBERVAULT_PROTOCOL_VERSION),
            REQUEST_ID_HEADER: str(uuid.uuid4()),
        }
        payload = {
            "backend_type": backend_type,
            "config": config,
            "path": path,
            "referenced_remotes": referenced_remotes,
        }

        try:
            resp = sess.post(url, json=payload, headers=headers, timeout=timeout)
            if resp.status_code == 401:
                raise ProxyUnauthorizedError(f"Proxy {host}:{port} rejected authentication token.")
            return cast(dict[str, Any], resp.json())
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as exc:
            raise ProxyUnreachableError(f"Timeout querying {host}:{port}: {exc}") from exc
        except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as exc:
            raise ProxyUnreachableError(f"Failed to connect to proxy {host}:{port}: {exc}") from exc

    def browse_remote(
        self,
        host: str,
        port: int,
        token: str,
        expected_fingerprint: str,
        backend_type: str,
        config: dict[str, Any],
        path: str = "",
        referenced_remotes: dict[str, dict[str, Any]] | list[dict[str, Any]] | None = None,
        timeout: tuple[float, float] = (5.0, 20.0),
    ) -> dict[str, Any]:
        """Send remote browsing request to proxy worker."""
        clean_fp = normalize_fingerprint(expected_fingerprint)
        base_url = f"https://{host}:{port}"
        url = f"{base_url}/v1/remotes/browse"

        sess = requests.Session()
        sess.mount(f"https://{host}", FingerprintAdapter(fingerprint=clean_fp))

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            PROTOCOL_HEADER: str(EMBERVAULT_PROTOCOL_VERSION),
            REQUEST_ID_HEADER: str(uuid.uuid4()),
        }
        payload = {
            "backend_type": backend_type,
            "config": config,
            "path": path,
            "referenced_remotes": referenced_remotes,
        }

        try:
            resp = sess.post(url, json=payload, headers=headers, timeout=timeout)
            if resp.status_code == 401:
                raise ProxyUnauthorizedError(f"Proxy {host}:{port} rejected authentication token.")
            return cast(dict[str, Any], resp.json())
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as exc:
            raise ProxyUnreachableError(f"Timeout querying {host}:{port}: {exc}") from exc
        except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as exc:
            raise ProxyUnreachableError(f"Failed to connect to proxy {host}:{port}: {exc}") from exc

    def download_remote(
        self,
        host: str,
        port: int,
        token: str,
        expected_fingerprint: str,
        backend_type: str,
        config: dict[str, Any],
        base_path: str = "",
        items: list[dict[str, Any]] | None = None,
        referenced_remotes: dict[str, dict[str, Any]] | list[dict[str, Any]] | None = None,
        timeout: tuple[float, float | None] = (5.0, None),
    ) -> requests.Response:
        """Stream remote files or archive from proxy worker."""
        clean_fp = normalize_fingerprint(expected_fingerprint)
        base_url = f"https://{host}:{port}"
        url = f"{base_url}/v1/remotes/download"

        sess = requests.Session()
        sess.mount(f"https://{host}", FingerprintAdapter(fingerprint=clean_fp))

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            PROTOCOL_HEADER: str(EMBERVAULT_PROTOCOL_VERSION),
            REQUEST_ID_HEADER: str(uuid.uuid4()),
        }
        payload = {
            "backend_type": backend_type,
            "config": config,
            "base_path": base_path,
            "items": items or [],
            "referenced_remotes": referenced_remotes,
        }

        try:
            resp = sess.post(url, json=payload, headers=headers, stream=True, timeout=timeout)
            if resp.status_code == 401:
                raise ProxyUnauthorizedError(f"Proxy {host}:{port} rejected authentication token.")
            return resp
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as exc:
            raise ProxyUnreachableError(f"Timeout querying {host}:{port}: {exc}") from exc
        except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as exc:
            raise ProxyUnreachableError(f"Failed to connect to proxy {host}:{port}: {exc}") from exc

    def discover(
        self,
        host: str,
        port: int,
        token: str,
        expected_fingerprint: str,
        backend_type: str,
        config: dict[str, Any],
        path: str = "",
        referenced_remotes: dict[str, dict[str, Any]] | list[dict[str, Any]] | None = None,
        timeout: tuple[float, float] | None = None,
        include_subfolder_files: bool = False,
        timeout_s: int = 30,
    ) -> dict[str, Any]:
        """Send directory discovery request to proxy worker."""
        if timeout is None:
            timeout = (5.0, float(timeout_s + 15.0))
        clean_fp = normalize_fingerprint(expected_fingerprint)
        base_url = f"https://{host}:{port}"
        url = f"{base_url}/v1/discover"

        sess = requests.Session()
        sess.mount(f"https://{host}", FingerprintAdapter(fingerprint=clean_fp))

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            PROTOCOL_HEADER: str(EMBERVAULT_PROTOCOL_VERSION),
            REQUEST_ID_HEADER: str(uuid.uuid4()),
        }
        payload = {
            "backend_type": backend_type,
            "config": config,
            "path": path,
            "referenced_remotes": referenced_remotes,
            "include_subfolder_files": include_subfolder_files,
            "timeout_s": timeout_s,
        }

        try:
            resp = sess.post(url, json=payload, headers=headers, timeout=timeout)
            if resp.status_code == 401:
                raise ProxyUnauthorizedError(f"Proxy {host}:{port} rejected authentication token.")
            return cast(dict[str, Any], resp.json())
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as exc:
            raise ProxyUnreachableError(f"Timeout querying {host}:{port}: {exc}") from exc
        except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as exc:
            raise ProxyUnreachableError(f"Failed to connect to proxy {host}:{port}: {exc}") from exc

    def dispatch_task(
        self,
        host: str,
        port: int,
        token: str,
        expected_fingerprint: str,
        payload: dict[str, Any],
        timeout: tuple[float, float] = (5.0, 15.0),
    ) -> dict[str, Any]:
        """Dispatch task attempt to proxy node."""
        clean_fp = normalize_fingerprint(expected_fingerprint)
        base_url = f"https://{host}:{port}"
        url = f"{base_url}/v1/tasks"

        sess = requests.Session()
        sess.mount(f"https://{host}", FingerprintAdapter(fingerprint=clean_fp))

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            PROTOCOL_HEADER: str(EMBERVAULT_PROTOCOL_VERSION),
            REQUEST_ID_HEADER: str(uuid.uuid4()),
        }

        try:
            resp = sess.post(url, json=payload, headers=headers, timeout=timeout)
            if resp.status_code == 401:
                raise ProxyUnauthorizedError(f"Proxy {host}:{port} rejected authentication token.")
            return cast(dict[str, Any], resp.json())
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as exc:
            raise ProxyUnreachableError(
                f"Timeout dispatching task to {host}:{port}: {exc}"
            ) from exc
        except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as exc:
            raise ProxyUnreachableError(f"Failed to dispatch task to {host}:{port}: {exc}") from exc

    def get_task_status(
        self,
        host: str,
        port: int,
        token: str,
        expected_fingerprint: str,
        attempt_id: uuid.UUID,
        timeout: tuple[float, float] = (5.0, 10.0),
    ) -> dict[str, Any]:
        """Fetch task status and metrics from proxy node."""
        clean_fp = normalize_fingerprint(expected_fingerprint)
        base_url = f"https://{host}:{port}"
        url = f"{base_url}/v1/tasks/{attempt_id}"

        sess = requests.Session()
        sess.mount(f"https://{host}", FingerprintAdapter(fingerprint=clean_fp))

        headers = {
            "Authorization": f"Bearer {token}",
            PROTOCOL_HEADER: str(EMBERVAULT_PROTOCOL_VERSION),
            REQUEST_ID_HEADER: str(uuid.uuid4()),
        }

        try:
            resp = sess.get(url, headers=headers, timeout=timeout)
            if resp.status_code == 401:
                raise ProxyUnauthorizedError(f"Proxy {host}:{port} rejected authentication token.")
            return cast(dict[str, Any], resp.json())
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as exc:
            raise ProxyUnreachableError(
                f"Timeout querying task status on {host}:{port}: {exc}"
            ) from exc
        except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as exc:
            raise ProxyUnreachableError(
                f"Failed to query task status on {host}:{port}: {exc}"
            ) from exc

    def get_task_logs(
        self,
        host: str,
        port: int,
        token: str,
        expected_fingerprint: str,
        attempt_id: uuid.UUID,
        from_seq: int = 0,
        timeout: tuple[float, float] = (5.0, 10.0),
    ) -> dict[str, Any]:
        """Fetch log lines from proxy node."""
        clean_fp = normalize_fingerprint(expected_fingerprint)
        base_url = f"https://{host}:{port}"
        url = f"{base_url}/v1/tasks/{attempt_id}/logs?from_seq={from_seq}"

        sess = requests.Session()
        sess.mount(f"https://{host}", FingerprintAdapter(fingerprint=clean_fp))

        headers = {
            "Authorization": f"Bearer {token}",
            PROTOCOL_HEADER: str(EMBERVAULT_PROTOCOL_VERSION),
            REQUEST_ID_HEADER: str(uuid.uuid4()),
        }

        try:
            resp = sess.get(url, headers=headers, timeout=timeout)
            if resp.status_code == 401:
                raise ProxyUnauthorizedError(f"Proxy {host}:{port} rejected authentication token.")
            return cast(dict[str, Any], resp.json())
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as exc:
            raise ProxyUnreachableError(f"Timeout reading logs from {host}:{port}: {exc}") from exc
        except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as exc:
            raise ProxyUnreachableError(f"Failed to read logs from {host}:{port}: {exc}") from exc

    def cancel_task(
        self,
        host: str,
        port: int,
        token: str,
        expected_fingerprint: str,
        attempt_id: uuid.UUID,
        timeout: tuple[float, float] = (5.0, 10.0),
    ) -> dict[str, Any]:
        """Cancel a running task attempt on proxy node."""
        clean_fp = normalize_fingerprint(expected_fingerprint)
        base_url = f"https://{host}:{port}"
        url = f"{base_url}/v1/tasks/{attempt_id}/cancel"

        sess = requests.Session()
        sess.mount(f"https://{host}", FingerprintAdapter(fingerprint=clean_fp))

        headers = {
            "Authorization": f"Bearer {token}",
            PROTOCOL_HEADER: str(EMBERVAULT_PROTOCOL_VERSION),
            REQUEST_ID_HEADER: str(uuid.uuid4()),
        }

        try:
            resp = sess.post(url, headers=headers, timeout=timeout)
            if resp.status_code == 401:
                raise ProxyUnauthorizedError(f"Proxy {host}:{port} rejected authentication token.")
            return cast(dict[str, Any], resp.json())
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as exc:
            raise ProxyUnreachableError(f"Timeout cancelling task on {host}:{port}: {exc}") from exc
        except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as exc:
            raise ProxyUnreachableError(f"Failed to cancel task on {host}:{port}: {exc}") from exc

    def upgrade_rclone(
        self,
        host: str,
        port: int,
        token: str,
        expected_fingerprint: str,
        version: str,
        timeout: tuple[float, float] = (10.0, 90.0),
    ) -> dict[str, Any]:
        """Trigger RClone binary download and upgrade on remote proxy node."""
        clean_fp = normalize_fingerprint(expected_fingerprint)
        base_url = f"https://{host}:{port}"
        url = f"{base_url}/v1/system/rclone/upgrade"

        sess = requests.Session()
        sess.mount(f"https://{host}", FingerprintAdapter(fingerprint=clean_fp))

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            PROTOCOL_HEADER: str(EMBERVAULT_PROTOCOL_VERSION),
            REQUEST_ID_HEADER: str(uuid.uuid4()),
        }

        try:
            resp = sess.post(url, headers=headers, json={"version": version}, timeout=timeout)
            if resp.status_code == 401:
                raise ProxyUnauthorizedError(f"Proxy {host}:{port} rejected authentication token.")
            if resp.status_code >= 400:
                err_data = (
                    resp.json()
                    if "application/json" in resp.headers.get("content-type", "")
                    else {}
                )
                err_msg = err_data.get("message") or f"HTTP {resp.status_code}: {resp.text}"
                raise ProxyClientError(f"Proxy upgrade failed: {err_msg}")
            return cast(dict[str, Any], resp.json())
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout) as exc:
            raise ProxyUnreachableError(
                f"Timeout upgrading RClone on {host}:{port}: {exc}"
            ) from exc
        except (requests.exceptions.ConnectionError, requests.exceptions.RequestException) as exc:
            raise ProxyUnreachableError(
                f"Failed to communicate with proxy {host}:{port}: {exc}"
            ) from exc
