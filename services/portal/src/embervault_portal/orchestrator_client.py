"""Client for communicating with Orchestrator Internal API."""

from __future__ import annotations

import logging
from typing import Any
import requests

logger = logging.getLogger(__name__)


class OrchestratorPortalClient:
    """HTTP client for Orchestrator internal public shares API."""

    def __init__(
        self,
        base_url: str,
        timeout_seconds: int = 15,
        connect_timeout: float = 4.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.connect_timeout = connect_timeout

    def _timeout(self, read_timeout: float | None = None) -> tuple[float, float]:
        """Return (connect_timeout, read_timeout) tuple for fast socket-level failure."""
        return (
            self.connect_timeout,
            read_timeout if read_timeout is not None else float(self.timeout_seconds),
        )

    def validate_share(self, token: str, username: str, password: str) -> dict[str, Any]:
        """Validate token and credentials with orchestrator."""
        url = f"{self.base_url}/internal/v1/public-shares/validate"
        try:
            resp = requests.post(
                url,
                json={"token": token, "username": username, "password": password},
                timeout=self._timeout(),
            )
            try:
                data = resp.json()
            except Exception:
                data = {"status": "error", "message": resp.text}
            return {"status_code": resp.status_code, "data": data}
        except requests.RequestException as exc:
            logger.warning("Failed to connect to backend internal API during validate: %s", exc)
            return {
                "status_code": 503,
                "data": {
                    "status": "error",
                    "message": "Servizio momentaneamente non disponibile. Riprova più tardi.",
                },
            }

    def browse_share(self, token: str, subpath: str = "") -> dict[str, Any]:
        """Browse files and folders inside the share base path."""
        url = f"{self.base_url}/internal/v1/public-shares/browse"
        try:
            resp = requests.post(
                url,
                json={"token": token, "subpath": subpath},
                timeout=self._timeout(),
            )
            try:
                data = resp.json()
            except Exception:
                data = {"status": "error", "message": resp.text}
            return {"status_code": resp.status_code, "data": data}
        except requests.RequestException as exc:
            logger.warning("Failed to connect to backend internal API during browse: %s", exc)
            return {
                "status_code": 503,
                "data": {
                    "status": "error",
                    "message": "Servizio momentaneamente non disponibile. Riprova più tardi.",
                },
            }

    def download_share(
        self,
        token: str,
        subpath: str = "",
        items: list[dict[str, Any]] | None = None,
    ) -> requests.Response:
        """Download selected items from the share as a streaming response."""
        url = f"{self.base_url}/internal/v1/public-shares/download"
        return requests.post(
            url,
            json={"token": token, "subpath": subpath, "items": items or []},
            stream=True,
            timeout=self._timeout(read_timeout=float(self.timeout_seconds * 4)),
        )

    def get_portal_branding(self) -> dict[str, Any]:
        """Retrieve public portal branding from orchestrator."""
        url = f"{self.base_url}/internal/v1/public-shares/branding"
        try:
            resp = requests.get(url, timeout=self._timeout(read_timeout=3.0))
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict):
                    return data
        except Exception as exc:
            logger.debug("Could not retrieve portal branding: %s", exc)
        return {
            "status": "ok",
            "app_name": "EmberVault public portal",
            "custom_app_name": "",
            "has_custom_logo": False,
            "logo_data": None,
        }
