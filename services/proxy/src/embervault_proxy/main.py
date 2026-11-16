"""Supervisor and CLI entrypoint for EmberVault Proxy service.

Generates or loads the persistent self-signed TLS certificate and private key,
then starts Gunicorn with native HTTPS configuration.
"""

from __future__ import annotations

import subprocess
import sys

from embervault_common.config import ProxySettings
from embervault_common.observability import configure_logging, get_logger
from embervault_proxy.tls import ensure_tls_credentials

logger = get_logger("embervault_proxy.main")


def main() -> None:
    """Initialize TLS credentials and launch Gunicorn with HTTPS."""
    settings = ProxySettings.load()

    configure_logging(
        service="proxy",
        log_level=settings.log_level,
        log_format=settings.log_format,
    )

    cert_path, key_path, fingerprint = ensure_tls_credentials(settings)
    logger.info(
        "proxy_tls_ready",
        cert_path=str(cert_path),
        fingerprint=fingerprint,
        port=settings.proxy_port,
    )

    cmd = [
        "gunicorn",
        "--bind",
        f"0.0.0.0:{settings.proxy_port}",
        "--workers",
        "1",
        "--threads",
        "4",
        "--certfile",
        str(cert_path),
        "--keyfile",
        str(key_path),
        "embervault_proxy.factory:create_proxy_app()",
    ]

    logger.info("proxy_starting_gunicorn", bind=f"0.0.0.0:{settings.proxy_port}")
    sys.exit(subprocess.call(cmd))


if __name__ == "__main__":
    main()
