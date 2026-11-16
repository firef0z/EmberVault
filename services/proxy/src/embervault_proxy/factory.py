"""Application factory for EmberVault Proxy worker service."""

from __future__ import annotations

from flask import Flask, Response, jsonify

from embervault_common.config import ProxySettings
from embervault_common.observability import (
    configure_logging,
    create_metrics_middleware,
    generate_metrics_response,
    get_logger,
    init_service_metrics,
)
from embervault_proxy.api import proxy_api
from embervault_proxy.auth import inject_protocol_headers, require_proxy_auth
from embervault_proxy.tls import ensure_tls_credentials


def create_proxy_app(settings: ProxySettings | None = None) -> Flask:
    """Create and configure an instance of the Proxy worker Flask application."""
    if settings is None:
        settings = ProxySettings.load()

    # Enforce minimum token requirement (already validated in ProxySettings, but enforce at factory)
    token_str = settings.token.get_secret_value().strip()
    if len(token_str) < 32:
        raise ValueError("Proxy TOKEN must be at least 32 characters long.")

    configure_logging(
        service="proxy",
        log_level=settings.log_level,
        log_format=settings.log_format,
    )
    logger = get_logger("embervault_proxy")

    # Ensure TLS certificate is ready and obtain fingerprint
    cert_path, key_path, fingerprint = ensure_tls_credentials(settings)

    logger.info(
        "initializing_proxy",
        env=settings.env,
        port=settings.proxy_port,
        tls_cert=str(cert_path),
        cert_fingerprint=fingerprint,
    )

    from embervault_proxy import __version__

    init_service_metrics("proxy", version=__version__, milestone="M9")

    from embervault_common.security import extract_cert_expiration
    from embervault_proxy.tls import renew_self_signed_cert

    expires_at = None
    if cert_path.exists():
        try:
            expires_at = extract_cert_expiration(cert_path.read_bytes())
        except Exception as exc:
            logger.warning("failed_extracting_cert_expiration_at_startup", error=str(exc))

    app = Flask(__name__)
    app.config["SETTINGS"] = settings
    app.config["TLS_CERT_PATH"] = cert_path
    app.config["TLS_KEY_PATH"] = key_path
    app.config["TLS_FINGERPRINT"] = fingerprint
    app.config["TLS_EXPIRES_AT"] = expires_at

    # Background monitor for automatic 90-day certificate expiration renewal
    def _cert_auto_renew_monitor():
        import os
        import signal
        import time
        import datetime

        while True:
            time.sleep(3600)  # Check hourly
            try:
                if cert_path.exists():
                    current_exp = extract_cert_expiration(cert_path.read_bytes())
                    now = datetime.datetime.now(datetime.UTC)
                    if now >= current_exp:
                        logger.warning(
                            "cert_expired_in_background_renewing_and_exiting",
                            cert_path=str(cert_path),
                            expires_at=current_exp.isoformat(),
                        )
                        renew_self_signed_cert(cert_path, key_path, valid_days=90)
                        try:
                            os.kill(os.getpid(), signal.SIGTERM)
                        except Exception:
                            os._exit(0)
                        break
            except Exception as e:
                logger.error("cert_auto_renew_monitor_error", error=str(e))

    import threading

    threading.Thread(
        target=_cert_auto_renew_monitor, daemon=True, name="cert-auto-renew-monitor"
    ).start()

    create_metrics_middleware(app, "proxy")

    # Register protocol header injection on all responses
    app.after_request(inject_protocol_headers)

    # Register authenticated /v1 API routes
    app.register_blueprint(proxy_api)

    # Public liveness and readiness endpoints for Docker/container probes
    @app.route("/healthz", methods=["GET"])
    def healthz() -> Response:
        """Unauthenticated liveness health check endpoint."""
        return jsonify({"status": "ok", "service": "proxy"})

    @app.route("/readyz", methods=["GET"])
    def readyz() -> Response:
        """Unauthenticated readiness health check endpoint."""
        return jsonify({"status": "ready", "service": "proxy"})

    # Authenticated metrics endpoint (spec §5.2: GET /metrics requires Bearer)
    @app.route("/metrics", methods=["GET"])
    @require_proxy_auth
    def metrics() -> Response:
        """Authenticated Prometheus metrics scrape endpoint."""
        data, content_type = generate_metrics_response()
        return Response(data, mimetype=content_type)

    return app
