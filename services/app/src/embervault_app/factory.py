"""Application factory for EmberVault Web UI service."""

from __future__ import annotations

import os
from typing import Any

from flask import Flask, Response, jsonify, render_template, session
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.auth import init_auth
from embervault_app.blueprints.api import api_bp
from embervault_app.blueprints.auth import auth_bp
from embervault_app.blueprints.ui import ui_bp
from embervault_app.i18n import init_i18n, translate as _
from embervault_app.orchestrator_client import OrchestratorClient
from embervault_app.security import init_security
from embervault_app.timezones import init_timezones
from embervault_app.whitelabel import init_whitelabel
from embervault_common.config import AppSettings, DatabaseSettings, SecuritySettings
from embervault_common.observability import (
    configure_logging,
    create_metrics_middleware,
    generate_metrics_response,
    get_logger,
    init_service_metrics,
)
from embervault_db.models.base import Base
from embervault_db.session import create_session_factory
from embervault_db.settings_store import SettingsStore


def create_app(
    settings: AppSettings | None = None,
    session_factory: sessionmaker[Session] | None = None,
    orchestrator_client: OrchestratorClient | None = None,
    settings_store: SettingsStore | None = None,
) -> Flask:
    """Create and configure an instance of the Flask application."""
    if settings is None:
        settings = AppSettings.load()

    configure_logging(
        service="app",
        log_level=settings.log_level,
        log_format=settings.log_format,
    )
    logger = get_logger("embervault_app")
    logger.info("initializing_app", env=settings.env, port=settings.app_port)

    from embervault_app import __version__

    init_service_metrics("app", version=__version__, milestone="M9")

    # Base directory paths
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    templates_dir = os.path.join(pkg_dir, "templates")
    static_dir = os.path.join(pkg_dir, "static")

    app = Flask(
        __name__,
        template_folder=templates_dir,
        static_folder=static_dir,
        static_url_path="/static",
    )

    # Security & session secret key
    sec_settings = SecuritySettings.load()
    secret_key = (
        sec_settings.secret_key.get_secret_value()
        if sec_settings.secret_key and sec_settings.secret_key.get_secret_value()
        else "dev-secret-key-32-chars-long-minimum-random"
    )
    app.config["SECRET_KEY"] = secret_key
    app.config["SETTINGS"] = settings

    # Initialize Database session factory
    if session_factory is None:
        if os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_HOST") == "postgres":
            db_settings = DatabaseSettings.load()
            engine = create_engine(
                db_settings.resolved_database_url,
                pool_pre_ping=True,
                pool_size=10,
                max_overflow=20,
            )
            session_factory = create_session_factory(engine)
        else:
            engine = create_engine("sqlite:///:memory:")
            Base.metadata.create_all(engine)
            session_factory = create_session_factory(engine)
    app.config["SESSION_FACTORY"] = session_factory

    # Idempotently sync system roles and permissions on startup
    try:
        from embervault_common.config import is_demo_mode
        from embervault_db.seed import seed_demo_data, seed_initial_data

        with session_factory() as seed_session:
            seed_initial_data(seed_session)
            if is_demo_mode(settings):
                seed_demo_data(seed_session)
    except Exception as exc:
        logger.debug("seed_initial_data_skipped_on_startup", error=str(exc))

    # Mark stale runs left over from prior execution/crash as failed on startup
    try:
        from embervault_db.repositories.execution_repository import ExecutionRepository

        with session_factory() as startup_session:
            aborted = ExecutionRepository.abort_stale_running_runs_on_startup(startup_session)
            if aborted:
                startup_session.commit()
                logger.warning("stale_running_runs_aborted_on_startup", count=aborted)
    except Exception as exc:
        logger.debug("stale_runs_cleanup_skipped_on_startup", error=str(exc))

    # Initialize Dynamic Settings Store
    if settings_store is None:
        settings_store = SettingsStore(session_factory)
    app.config["SETTINGS_STORE"] = settings_store

    # Initialize Orchestrator client
    if orchestrator_client is None:
        token = (
            sec_settings.internal_api_token.get_secret_value()
            if sec_settings.internal_api_token
            else None
        )
        orch_url = os.environ.get("EMBERVAULT_ORCH_URL", "http://orchestrator:8081")
        orchestrator_client = OrchestratorClient(base_url=orch_url, internal_api_token=token)
    app.config["ORCHESTRATOR_CLIENT"] = orchestrator_client

    # Metrics middleware
    create_metrics_middleware(app, "app")

    # Security middleware (CSP nonce, security headers, CSRF)
    init_security(app)

    # Session cookie hardening
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    if getattr(settings, "session_cookie_secure", False):
        app.config["SESSION_COOKIE_SECURE"] = True

    # Authentication & RBAC context
    init_auth(app)

    # Internationalization (i18n) & Timezones
    init_i18n(app)
    init_timezones(app)
    init_whitelabel(app)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(ui_bp)
    app.register_blueprint(api_bp)

    # Detailed Request/Response Logging for Diagnostics
    @app.before_request
    def log_incoming_request() -> None:
        import time

        from flask import g, request

        if request.path in ("/healthz", "/readyz", "/metrics"):
            return
        g._diag_start = time.monotonic()
        user_id = session.get("user_id", "anon")
        logger.debug(
            "http_request_start",
            method=request.method,
            path=request.path,
            ip=request.remote_addr,
            user_id=user_id,
        )

    @app.after_request
    def log_outgoing_response(response: Response) -> Response:
        import time

        from flask import g, request

        if request.path in ("/healthz", "/readyz", "/metrics"):
            return response
        start = getattr(g, "_diag_start", None)
        duration_ms = round((time.monotonic() - start) * 1000, 2) if start else None
        current_u = getattr(g, "current_user", None)
        try:
            username = getattr(current_u, "username", "anon") if current_u else "anon"
            role = (
                getattr(getattr(current_u, "role", None), "name", "none") if current_u else "none"
            )
        except Exception:
            username = "anon"
            role = "none"
        logger.info(
            "http_request_end",
            method=request.method,
            path=request.path,
            status=response.status_code,
            duration_ms=duration_ms,
            user=username,
            role=role,
        )
        return response

    @app.errorhandler(Exception)
    def handle_unhandled_exception(exc: Exception) -> Any:
        from flask import request
        from werkzeug.exceptions import HTTPException

        if isinstance(exc, HTTPException):
            code = exc.code or 500
            if code >= 500:
                logger.error(
                    "server_http_exception",
                    path=request.path,
                    method=request.method,
                    status=code,
                    error=str(exc),
                    exc_info=True,
                )
            else:
                logger.warning(
                    "client_http_exception",
                    path=request.path,
                    method=request.method,
                    status=code,
                    error=str(exc),
                )
            if request.path.startswith("/api/") or request.is_json:
                return jsonify(
                    {
                        "status": "error",
                        "error": exc.name.lower().replace(" ", "_"),
                        "message": exc.description,
                    }
                ), code
            return render_template(
                "error.html", error_code=code, error_title=exc.name, error_message=exc.description
            ), code

        logger.error(
            "unhandled_server_exception",
            path=request.path,
            method=request.method,
            error=str(exc),
            error_type=exc.__class__.__name__,
            exc_info=True,
        )
        if request.path.startswith("/api/") or request.is_json:
            return jsonify({"status": "error", "error": "internal_error", "message": str(exc)}), 500
        return render_template(
            "error.html",
            error_code=500,
            error_title=_("error_internal_title"),
            error_message=str(exc),
        ), 500

    # System Health & Metrics Endpoints
    @app.route("/healthz", methods=["GET"])
    def healthz() -> Response:
        """Liveness health check endpoint."""
        return jsonify({"status": "ok", "service": "app"})

    @app.route("/readyz", methods=["GET"])
    def readyz() -> Response:
        """Readiness health check endpoint verifying DB connectivity."""
        try:
            with session_factory() as session:
                session.execute(
                    text("SELECT 1")
                    if "text" in globals()
                    else __import__("sqlalchemy").text("SELECT 1")
                )
            return jsonify({"status": "ready", "service": "app"})
        except Exception as exc:
            logger.warning("readyz_check_failed", error=str(exc))
            return Response(
                response=jsonify({"status": "not_ready", "error": str(exc)}).data,
                status=503,
                mimetype="application/json",
            )

    @app.route("/metrics", methods=["GET"])
    def metrics() -> Response:
        """Prometheus metrics scrape endpoint."""
        data, content_type = generate_metrics_response(
            session_factory=app.config.get("SESSION_FACTORY")
        )
        return Response(data, mimetype=content_type)

    return app
